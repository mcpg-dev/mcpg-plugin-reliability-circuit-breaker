//! Circuit Breaker ToolGate plugin for MCPG.
//!
//! Implements the circuit breaker pattern per tool: tracks failures
//! and short-circuits requests to unhealthy backends with fast 503
//! responses. State machine: Closed → Open (after failure_threshold)
//! → HalfOpen (after cooldown) → Closed (on probe success) or back
//! to Open (on failure).
//!
//! Distributed as a `native-cdylib-v1` plugin.

use dashmap::DashMap;
use mcpg_plugin_protocol::{GateDecision, PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::Deserialize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const PLUGIN_ID: &str = "dev.mcpg.circuit-breaker";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the circuit.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// How long the circuit stays open before transitioning to half-open (ms).
    #[serde(default = "default_cooldown_ms")]
    pub cooldown_ms: u64,
    /// Maximum concurrent probes allowed when half-open.
    #[serde(default = "default_half_open_max_inflight")]
    pub half_open_max_inflight: u32,
    /// HTTP status codes that count as failures (default: 500-599).
    #[serde(default = "default_failure_status_codes")]
    pub failure_status_codes: Vec<u16>,
    /// Per-tool overrides.
    #[serde(default)]
    pub per_tool: Vec<ToolOverride>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOverride {
    /// Tool name (exact match).
    pub tool: String,
    /// Override failure threshold for this tool.
    pub failure_threshold: Option<u32>,
    /// Override cooldown for this tool.
    pub cooldown_ms: Option<u64>,
}

fn default_failure_threshold() -> u32 {
    5
}
fn default_cooldown_ms() -> u64 {
    30_000
}
fn default_half_open_max_inflight() -> u32 {
    1
}
fn default_failure_status_codes() -> Vec<u16> {
    (500..=599).collect()
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            cooldown_ms: default_cooldown_ms(),
            half_open_max_inflight: default_half_open_max_inflight(),
            failure_status_codes: default_failure_status_codes(),
            per_tool: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// State Machine
// ---------------------------------------------------------------------------

/// State of a per-tool circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitStatus {
    Closed,
    Open,
    HalfOpen,
}

impl std::fmt::Display for CircuitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Open => write!(f, "open"),
            Self::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Mutable state for a single tool's circuit breaker.
pub struct CircuitState {
    status: std::sync::Mutex<CircuitStatus>,
    failure_count: AtomicU32,
    last_failure: std::sync::Mutex<Option<Instant>>,
    last_transition: std::sync::Mutex<Instant>,
    half_open_inflight: AtomicU32,
}

impl CircuitState {
    fn new() -> Self {
        Self {
            status: std::sync::Mutex::new(CircuitStatus::Closed),
            failure_count: AtomicU32::new(0),
            last_failure: std::sync::Mutex::new(None),
            last_transition: std::sync::Mutex::new(Instant::now()),
            half_open_inflight: AtomicU32::new(0),
        }
    }

    fn status(&self) -> CircuitStatus {
        *self.status.lock().unwrap()
    }

    fn transition_to(&self, new_status: CircuitStatus) {
        let old = {
            let mut s = self.status.lock().unwrap();
            let old = *s;
            *s = new_status;
            old
        };
        *self.last_transition.lock().unwrap() = Instant::now();
        if old != new_status {
            info!(from = %old, to = %new_status, "circuit breaker state transition");
            metrics::counter!("mcpg_circuit_breaker_transitions_total",
                "from" => old.to_string(),
                "to" => new_status.to_string(),
            )
            .increment(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/// Circuit breaker gate plugin — tracks failures per tool and short-circuits when tripped.
pub struct CircuitBreakerPlugin {
    manifest: PluginManifest,
    config: CircuitBreakerConfig,
    circuits: DashMap<String, CircuitState>,
}

impl CircuitBreakerPlugin {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "Circuit Breaker".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            config,
            circuits: DashMap::new(),
        }
    }

    pub fn from_config(config_value: &serde_json::Value) -> Result<Self, String> {
        let config: CircuitBreakerConfig = serde_json::from_value(config_value.clone())
            .map_err(|e| format!("invalid circuit breaker config: {e}"))?;
        Ok(Self::new(config))
    }

    /// SDK macro factory: parses operator config JSON, failing CLOSED on
    /// a present-but-malformed block (an empty/absent block still yields
    /// defaults). See `mcpg_plugin_sdk::config`.
    pub fn from_config_json(config_json: &str) -> Self {
        let config: CircuitBreakerConfig =
            mcpg_plugin_sdk::fail_closed_config!(config_json, CircuitBreakerConfig);
        Self::new(config)
    }

    fn get_or_create_circuit(
        &self,
        tool_name: &str,
    ) -> dashmap::mapref::one::Ref<'_, String, CircuitState> {
        if !self.circuits.contains_key(tool_name) {
            self.circuits
                .entry(tool_name.to_owned())
                .or_insert_with(CircuitState::new);
        }
        self.circuits.get(tool_name).unwrap()
    }

    fn failure_threshold_for(&self, tool_name: &str) -> u32 {
        self.config
            .per_tool
            .iter()
            .find(|o| o.tool == tool_name)
            .and_then(|o| o.failure_threshold)
            .unwrap_or(self.config.failure_threshold)
    }

    fn cooldown_for(&self, tool_name: &str) -> Duration {
        let ms = self
            .config
            .per_tool
            .iter()
            .find(|o| o.tool == tool_name)
            .and_then(|o| o.cooldown_ms)
            .unwrap_or(self.config.cooldown_ms);
        Duration::from_millis(ms)
    }

    fn is_failure_result(&self, result: &serde_json::Value) -> bool {
        // Check isError field
        if result.get("isError").and_then(|v| v.as_bool()) == Some(true) {
            return true;
        }
        // Check for error content
        if let Some(contents) = result.get("content").and_then(|v| v.as_array()) {
            for item in contents {
                if item.get("type").and_then(|v| v.as_str()) == Some("error") {
                    return true;
                }
            }
        }
        false
    }
}

impl SyncToolGate for CircuitBreakerPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> GateDecision {
        // Plugin-scoped span so traces from circuit-breaker
        // attribute back to dev.mcpg.circuit-breaker.
        let _span = tracing::info_span!(
            "circuit_breaker_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = std::time::Instant::now();
        let decision = self.evaluate_pre_inner(ctx);
        let outcome = match &decision {
            GateDecision::Allow { .. } => "allow",
            GateDecision::Deny { .. } => "deny",
            GateDecision::Challenge { .. } => "challenge",
            GateDecision::PendingApproval { .. } => "pending_approval",
        };
        metrics::counter!(
            "mcpg_circuit_breaker_decisions_total",
            "tool" => ctx.tool_name.clone(),
            "outcome" => outcome,
        )
        .increment(1);
        metrics::histogram!("mcpg_circuit_breaker_evaluate_ms")
            .record(started.elapsed().as_millis() as f64);
        decision
    }

    fn evaluate_post(
        &self,
        ctx: &PluginContext,
        _arguments: &serde_json::Value,
        result: &serde_json::Value,
        _execution_duration_ms: u64,
        _config: &serde_json::Value,
    ) -> GateDecision {
        let circuit = self.get_or_create_circuit(&ctx.tool_name);
        let status = circuit.status();
        let is_failure = self.is_failure_result(result);

        match status {
            CircuitStatus::Closed => {
                if is_failure {
                    let count = circuit.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
                    *circuit.last_failure.lock().unwrap() = Some(Instant::now());
                    let threshold = self.failure_threshold_for(&ctx.tool_name);
                    if count >= threshold {
                        warn!(
                            tool = %ctx.tool_name,
                            failures = count,
                            threshold = threshold,
                            "failure threshold reached — opening circuit"
                        );
                        circuit.transition_to(CircuitStatus::Open);
                        circuit.failure_count.store(0, Ordering::Release);
                        circuit.half_open_inflight.store(0, Ordering::Release);
                    }
                } else {
                    // Reset failure count on success
                    circuit.failure_count.store(0, Ordering::Release);
                }
            }
            CircuitStatus::HalfOpen => {
                circuit.half_open_inflight.fetch_sub(1, Ordering::AcqRel);
                if is_failure {
                    warn!(tool = %ctx.tool_name, "half-open probe failed — reopening circuit");
                    circuit.transition_to(CircuitStatus::Open);
                    circuit.half_open_inflight.store(0, Ordering::Release);
                } else {
                    info!(tool = %ctx.tool_name, "half-open probe succeeded — closing circuit");
                    circuit.transition_to(CircuitStatus::Closed);
                    circuit.failure_count.store(0, Ordering::Release);
                    circuit.half_open_inflight.store(0, Ordering::Release);
                }
            }
            CircuitStatus::Open => {
                // Shouldn't normally receive post_dispatch in Open state,
                // but handle gracefully (in-flight request from before transition).
            }
        }

        GateDecision::allow()
    }
}

impl CircuitBreakerPlugin {
    fn evaluate_pre_inner(&self, ctx: &PluginContext) -> GateDecision {
        let circuit = self.get_or_create_circuit(&ctx.tool_name);
        let status = circuit.status();

        match status {
            CircuitStatus::Closed => {
                debug!(tool = %ctx.tool_name, "circuit closed — allowing request");
                GateDecision::allow()
            }
            CircuitStatus::Open => {
                let cooldown = self.cooldown_for(&ctx.tool_name);
                let elapsed = circuit.last_transition.lock().unwrap().elapsed();
                if elapsed >= cooldown {
                    // Cooldown expired — try half-open
                    let inflight = circuit.half_open_inflight.load(Ordering::Acquire);
                    if inflight < self.config.half_open_max_inflight {
                        circuit.half_open_inflight.fetch_add(1, Ordering::AcqRel);
                        circuit.transition_to(CircuitStatus::HalfOpen);
                        debug!(tool = %ctx.tool_name, "circuit open→half_open — allowing probe");
                        GateDecision::allow()
                    } else {
                        debug!(tool = %ctx.tool_name, "circuit open, cooldown expired but half-open full — denying");
                        deny_circuit_open(&ctx.tool_name)
                    }
                } else {
                    debug!(tool = %ctx.tool_name, remaining_ms = (cooldown - elapsed).as_millis(), "circuit open — denying");
                    metrics::counter!("mcpg_circuit_breaker_rejections_total",
                        "tool" => ctx.tool_name.clone(),
                    )
                    .increment(1);
                    deny_circuit_open(&ctx.tool_name)
                }
            }
            CircuitStatus::HalfOpen => {
                let inflight = circuit.half_open_inflight.load(Ordering::Acquire);
                if inflight < self.config.half_open_max_inflight {
                    circuit.half_open_inflight.fetch_add(1, Ordering::AcqRel);
                    debug!(tool = %ctx.tool_name, inflight = inflight + 1, "circuit half-open — allowing probe");
                    GateDecision::allow()
                } else {
                    debug!(tool = %ctx.tool_name, "circuit half-open, max probes reached — denying");
                    deny_circuit_open(&ctx.tool_name)
                }
            }
        }
    }
}

fn deny_circuit_open(tool_name: &str) -> GateDecision {
    GateDecision::Deny {
        http_status: 503,
        code: -32000,
        message: format!("circuit breaker open for tool '{tool_name}' — backend unavailable"),
        error_data: Some(serde_json::json!({
            "circuit_state": "open",
            "tool": tool_name,
        })),
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: CircuitBreakerPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| CircuitBreakerPlugin::from_config_json(cfg),
        }
    ],
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginIdentity;

    fn test_ctx(tool: &str) -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-test".to_owned(),
            session_id: Some("sess-test".to_owned()),
            tool_name: tool.to_owned(),
            identity: PluginIdentity {
                kind: "anonymous".to_owned(),
                trust_level: "unauthenticated".to_owned(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: Default::default(),
            },
            transport: "http".to_owned(),
        }
    }

    fn success_result() -> serde_json::Value {
        serde_json::json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false
        })
    }

    fn failure_result() -> serde_json::Value {
        serde_json::json!({
            "content": [{"type": "text", "text": "error"}],
            "isError": true
        })
    }

    #[test]
    fn empty_config_yields_defaults() {
        // An empty/absent operator config block still uses Default (the
        // operator opted out — not a typo).
        let plugin = CircuitBreakerPlugin::from_config_json("{}");
        let defaults = CircuitBreakerConfig::default();
        assert_eq!(plugin.config.failure_threshold, defaults.failure_threshold);
        assert_eq!(plugin.config.cooldown_ms, defaults.cooldown_ms);
        assert_eq!(
            plugin.config.half_open_max_inflight,
            defaults.half_open_max_inflight
        );
        assert!(plugin.config.per_tool.is_empty());
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_config_fails_closed() {
        // A present-but-malformed config block refuses the plugin rather
        // than silently degrading to defaults.
        let _ = CircuitBreakerPlugin::from_config_json("not json");
    }

    #[test]
    fn unknown_config_key_is_rejected() {
        // A stray / renamed / typo'd key must be a parse error (fail-closed)
        // rather than silently ignored — guards the deny_unknown_fields
        // annotation on CircuitBreakerConfig.
        let bad = serde_json::json!({
            "failure_threshold": 5,
            "failure_treshold": 7, // typo
        });
        let err = CircuitBreakerPlugin::from_config(&bad);
        assert!(err.is_err(), "unknown config key should be rejected");
    }

    #[test]
    fn unknown_per_tool_key_is_rejected() {
        // The nested ToolOverride struct is also strict — a typo'd
        // per-tool key fails the whole config parse.
        let bad = serde_json::json!({
            "per_tool": [
                { "tool": "x", "failure_treshold": 1 } // typo
            ]
        });
        let err = CircuitBreakerPlugin::from_config(&bad);
        assert!(err.is_err(), "unknown per-tool key should be rejected");
    }

    #[test]
    fn closed_allows_requests() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig::default());
        let ctx = test_ctx("test_tool");
        let config = serde_json::json!({});
        let result = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        assert!(result.is_allow());
    }

    #[test]
    fn failures_trip_circuit() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig {
            failure_threshold: 3,
            cooldown_ms: 60_000,
            ..Default::default()
        });
        let ctx = test_ctx("test_tool");
        let config = serde_json::json!({});
        let fail = failure_result();

        // 3 failures should trip the circuit
        for _ in 0..3 {
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
            plugin.evaluate_post(&ctx, &serde_json::json!({}), &fail, 100, &config);
        }

        // Next request should be denied
        let result = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        assert!(!result.is_allow());
    }

    #[test]
    fn open_circuit_denies_fast() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown_ms: 60_000, // long cooldown
            ..Default::default()
        });
        let ctx = test_ctx("test_tool");
        let config = serde_json::json!({});

        // Trip the circuit
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(
            &ctx,
            &serde_json::json!({}),
            &failure_result(),
            100,
            &config,
        );

        // Should deny immediately
        let start = Instant::now();
        let result = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        let elapsed = start.elapsed();

        assert!(!result.is_allow());
        assert!(
            elapsed.as_millis() < 10,
            "denial should be fast, was {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn cooldown_transitions_to_half_open() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown_ms: 1, // 1ms cooldown for test
            half_open_max_inflight: 1,
            ..Default::default()
        });
        let ctx = test_ctx("test_tool");
        let config = serde_json::json!({});

        // Trip the circuit
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(
            &ctx,
            &serde_json::json!({}),
            &failure_result(),
            100,
            &config,
        );

        // Wait for cooldown
        std::thread::sleep(Duration::from_millis(10));

        // Should allow a probe (transitions to half-open)
        let result = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        assert!(result.is_allow());
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown_ms: 1,
            half_open_max_inflight: 1,
            ..Default::default()
        });
        let ctx = test_ctx("test_tool");
        let config = serde_json::json!({});

        // Trip the circuit
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(
            &ctx,
            &serde_json::json!({}),
            &failure_result(),
            100,
            &config,
        );

        std::thread::sleep(Duration::from_millis(10));

        // Probe succeeds
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(&ctx, &serde_json::json!({}), &success_result(), 50, &config);

        // Circuit should be closed — next request should be allowed
        let result = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        assert!(result.is_allow());
    }

    #[test]
    fn half_open_failure_reopens_circuit() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown_ms: 1,
            half_open_max_inflight: 1,
            ..Default::default()
        });
        let ctx = test_ctx("test_tool");
        let config = serde_json::json!({});

        // Trip and wait for cooldown
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(
            &ctx,
            &serde_json::json!({}),
            &failure_result(),
            100,
            &config,
        );
        std::thread::sleep(Duration::from_millis(10));

        // Probe fails
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(
            &ctx,
            &serde_json::json!({}),
            &failure_result(),
            100,
            &config,
        );

        // Circuit should be open again (deny without waiting for cooldown since we just transitioned)
        let circuit = plugin.get_or_create_circuit("test_tool");
        assert_eq!(circuit.status(), CircuitStatus::Open);
    }

    #[test]
    fn per_tool_override() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig {
            failure_threshold: 10, // high default
            per_tool: vec![ToolOverride {
                tool: "fragile_tool".to_owned(),
                failure_threshold: Some(1),
                cooldown_ms: None,
            }],
            ..Default::default()
        });
        let ctx = test_ctx("fragile_tool");
        let config = serde_json::json!({});

        // 1 failure should trip for the overridden tool
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(
            &ctx,
            &serde_json::json!({}),
            &failure_result(),
            100,
            &config,
        );

        let result = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        assert!(!result.is_allow());

        // Default-threshold tool should still be closed
        let ctx2 = test_ctx("normal_tool");
        let result2 = plugin.evaluate_pre(&ctx2, &serde_json::json!({}), None, &config);
        assert!(result2.is_allow());
    }

    #[test]
    fn success_resets_failure_count() {
        let plugin = CircuitBreakerPlugin::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });
        let ctx = test_ctx("test_tool");
        let config = serde_json::json!({});

        // 2 failures (below threshold)
        for _ in 0..2 {
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
            plugin.evaluate_post(
                &ctx,
                &serde_json::json!({}),
                &failure_result(),
                100,
                &config,
            );
        }

        // 1 success resets
        plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        plugin.evaluate_post(&ctx, &serde_json::json!({}), &success_result(), 50, &config);

        // 2 more failures shouldn't trip (count was reset)
        for _ in 0..2 {
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
            plugin.evaluate_post(
                &ctx,
                &serde_json::json!({}),
                &failure_result(),
                100,
                &config,
            );
        }

        let result = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        assert!(result.is_allow());
    }
}
