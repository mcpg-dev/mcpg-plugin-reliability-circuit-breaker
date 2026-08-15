# Circuit Breaker — `dev.mcpg.circuit-breaker`

> class `tool_gate` · `native` · package `mcpg-plugin-reliability-circuit-breaker` · artifact `libmcpg_plugin_reliability_circuit_breaker.so` · Apache-2.0

Per-tool circuit breaker for the MCPG gateway. It counts consecutive failed tool
results and, once a tool crosses its failure threshold, stops dispatching to that
tool entirely — answering with a fast HTTP 503 instead of another doomed backend
round-trip — until a cooldown elapses and a single probe proves the backend
healthy again. Reach for it when a flaky or downed backend would otherwise burn
request budget, connection-pool slots, and client latency on calls that are
already destined to fail.

## What it does
- Tracks consecutive failures per tool name. A result counts as a failure when
  it carries `isError: true` or any `content[]` item of `type: "error"`.
- Runs the classic three-state machine: `Closed` → `Open` (after
  `failure_threshold` consecutive failures) → `HalfOpen` (once `cooldown_ms`
  has passed) → `Closed` (probe succeeds) or back to `Open` (probe fails).
- Denies while `Open` with HTTP 503, JSON-RPC code `-32000`, and `error_data`
  carrying `circuit_state: "open"` plus the tool name.
- Admits at most `half_open_max_inflight` concurrent probes while `HalfOpen`;
  everything else is denied without touching the backend.
- Resets the failure counter on any success while `Closed`, so isolated blips
  never accumulate into a trip.
- Accepts per-tool overrides of `failure_threshold` and `cooldown_ms` for tools
  that deserve a tighter or looser trip point than the rest.
- Declares no host capabilities and opens no sockets — all state is in-process.

## Configuration
Loaded from the flat top-level `plugins:` list. Every entry of class `tool_gate`
joins the gate chain that runs on each tool call; a `Deny` from an enforcing gate
ends the chain immediately.

```yaml
plugins:
  - id: dev.mcpg.circuit-breaker
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_reliability_circuit_breaker.so }
    # or, platform-agnostic — the gateway resolves the artifact for its own
    # os/arch/libc at boot:
    # source: { oci: ghcr.io/mcpg-dev/source-code/plugins/circuit-breaker:protocol-1 }
    config:
      failure_threshold: 5            # consecutive failures that trip the circuit
      cooldown_ms: 30000              # open → half-open delay
      half_open_max_inflight: 1       # concurrent probes while half-open
      per_tool:
        - tool: "billing.charge"      # exact tool name, not a glob
          failure_threshold: 2
          cooldown_ms: 60000
```

| Field | Type | Default | Description |
|---|---|---|---|
| `failure_threshold` | integer | `5` | Consecutive failed results before the circuit opens. |
| `cooldown_ms` | integer | `30000` | How long the circuit stays open before a half-open probe is admitted. |
| `half_open_max_inflight` | integer | `1` | Concurrent probe requests permitted while half-open. |
| `failure_status_codes` | integer[] | `500`–`599` | Accepted by the schema. Failure classification reads the tool result, so this list does not affect the decision. |
| `per_tool` | object[] | `[]` | Overrides keyed by `tool` (exact name, required) with optional `failure_threshold` and `cooldown_ms`. |

Unknown fields are rejected, at the top level and inside `per_tool` entries. An
absent or empty `config:` block yields the defaults above; a present-but-malformed
block refuses the plugin at boot rather than quietly degrading to defaults, so a
typo in a reliability knob surfaces as a boot error instead of a silent
behaviour change.

## Operations
Circuits live in the plugin instance, so they are per gateway process: a fleet of
N replicas trips N independent circuits, and a restart starts every tool
`Closed`. Size `failure_threshold` against the traffic one replica sees, not
against fleet-wide volume.

Tool names are keyed exactly — a `per_tool` entry for `billing.charge` does not
cover `billing.refund`. Tools with no override use the plugin-wide
`failure_threshold` and `cooldown_ms`.

The gate chain is also evaluated on prompt, resource, and completion requests,
where the keyed name is the prompt name, resource URI, or completion reference.
Failure accounting is driven by post-dispatch results, which the gateway reports
on the tool-call path, so circuits trip on tool traffic.

## Observability
- `mcpg_circuit_breaker_decisions_total{tool,outcome}` — one sample per
  pre-dispatch evaluation.
- `mcpg_circuit_breaker_transitions_total{from,to}` — state changes, labelled
  `closed` / `open` / `half_open`.
- `mcpg_circuit_breaker_rejections_total{tool}` — denials issued while the
  circuit is open and still inside its cooldown.
- `mcpg_circuit_breaker_evaluate_ms` — pre-dispatch evaluation latency.

Each evaluation also opens a `circuit_breaker_evaluate_pre` tracing span tagged
with the plugin id and tool name; transitions log at INFO and threshold trips at
WARN.

## Build
The `cdylib-export` feature gates the `mcpg_plugin_register` export. It is on by
default for a standalone build and switched off when the crate is linked as a
path dependency alongside other plugins, since several `mcpg_plugin_register`
symbols collide at link time:

```bash
cargo build -p mcpg-plugin-reliability-circuit-breaker --features cdylib-export --release   # → target/release/libmcpg_plugin_reliability_circuit_breaker.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, loading, and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Sibling reliability gates: `libs/plugins/reliability/rate-limit`,
  `libs/plugins/reliability/response-cache`
