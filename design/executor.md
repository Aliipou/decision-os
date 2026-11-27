# Design: executor (`dos-exec`, stdio MCP gateway proxy)

## Goal

Port `oracle/decision-os-min/decision_os_min/gateway/mcp_proxy.py` and the
govern/approval control flow of `engine.py` to a new crate `crates/dos-exec`.
The proxy launches the governed MCP server, relays newline-delimited JSON-RPC
in both directions, and gates every `tools/call` and `resources/read`:

    client --stdio--> dos-exec --stdio--> governed server
                         |
                  DecisionEngine (trait)  -> Allow / Ask / Deny
                  Approvals (trait)       -> human wait on Ask
                  AuditSink (trait)       -> one record per outcome, before the effect

Done means: every behavior in `tests/gateway/test_mcp_proxy.py` that belongs to
the proxy has a Rust test against a fake MCP server (a test-only binary in the
crate), and every error path refuses.

Out of scope: the policy, guardrails, kernel signing, spent store and file
approval store. They plug in through the three traits. The real decision engine
is built in parallel by another task.

## Approaches

**A. tokio.** What the plan says for `dos-mcp`. Not in the offline registry,
so it cannot be built here today.

**B. std threads.** Same shape as the oracle: a client reader, an upstream
reader, a fixed pool of call workers (default 8), mutex-guarded writers. No new
dependency besides `serde_json`.

**Choice: B.** It mirrors the oracle one to one, which makes parity review
easy. Moving to tokio later changes only `proxy.rs`.

## Control flow per gated call (matches the oracle)

1. Name missing or not a non-empty string: JSON-RPC error `-32602`.
2. `arguments` null becomes `{}`; any other non-object: refused.
3. `engine.decide(req, None)`: `Allow` runs, `Deny` refuses, `Ask` waits.
4. Ask: `approvals.wait(...)` returns Approved, Denied, Expired, Cancelled or
   Unavailable (non-interactive). Approved: `engine.decide(req, Some(id))`
   again, and only `Allow` runs. Anything else refuses.
5. Before the forward: `audit.record(executed=true)`. A failed record refuses.
   Every refusal is recorded too.
6. Refused tool call: `result.isError: true` with
   ``Decision OS blocked `server/tool`: <reason>. <hint>``. Refused
   `resources/read`: error `-32001`. Cancelled by the client: no reply.
   Upstream failure or engine error: error `-32603`.

## Failure modes (each must refuse)

| Case | Result |
|---|---|
| engine returns `Err` | `-32603`, never forwarded |
| audit write fails | refused, never forwarded |
| gated method without `id` (alone or in a batch) | dropped, stderr note |
| client line that is not valid strict JSON (incl. duplicate keys, NaN, lone surrogates) | dropped. **Deviation:** the oracle forwards unparseable lines raw; a lenient server parser could read a call we could not see. |
| upstream exits mid-call | `-32603` |
| upstream exits while a call waits for approval | wait aborted, refused |
| forward write to upstream fails | `-32603` |
| approval approved but second decision is not Allow | refused |
| client half-closes | waits aborted, in-flight replies still written |
| server cannot be started | exit code 127, `cannot start MCP server` on stderr |

## Test plan

`crates/dos-exec/tests/proxy.rs`, driving `Proxy` through in-process pipes and
the fake server `src/bin/dos-exec-fake-mcp.rs`, with a scripted engine:
notifications and tool hiding, allow forwards, deny never reaches the server,
annotation hints, ask approve/deny/expire/non-interactive, parallel calls while
one waits, server-initiated requests, cancellation, id-less calls and batches,
`resources/read`, half-close replies, bad command, engine error, audit failure,
upstream death mid-call, invalid JSON and duplicate keys dropped.
