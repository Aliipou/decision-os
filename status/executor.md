# Status: executor

Branch `task/executor`. Design: `design/executor.md`.

## What changed

| File | Change |
|---|---|
| `crates/dos-exec/src/proxy.rs` | `Proxy`: launches the server, relays newline-delimited JSON-RPC, gates `tools/call` and `resources/read`, hides hard-denied tools, remembers annotation hints, approval wait, cancellation, half-close, shutdown |
| `crates/dos-exec/src/decision.rs` | traits `DecisionEngine`, `Approvals`, `AuditSink`; `Verdict` (Allow/Ask/Deny), `StaticVerdict`, `ApprovalOutcome`, `CancelToken`, `NoAudit` |
| `crates/dos-exec/src/approvals.rs` | `NonInteractive` (every Ask refused), `MemoryApprovals` (timeout, `pending`, `resolve`) |
| `crates/dos-exec/src/strict.rs` | strict client JSON parse: duplicate keys, NaN, lone surrogates and the like are refused |
| `crates/dos-exec/src/launch.rs` | oracle `slug`, `resolve_argv` (single-string command split, PATH + PATHEXT lookup so `.cmd` servers resolve) |
| `crates/dos-exec/src/bin/dos-exec-fake-mcp.rs` | test fixture, Rust twin of the oracle's `fake_mcp_server.py`, plus `die` and `slow` tools |
| `crates/dos-exec/tests/proxy.rs` | 22 end-to-end tests |
| `Cargo.lock` | `dos-exec` entry only (serde 1.0.229, serde_json 1.0.154 were already locked) |

Wiring contract: `engine.decide(req, None)`. On `Ask`, `approvals.wait(...)`. On
`Approved`, `engine.decide(req, Some(approval_id))` and only `Allow` runs.
`audit.record(executed=true)` happens before the forward; if it fails the call is
refused. Every refusal is recorded as `DENY`, `executed=false`.

## Evidence

Build recipe from the brief (gnu toolchain, `-j 2`, `--offline`).

```
cargo test --workspace --offline -j 2 --no-fail-fast
dos-exec unittests:   test result: ok. 4 passed; 0 failed
dos-exec tests/proxy: test result: ok. 22 passed; 0 failed
dos-core (all):       41 + 39 + 1 + 1 + 1 + 10 passed, 0 failed
dos-conformance:      11 passed; adapter_failures: 26 run, 1 failed
                      (orphan_holding_stderr_does_not_hang, the known Windows-only failure)
```

`dos-exec` tests ran 4 more times in a row: 22 passed each time (about 1 s).

`cargo fmt --all -- --check` (via the 1.96.0 msvc toolchain, which has rustfmt): exit 0.

Mutation check: removing the id-less guard on single messages makes
`id_less_tools_call_is_never_forwarded` fail (`assertion left == right failed`);
restored afterwards.

Parity tests (from `tests/gateway/test_mcp_proxy.py`): notifications and tool
hiding, allowed call forwarded, denied call never reaches the server, annotation
hint, ask approve/deny, parallel calls with server-initiated `roots/list` and
cancellation, audit of every outcome, bad command exits 127, replies after
half-close, id-less calls dropped, `resources/read` governed.

Fail-closed tests: engine error (`-32603`, not forwarded, audited), audit failure
(refused before the effect), Ask without a human, approval timeout, server death
mid-call (`-32603`), server death during an approval wait (wait aborted, refused),
ambiguous client JSON dropped (duplicate `method` both orders, NaN), mixed batch,
bad requests (`-32602`, non-object arguments), 30 parallel calls.

## Not done

- **Clippy not run.** The gnu toolchain has no clippy, and the msvc one cannot
  build build scripts without `link.exe`. I grepped for `unwrap`, `expect`,
  `panic!` and indexing in non-test code (none) and fixed two likely lints by
  hand. Run `cargo clippy --all-targets -- -D warnings` in CI.
- Tests were written together with the code, not run red first. The mutation
  check above is the only red-to-green evidence.
- No `dos-cli` subcommand, no file approval store shared with the dashboard, no
  notify or dashboard spawn, no session touch file. These belong to other crates.
- No conformance vectors under `conformance/vectors/mcp/` yet.
- No red-team or verifier pass yet.

## Open decisions

1. **Unparseable client lines are dropped.** The oracle forwards them raw. A
   Python server accepts NaN and resolves duplicate keys its own way, so
   forwarding lets a `tools/call` through that the proxy never saw. This is a
   security deviation from the oracle; per CLAUDE.md it may need an
   `ESCALATION.md` entry and a disagreement vector before merge.
2. **Server exit during an approval wait aborts the wait** with the reason "the
   MCP server exited". In the oracle the wait runs to its timeout, and the
   release then hangs on a future nobody completes. Rust refuses right away.
3. **Re-serialized messages.** Gated calls, batches and filtered `tools/list`
   replies are re-encoded by serde_json: keys sorted, and integers past u64 or
   i64 become floats. The server gets exactly the value that was decided on.
   Byte-exact forwarding would need `arbitrary_precision` and `preserve_order`,
   which would change serde_json features for the whole workspace.
4. **Engine interface.** `Verdict` has no redacted payload, so kernel redaction
   obligations (`redact_fields`) cannot change the forwarded arguments yet. The
   signed decision, PEP checks and one-time spend are assumed to live behind
   `DecisionEngine` and `AuditSink` until `dos-pep` exists; the engine task may
   want a different seam.
5. **Threads, not tokio.** tokio is not in the offline registry. Only `proxy.rs`
   would change.
6. The plan names the crate `dos-mcp`. The brief said `dos-exec`, so that is
   the name used here.
