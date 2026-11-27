# Decision OS

Security infrastructure for AI agents. A kernel signs a decision bound to one exact
action, an executor runs the effect only with that decision and a one-time token, and
every outcome goes into one tamper-evident audit log. A gateway puts this in front of
every MCP server and model API an agent uses.

This repository is the Rust rewrite. The plan is `RUST_REWRITE.md`; the way work is
done is `CLAUDE.md`.

## Layout

| Path | What |
|---|---|
| `oracle/decision-os-min/` | The Python kernel, executor and gateway (shipped as `decision-os-min`). Frozen reference. |
| `oracle/sluicegate-py/` | sluicegate: capability authority, Rust TCB, Lean and TLA+ models. Frozen reference. |
| `oracle/contracts-spec/` | The Authority Enforcement Profile (AE-1..AE-10) and its conformance suite. Frozen reference. |
| `spec/` | The normative spec. `spec/KNOWN_GAPS.md` lists every gap found in the oracles and what Rust must do instead. |
| `conformance/` | Language-neutral test vectors and the runner that checks any implementation against them (arrives with the first Rust tasks; `dos-audit` exists). |
| `crates/` | The Rust implementation (`dos-*`, arrives with the first Rust tasks; `dos-audit` exists). |
| `docs/` | `docs/INDEX.md` maps all documentation, including the oracles' own. |

## Audit log (`dos-audit`)

An append-only log: one JCS line per entry, each entry hash-chained to the previous one
and signed with Ed25519, plus a signed head file (the anchor) that makes tail truncation
detectable. `FileSink` implements `dos_core::store::AuditSink`; appends are locked across
processes and fsynced, and a damaged tail refuses further appends.

```text
dos-audit verify <log> --key <ed25519-public-key-hex> [--anchor-file <log>.anchor] [--python-compat]
```

Exit 0 verifies, 1 does not (reason on stderr), 2 is a usage error. `--python-compat`
verifies logs written by the Python oracle. A mixed Rust and Python deployment must
share one lock file (`FileSink::with_lock_path`). Design: `design/audit.md`; status and
open decisions: `status/audit.md`; red-team results: `findings/audit.md`.

The oracles are imported with their full history and are not edited. Each one's CI
runs unchanged from its directory (`.github/workflows/oracle-*.yml`), and the AE
conformance suite runs against every implementation (`ae-conformance.yml`).

## License

Apache-2.0 (see each oracle's `LICENSE` for the imported code).
