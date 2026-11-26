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
| `conformance/` | Language-neutral test vectors and the runner that checks any implementation against them. |
| `crates/` | The Rust implementation (`dos-*`). |
| `docs/` | `docs/INDEX.md` maps all documentation, including the oracles' own. |

The oracles are imported with their full history and are not edited. Each one's CI
runs unchanged from its directory (`.github/workflows/oracle-*.yml`), and the AE
conformance suite runs against every implementation (`ae-conformance.yml`).

## License

Apache-2.0 (see each oracle's `LICENSE` for the imported code).
