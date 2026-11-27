# Status: audit (crate dos-audit)

Branch `task/audit`. Design: `design/audit.md`.

## What changed

| File | What |
|---|---|
| `crates/dos-audit/src/sink.rs` | `FileSink` implements `dos_core::store::AuditSink`: cross-process locked (`<log>.lock`), fsync'd, signed, hash-chained JCS lines; fail closed on torn or corrupt tail |
| `crates/dos-audit/src/anchor.rs` | `Anchor` trait, `FileAnchor` (signed head file `<log>.anchor`, atomic replace, wired by default), `read_anchor_file` |
| `crates/dos-audit/src/verify.rs` | `verify_file`, `verify_file_with_anchor_file`, typed errors with line index |
| `crates/dos-audit/src/entry.rs` | hash and signing payloads; Python-compatible legacy hash |
| `crates/dos-audit/tests/audit.rs` | 20 tests |

## Evidence

`cargo +stable-x86_64-pc-windows-gnu test --workspace --offline -j 2`: dos-audit `20 passed; 0 failed`; dos-core suites green; only failure is the known `orphan_holding_stderr_does_not_hang`.

Covered: round trip, resume, empty log, reserved/bad input, field edit, rehash without key, wrong/unknown key, reorder, delete middle, delete head, insert, tail truncation (chain alone passes, anchor catches), fork vs anchor, forged/garbage/missing anchor, torn line, garbage line, blank line, non-canonical line, 4 threads x 2 sinks concurrent append (60 entries verify), anchor failure propagates, unwritable path, Python-recipe hash of Rust log, Python-style log verifies in `python_compat` (incl. non-ASCII ASCII-escaped hash), Rust sink extends a Python log.

## Not done

- clippy not installed for this toolchain; lints (no unwrap/indexing) were followed by hand, not checked.
- No live Python-run cross check (python launcher broken on this box); Python's hash is reproduced with the documented recipe via `serde_json`.
- No conformance vectors under `conformance/vectors/audit/`; no `dos-pep` wiring.
- Kani/fuzz not added.

## Open decisions

1. Entry signatures reuse domain `audit-head`; a dedicated `audit-entry` domain needs a `spec/sign.md` change.
2. A Rust log is verifiable by Python's `verify()` only for ASCII entries (JCS vs ASCII-escaped hash, DM-3). Python cannot check `sig`.
3. Default anchor is a local file next to the log (same trust domain); real tamper evidence needs an external anchor.
4. Sink continues a Python log (hash-checked tail) though its lines are not JCS; strict verify then reports `non_canonical`, compat mode accepts.

## TODO (remaining phases, independent unless noted)

- [ ] Conformance area `audit`: vectors in `conformance/vectors/audit/` (op `verify` over an inline log, expected `ok` or `{error: <VerifyErrorKind code>}`), adapter op in `dos-core-adapter` or a `dos-audit` adapter, oracle adapter for `audit.py` (`oracle_expected` for DM-3 non-ASCII). Closes CS-1 audit part.
- [ ] `dos-pep` wiring: call `AuditSink::append` before every effect, every refusal path (DM-1); fail closed on `StoreError`.
- [ ] Live cross-check with Python `HashLog.verify()` on a Rust log and Rust verify on a Python log (needs a working Python).
- [ ] Dedicated `audit-entry` sign domain (spec/sign.md change, Ali's decision).
- [ ] External anchor implementation (WORM or remote) behind the `Anchor` trait.
- [ ] Fuzz target for `verify_bytes` and sink tail scan; Kani not needed (no unsafe).
- [ ] Run `cargo clippy -p dos-audit` where clippy is installed.
- [ ] CLI: `dos audit verify <log> [--anchor]`.

Phases are sequential only where they touch shared files: vectors and pep wiring both need the `dos-audit` API, which is stable now, so they can run in parallel worktrees.
