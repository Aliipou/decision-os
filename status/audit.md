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

## Phase 2 (this round)

| Item | State |
|---|---|
| Refactor | `verify_bytes` public; anchor check simplified; `head()` and resume read only the log tail |
| Conformance vectors | 16 files in `conformance/vectors/audit/` (valid, edit, reorder, delete, duplicate, truncation with and without anchor, fork, unknown key, empty, torn line, non-canonical, oracle log strict and compat); checked by `crates/dos-audit/tests/vectors.rs` (generates missing files only) |
| CLI | `dos-audit verify <log> --key <hex>... [--anchor-file p] [--python-compat]`, exit 0/1/2, tested |
| Fuzz | `fuzz/fuzz_targets/audit.rs` written; NOT built (libfuzzer-sys is not in the offline registry, needs nightly); `fuzz/Cargo.lock` not regenerated |
| Tests | dos-audit: 21 + 1 vector test, all pass; workspace only fails the known orphan test |

## Still TODO

- [ ] Wire `audit` area into `dos-core-adapter` and the oracle adapter (`oracle-decision-os-min/adapter.py`); the vectors are ready. Not done here: it edits `areas/mod.rs`, which sibling branches also edit (merge conflict risk), and Python does not run on this machine.
- [ ] `dos-pep` wiring (crate does not exist on this branch).
- [ ] Live Python cross-check; external anchor; dedicated `audit-entry` domain (Ali's decision); clippy run; build the fuzz target (online, nightly).

## Red team and verification round

Finding fixed (S2): `FileSink` cached the head keyed on file length, so a log swapped for another of the same length between two appends from one sink would be chained from a stale head. The cache is gone; every append re-reads the last line (test `sink_follows_the_disk_not_a_cache`).

New tests in `crates/dos-audit/tests/redteam.rs` (11): every single-bit flip (two bits per byte) of a 3-entry log is detected with the anchor; every byte prefix is detected; extensions and duplicates refused; all line permutations and removals; signature replay across entries; cross-domain signatures; stripped-and-rehashed signatures refused in strict mode; 3 OS processes x 25 appends verify as one 75-entry chain; hostile inputs (deep nesting, BOM, bad UTF-8, huge numbers) never panic, in the verifier and the sink.

Evidence: `cargo test -p dos-audit --offline -j 2`, run 6 times, all green (21 + 11 + 1 + 1 tests); workspace run: only the known `orphan_holding_stderr_does_not_hang` fails.

Known limits (by design, not defects): a writer holding the key can rewrite the whole log and anchor together; rolling back log and anchor to an older matching pair is undetectable without an external anchor; `python_compat` mode lets an attacker strip signatures and rehash.
