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

## Conformance wiring (done)

`audit` area added to `dos-core-adapter` (`areas/audit.rs`, one line in `areas/mod.rs`, deps `dos-audit`, `dos-core`) and to `required` in `conformance/adapters/rust-dos-core/manifest.json`. Evidence: `dos-conformance --adapter dos-core-adapter.exe --area audit --require audit` -> `summary: 16 cases (ok 16, FAIL 0, unsupported 0 ...) result: PASS`. The oracle adapter answers `unsupported` for `audit` (it needs Python, which does not run here, and the oracle writes no signatures); it does not require the area.
Merge note: `areas/mod.rs` and the adapter `Cargo.toml` are also edited by sibling branches; resolve by keeping every area line and dependency.

## conformance-runner fix (Windows)

`orphan_holding_stderr_does_not_hang`: on Windows a grandchild inherits the adapter's stdout pipe, so the runner waited for an EOF that never came and then killed an adapter that had already exited fine, reporting FAIL. Fix in `crates/dos-conformance/src/runner.rs`: after the last response, if the adapter process itself has exited and nothing more is queued, stop waiting; an adapter that is still alive keeps the old timeout and kill (`adapter_that_never_exits_fails` still passes). Result: the runner now prints PASS and exits 0 in that case. The test still fails here, now only on its 10 s limit: its harness waits for the orphan to release the harness's own pipe (the orphan inherits the runner's stdout handle on Windows), which cannot be cleared without `unsafe` or a handle list, so it needs a Unix box or a test change (not made: existing tests are not edited).

## Formal and lint evidence (tools installed this round: Lean 4.36.0, rustfmt, clippy)

- `formal/audit/Audit.lean`: Lean 4 (core only) model of the chain. Proved: `append_valid`, `seq_eq_index`, `fork_free` (valid logs of equal length and equal head hash are equal), `valid_prefix`, `valid_take`, `anchor_binds` (an anchor pins the first n entries, so any earlier edit, insert, delete or reorder is detected), `truncation_visible`. Axiom: collision resistance of the entry hash (`Model.inj`). Signatures are not modelled. `lean Audit.lean` exits 0 with no output; `grep -c sorry` = 0. This is a model of the design, not a proof of the Rust code; the tie between them is the tests.
- `formal/audit/Verdict.lean`: pure logic of `crates/dos-core/src/verdict.rs` copied one to one (rank, meet, fold from the authority verdict, parse). Proved: commutative, associative, idempotent, DENY absorbs, ALLOW identity, result is an operand and at least as restrictive as both, permitting only if both operands are, `composeWith` permitting only if authority and every evaluator are, `composeWith` at least as restrictive as every input, DENY anywhere gives DENY, every non-canonical wire string parses to DENY. `lean Verdict.lean` exits 0 with no output; no `sorry`. `#print axioms` was not captured (the run timed out), so "no extra axioms" is unconfirmed beyond the clean compile.
- `cargo fmt --check -p dos-audit -p dos-core-adapter`: clean. `cargo clippy -p dos-audit -p dos-core-adapter --all-targets --no-deps -- -D warnings`: clean after fixing 4 findings (3 collapsible ifs, one `set_readonly(false)` in a test). Not mine: `cargo clippy` with deps fails in `crates/dos-core/src/sign.rs:157` (`chunks_exact` with a constant size) under `-D warnings`; the sign task owns it.

`#print axioms` (confirmed afterwards): every theorem depends on at most `propext` and `Quot.sound`, the standard Lean axioms; none uses `sorryAx`. The collision-resistance assumption is a hypothesis of `Model`, not a Lean axiom.
