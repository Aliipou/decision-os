# Status: conformance-runner

Branch `task/conformance-runner`. Design: `design/conformance-runner.md`. Precise
wording for the points `spec/CONFORMANCE.md` leaves open: `spec/CONFORMANCE-notes.md`
(new file; CONFORMANCE.md is not edited).

All commands below ran in WSL Ubuntu against the worktree via a wrapper that sets
`GIT_DIR`/`GIT_WORK_TREE` to the worktree (the `.git` file holds a Windows path),
`core.autocrlf=true` (as on the Windows side) and `CARGO_TARGET_DIR=/root/target/conf`.

## What changed

| Path | What |
|---|---|
| `crates/dos-conformance/src/json.rs` | strict RFC 8259 parser and writer: exact decimal number equality, strings as UTF-16 units (lone surrogates kept, compare by code points), duplicate keys, BOM, raw controls, depth > 128, exponent magnitude >= 10^15 refused, no magic keys |
| `src/vector.rs` | loads `conformance/vectors/<area>/<name>.json`, every format deviation is an error (all reported, exit 2) |
| `src/manifest.rs` | adapter manifest `{"v":1,"command":[...],"required":[...],"oracle":bool}` |
| `src/protocol.rs` | request/response lines, `Output`, `serve()` loop for Rust adapters |
| `src/runner.rs`, `src/main.rs` | spawn, stream, per-case and overall timeouts, judge, print, `--json` report |
| `tests/adapter_failures.rs` | `harness = false`: the test binary is also the deliberately broken adapter; 26 checks |
| `crates/dos-core-adapter` | Rust adapter: `selftest` only, dispatch table in `src/areas/mod.rs` |
| `conformance/adapters/oracle-decision-os-min/` | `adapter` (sh: `python3 -I -B adapter.py`), `adapter.py` (selftest, meet), manifest |
| `conformance/adapters/rust-dos-core/` | `adapter` (sh, execs the built binary), manifest |
| `conformance/adapters/.gitattributes` | extensionless `adapter` scripts stay LF on Windows checkouts |
| `conformance/run.sh` | entry point: `--all` or `--changed-since <rev>`, `--adapter <name>`, `--json-dir <dir>` |
| `conformance/vectors/selftest/` | 13 vectors |
| `.github/workflows/conformance.yml` | ubuntu-latest, Rust stable, Python 3.12, `cryptography>=42`, unit tests, `run.sh --all`, report artifact |
| `Cargo.lock` | `dos-core-adapter`; dev-only `serde_json` 1.0.154 and its deps |

## CLI

```
dos-conformance (--adapter <program> [--arg <a>]... | --manifest <manifest.json>)
                [--vectors <dir>] [--area <a>]... [--require <a>]... [--oracle]
                [--json <report>] [--case-timeout <secs>] [--timeout <secs>]
exit 0 pass, 1 conformance failure, 2 usage, manifest or vector-format error
```

Defaults: `--vectors conformance/vectors`, every area, case timeout 10 s, overall 300 s.
The adapter gets `DOS_CONFORMANCE_BIN_DIR` (the runner's own directory) in its
environment; with `--manifest` its working directory is the manifest directory.

## Evidence

### Tests written first, seen failing (against stubs)

`cargo test -p dos-conformance` with a stub parser:

```
test json::tests::accepts_rfc8259_documents ... FAILED
test json::tests::agrees_with_serde_json ... FAILED
test json::tests::agrees_with_serde_json_on_values ... FAILED
test json::tests::depth_is_bounded ... FAILED
test json::tests::numbers_compare_by_exact_value ... FAILED
test json::tests::object_key_order_is_ignored ... FAILED
test json::tests::rejects_non_json ... ok
test json::tests::serde_magic_key_is_just_an_object ... FAILED
test json::tests::strings_compare_by_code_points ... FAILED
test json::tests::write_round_trips_and_keeps_lexemes_and_order ... FAILED
test result: FAILED. 1 passed; 9 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

`cargo test -p dos-conformance --test adapter_failures` with an empty `main`:

```
test good_adapter_passes ... FAILED
test late_answers_after_eof_pass ... ok
test wrong_output_fails ... FAILED
... (every other check FAILED)
adapter_failures: 25 run, 24 failed
```

(`rejects_non_json` and `late_answers_after_eof_pass` pass trivially against a stub that
rejects everything / exits 0; both are meaningful against the real code.)

Self-attack round (see below), new tests red before the fix:

```
test orphan_holding_stderr_does_not_hang ... FAILED   (runner waited ~30 s for the grandchild)
test manifest_required_and_oracle ... FAILED
want exit 2
exit Some(0)
note: required area "absent" has no vectors yet (no /tmp/dos-conf-test-8344-1/absent/)
adapter_failures: 2 run, 2 failed
```

### Tests green

`cargo test -q -p dos-conformance -p dos-core-adapter`:

```
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.41s
test good_adapter_passes ... ok
test late_answers_after_eof_pass ... ok
test wrong_output_fails ... ok
test missing_line_fails ... ok
test extra_line_fails ... ok
test malformed_json_fails ... ok
test malformed_shapes_fail ... ok
test partial_last_line_fails ... ok
test crash_fails ... ok
test nonzero_exit_fails ... ok
test early_exit_fails ... ok
test case_timeout_fails ... ok
test overall_timeout_fails ... ok
test adapter_that_never_exits_fails ... ok
test orphan_holding_stderr_does_not_hang ... ok
test missing_adapter_fails ... ok
test unsupported_allowed_unless_required ... ok
test zero_cases_fail ... ok
test bad_vectors_are_hard_errors ... ok
test oracle_mode_uses_oracle_expected ... ok
test numbers_compare_exactly ... ok
test area_selection ... ok
test json_report ... ok
test manifest_required_and_oracle ... ok
test bad_manifests_are_hard_errors ... ok
test usage_errors ... ok
adapter_failures: 26 run, 0 failed
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

Required failure classes and the check that proves each: wrong output
`wrong_output_fails`; missing line `missing_line_fails`, `early_exit_fails`; extra line
`extra_line_fails` (asserts "1 extra line(s) after the last response"); malformed JSON
`malformed_json_fails` and 21 shapes in `malformed_shapes_fail` (including duplicate keys
and the serde magic key); crash `crash_fails` (asserts "crashed (signal 6)" on unix);
timeout `case_timeout_fails`, `overall_timeout_fails`, `adapter_that_never_exits_fails`;
unsupported in a required area `unsupported_allowed_unless_required`,
`manifest_required_and_oracle`; zero cases `zero_cases_fail`. The differential test
`agrees_with_serde_json` checks at least 10,000 mutated documents (accept/reject must
match serde_json except for the deliberate differences).

### Both adapters, all areas

`bash conformance/run.sh --all 2>&1 | grep -vE '^ok '` (final code; the 13 `ok` lines per
adapter filtered out here, listed in full in an earlier run: echo-bool, echo-decimal,
echo-empty-containers, echo-exponent-is-integer, echo-integer-beyond-f64,
echo-integer-beyond-u64, echo-key-order, echo-lone-surrogate, echo-null,
echo-unicode-escapes, error-code, invalid-input, unknown-op):

```
conformance: building runner and Rust adapter

=== adapter oracle-decision-os-min
summary: 13 cases (ok 13, FAIL 0, unsupported 0, MISSING 0, MALFORMED 0, TIMEOUT 0), extra lines 0
adapter: exit 0
required areas: selftest
result: PASS

=== adapter rust-dos-core
summary: 13 cases (ok 13, FAIL 0, unsupported 0, MISSING 0, MALFORMED 0, TIMEOUT 0), extra lines 0
adapter: exit 0
required areas: selftest
result: PASS

conformance: all adapters passed
exit=0
```

### Oracle adapter accepts the `meet` input shapes

Scratch vectors (not committed) in the three shapes, one deliberately wrong:

```
ok          meet/compose-empty
ok          meet/compose-many
FAIL        meet/deliberately-wrong  expected {"ok":"ALLOW"} got {"ok":"DENY"}
ok          meet/meet-allow-deny
ok          meet/meet-limit-contain
ok          meet/meet-nonstring
ok          meet/meet-unknown
ok          meet/missing-field
ok          meet/parse-allow
ok          meet/parse-lower
summary: 10 cases (ok 9, FAIL 1, unsupported 0, MISSING 0, MALFORMED 0, TIMEOUT 0), extra lines 0
exit=1
```

Same vectors with `DOS_PYTHON` set to a `python3 -S` shim (no site-packages, so no
`cryptography`, like the frozen `full-gate` job; `python3 -S -c 'import cryptography'`
gives `ModuleNotFoundError: No module named 'cryptography'`), via
`--adapter conformance/adapters/oracle-decision-os-min/adapter --oracle`:

```
summary: 10 cases (ok 9, FAIL 1, unsupported 0, MISSING 0, MALFORMED 0, TIMEOUT 0), extra lines 0
adapter: exit 0
result: FAIL
  - not every case passed
```

The same scratch directory through the oracle *manifest* is now refused, because the
manifest requires `selftest` and the scratch directory has none:
`error: the manifest requires area "selftest", which has no directory under .../mv`, exit 2. The Rust adapter on the same
vectors: `summary: 10 cases (ok 0, ..., unsupported 10, ...)`, `result: PASS`, exit 0
(`meet` not required for it).

### run.sh failure and selection modes

```
### A. adapter dir without manifest
conformance: conformance/adapters/zz-nomanifest/ has no manifest.json
conformance: FAILED
exit=1
### B. broken python (oracle adapter cannot start)
  - adapter: adapter exit 1
  - not every case passed
conformance: adapter oracle-decision-os-min FAILED
exit=1
### C. --changed-since HEAD (uncommitted runner changes => all)
conformance: runner, adapters, crates, oracle or spec changed since HEAD; running all areas
conformance: all adapters passed
exit=0
### E. unknown adapter / bad revision
conformance: no adapter ran (no adapter named nope)
exit=1
conformance: unknown revision nosuchrev
exit=2
### F. only an untracked selftest vector changed
conformance: changed areas: selftest
ok          selftest/zz-scratch
ok          selftest/zz-scratch
conformance: all adapters passed
exit=0
### G. nothing changed
conformance: no vector area changed since HEAD; nothing to run
exit=0
### H. docs-only change
conformance: no vector area changed since HEAD; nothing to run
exit=0
```

Executable bits in git: `git ls-files -s conformance/run.sh conformance/adapters/*/adapter`
gives `100755` for all three.

### Gate and protected paths

```
$ bash scripts/gate-fast.sh fast
ok       cargo fmt
ok       cargo clippy
ok       cargo test (dos-conformance dos-core dos-core-adapter )
ok       conformance (changed areas)
ok       protected paths unchanged
gate exit=0
$ bash scripts/check-protected.sh
note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked
protected paths: unchanged
protected exit=0
$ git status --short --ignored oracle/ | wc -l
0
```

## Self-attack (checklist)

Found and fixed, each with a permanent test:

1. Hang (S2): the runner joined the stderr reader thread; an adapter whose background
   grandchild keeps stderr open hung the runner. Now stderr is collected over a channel
   with a 500 ms wait. Test `orphan_holding_stderr_does_not_hang`.
2. Fail-open on a typo (S1-ish for the gate): a manifest `required` entry for a missing
   area only printed a note, so `"slftest"` would silently drop the requirement. Now any
   absent manifest-required area is exit 2. Test `manifest_required_and_oracle`.
   Consequence: `meet` is not in the oracle manifest's `required` yet (no vectors); add it
   in the change that lands `conformance/vectors/meet/`.

Checked, no change needed: a writer blocked on an adapter that never reads stdin (runner
times out and kills; writer thread ends on EPIPE); adapter stdout held open after exit
(case timeout, "did not exit", killed); output text breaking line structure (names are
identifiers, details pass through `show()` which strips CR/LF; the writer escapes
controls, U+2028/2029); the serde_json `arbitrary_precision` magic key (own parser, test
`serde_magic_key_is_just_an_object`); relative program path plus `current_dir` (manifest
directory canonicalised); oracle tree writes (`-I -B`, `sys.dont_write_bytecode`,
compose.py loaded by path; `git status --ignored oracle/` empty).

Three ways this could cause an incident in six months:
- A Rust adapter answers `unsupported` for a new area whose vectors landed but which no
  manifest lists as required: that area passes while unimplemented. Mitigation: the
  summary prints the unsupported count; the integrator must add areas to `required`.
- The frozen `protected.yml` full-gate job has no `cryptography`. Oracle areas that need
  the kernel (sign, verdict) will fail there once their vectors exist. Needs Ali (that
  workflow is protected) or a lazy import that reports `unsupported` there, which would
  then hide the oracle in that job only (conformance.yml still runs it with cryptography).
- Slow CI start-up of Python under the 10 s first-response timeout would make the gate
  flaky. Measured locally well under a second; `--case-timeout` exists if needed.

## Not done

- Windows native execution of adapters: `std::process` cannot run shebang scripts on
  Windows, so `run.sh` from Git Bash reports the adapters as failing to start (fail
  closed). The runner and its tests are portable; run.sh is meant for Linux, macOS, WSL
  and CI. Not tested on macOS.
- Not run on Windows natively (`cargo test` was run in WSL only).
- No `meet` vectors committed (owned by another task); shapes checked with scratch vectors.
- Size: `wc -l` over the non-test Rust, run.sh and the adapters gives 2147 lines
  (rustfmt-expanded), far above the ~400-line guideline;
  the task inherently spans runner, two adapters, entry point and CI.

## Open risks

- `json.rs` is our own parser. It is differential-tested against serde_json and unit
  tested, but it is the piece that decides `ok`; the red team should fuzz it further.
- Requests re-serialise `input` (whitespace and string escapes normalised, lexemes and
  member order kept). An area that needs raw input bytes must carry them as a string
  (written in CONFORMANCE-notes.md).
- The selftest echo goes through Python `float` for decimals in the oracle adapter, so a
  selftest vector with more than 17 significant digits in a fraction would fail for the
  oracle (correctly flagged, but a limit for future selftest vectors).
