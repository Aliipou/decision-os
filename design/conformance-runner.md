# conformance-runner

## Goal

One runner (`crates/dos-conformance`) that checks any implementation's adapter against
`conformance/vectors/` exactly as `spec/CONFORMANCE.md` says, an entry point
(`conformance/run.sh`) for the gate and CI, the oracle adapter
(`oracle-decision-os-min`: areas `selftest`, `meet`), a Rust adapter skeleton
(`crates/dos-core-adapter`: area `selftest`), a `selftest` vector area, and a CI workflow.

Done when: the runner refuses every malformed vector and every adapter misbehaviour listed
below with a nonzero exit, `conformance/run.sh --all` is green with both adapters, and the
gate is green.

Out of scope: vectors for real areas (other tasks), wiring dos-core into the Rust adapter,
Windows execution of shebang adapters (see Risks).

## Choices

### 1. JSON parsing: own strict parser (chosen) vs serde_json

serde_json is the obvious choice, but:

- Without `arbitrary_precision`, integers above `u64` and every decimal become `f64`, so
  `0.1` and `0.10000000000000001` compare equal, and so do `2^53` and `2^53 + 1`. That is
  a comparator that says `ok` for a wrong answer.
- With `arbitrary_precision`, a literal object `{"$serde_json::private::Number": "5"}` is
  parsed as the number `5` (serde_json's private magic key), so an adapter can forge a
  number. It also has no duplicate-key hook without a second pass.
- serde_json refuses lone surrogate escapes (`"\ud800"`), which a `jcs` vector must be
  able to carry as input.

So the runner parses with a small RFC 8259 parser (`json.rs`, about 300 lines) that keeps
each number's lexeme, keeps strings as UTF-16 code units (lone surrogates survive),
keeps object member order (for re-emitting requests) and refuses duplicate keys, raw
control characters, a BOM, trailing data, depth over 128 and exponents over 10^15.
serde_json is a dev-dependency only: a differential test checks that both parsers accept
and reject the same documents (outside the deliberate differences above).

### 2. Number equality: exact decimal value (chosen) vs f64

A number is normalised to (sign, significant digits without leading or trailing zeros,
exponent). Two numbers are equal iff the triples are equal, so `1`, `1.0`, `10e-1` and
`1E0` are equal, `9007199254740993 != 9007199254740992`, `0.1 != 0.10000000000000001`,
and every zero (`0`, `-0`, `0.0e5`) is one value. This is exact equality of the
mathematical values, which is what "numbers compared as parsed values" can mean without a
lossy step. Written in `spec/CONFORMANCE-notes.md`.

### 3. Broken test adapter: the integration test binary itself (chosen) vs a shell script

`tests/adapter_failures.rs` is a `harness = false` test whose `main` acts as an adapter
when `DOS_TEST_ADAPTER_MODE` is set and otherwise runs the checks, spawning the runner
binary with itself as the adapter. Portable (no `sh`, no Python) and never shipped.

### 4. Adapter discovery: mandatory manifest (chosen) vs "any executable named adapter"

Every directory under `conformance/adapters/` must have a `manifest.json`; a directory
without one fails `run.sh` (no adapter silently skipped):

```json
{"v": 1, "command": ["./adapter"], "required": ["selftest"], "oracle": false}
```

`command` is an argv; a first element starting with `./` is resolved against the
manifest directory, which is also the adapter's working directory. `required` areas
must be fully supported whenever they are selected. `oracle: true` makes the runner check
`oracle_expected` when present.

### 5. Oracle adapter loads `compose.py` by file path (chosen) vs `import decision_os_min`

The package `__init__` imports the kernel, which needs `cryptography`. The protected
`full-gate` job runs the gate (and so `run.sh`) on Python 3.12 without `cryptography`,
and that workflow is frozen. `compose.py` documents that it imports nothing internal, so
the adapter loads that file as `decision_os_min.compose` with `sys.dont_write_bytecode`
and `python3 -I -B`. Same bytes, same behaviour, nothing written under `oracle/`. Future
areas that need the kernel import the package lazily (oracle dir is on `sys.path`).

## Protocol behaviour (beyond the spec text)

- Requests are streamed in order (area, then name, byte order) by a writer thread; stdin
  is closed after the last one, so an adapter that answers only after EOF still works.
- Each response line must end in `\n` (a trailing `\r` is tolerated), be at most 16 MiB,
  parse strictly, and be exactly `{"name", "output"}` with `name` equal to the request's
  and `output` exactly one of `{"ok": v}`, `{"error": "<non-empty>"}`, `{"unsupported": true}`.
- Per-case timeout (default 10 s) is the wait for the next response line; overall timeout
  default 300 s. On a timeout the adapter is killed and the remaining cases are missing.
- After the last response the runner waits for EOF; any further line is `extra`.
- Exit code 0 only if: at least one case ran, every selected area has at least one
  vector, every case is `ok` or `unsupported` in a non-required area, no extra line, the
  adapter exited with status 0 (not by signal) within the timeout. Otherwise 1. Usage and
  vector-format errors exit 2.

## Failure modes (each must refuse)

| Failure | Refused by | Test (`tests/adapter_failures.rs` unless noted) |
|---|---|---|
| unknown / missing field, wrong `v`, `name` != file, `area` != dir, case-only duplicate names, non-`.json` file, BOM, CR, duplicate JSON key | vector loader, exit 2 | `bad_vectors_are_hard_errors` |
| wrong output | compare | `wrong_output_fails`, `numbers_compare_exactly` |
| missing / extra / malformed / wrong-name / partial line | protocol reader | `missing_line_fails`, `extra_line_fails`, `malformed_json_fails`, `malformed_shapes_fail`, `partial_last_line_fails`, `early_exit_fails` |
| adapter crash (signal) or nonzero exit | exit status | `crash_fails`, `nonzero_exit_fails` |
| hang (no answer, never exits, orphan holding stderr) | case + overall timeout, kill, bounded stderr wait | `case_timeout_fails`, `overall_timeout_fails`, `adapter_that_never_exits_fails`, `orphan_holding_stderr_does_not_hang` |
| `unsupported` in a required area | compare | `unsupported_allowed_unless_required`, `manifest_required_and_oracle` |
| zero cases (no areas, empty area), absent selected/required area, required-area typo in a manifest | runner, exit 1 / 2 | `zero_cases_fail`, `manifest_required_and_oracle` |
| precision loss, forged number, duplicate keys in a response | strict parser, exact decimal compare | `json::tests::*`, `malformed_shapes_fail` |
| adapter not found | spawn error -> fail | `missing_adapter_fails` |
| bad manifest or CLI | exit 2 | `bad_manifests_are_hard_errors`, `usage_errors` |

## Test plan

Unit tests (json, vector, compare) and the harness-free integration test above; run with
`cargo test -p dos-conformance -p dos-core-adapter`. Then `conformance/run.sh --all`
against both adapters, plus the gate.
