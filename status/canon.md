# Status: canon (RFC 8785 JCS in dos-core)

Branch `task/canon`. Design: `design/canon.md`. Spec: `spec/canon.md`.

## What changed

| File | What |
|---|---|
| `crates/dos-core/src/canon.rs` | `parse_strict`, `to_jcs`, `canonicalize`, `Value`, `Number`, `CanonError`, `MAX_DEPTH` (531 non-blank, non-comment lines) |
| `crates/dos-core/Cargo.toml`, `Cargo.lock` | dev-dependencies only: `proptest 1.12.0`, `ryu-js 1.0.4`. dos-core has **no runtime dependency** |
| `crates/dos-core/tests/canon.rs` | 39 tests: every RFC 8785 example, each refusal, boundaries, 7 property tests |
| `crates/dos-core/tests/canon_vectors.rs` | runs every `conformance/vectors/jcs/*.json` (read with `parse_strict` itself) |
| `crates/dos-core/tests/jcs/differential.py`, `gen_vectors.py` | differential against `rfc8785`; vector generator |
| `crates/dos-core/examples/jcs_lines.rs` | stdin/stdout driver for the differential |
| `conformance/vectors/jcs/` | 106 new vectors, 48 with `gap: DM-2` and a computed `oracle_expected` |
| `fuzz/` | cargo-fuzz crate (own `[workspace]`), target `canon` |
| `spec/canon.md`, `design/canon.md`, this file | |

## Public API

```rust
pub const MAX_DEPTH: usize = 128;
pub struct Number(f64);                    // private field
impl Number { pub fn new(f64) -> Result<Number, CanonError>; pub fn get(self) -> f64 }
pub enum Value { Null, Bool(bool), Number(Number), String(String),
                 Array(Vec<Value>), Object(Vec<(String, Value)>) }
pub enum CanonError { LeadingBom, InvalidUtf8, Syntax, TrailingData, InvalidEscape,
    LoneSurrogate, Noncharacter, DuplicateKey, DepthExceeded, NonFiniteNumber, UnsafeInteger }
impl CanonError { pub fn code(self) -> &'static str }   // also Display, core::error::Error
pub fn parse_strict(bytes: &[u8]) -> Result<Value, CanonError>;
pub fn to_jcs(value: &Value) -> Result<Vec<u8>, CanonError>;
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, CanonError>;
```

Codes: `leading_bom invalid_utf8 syntax trailing_data invalid_escape lone_surrogate
noncharacter duplicate_key depth_exceeded non_finite_number unsafe_integer`.

## Decisions to confirm (Ali)

1. **Integer literals.** RFC 8785 itself rounds numbers (its 3.2.2 sample turns
   `333333333.33333329` into `333333333.3333333`), so a blanket "refuse inexact numbers"
   would refuse the RFC's own example. A blanket I-JSON range check on integers
   (what the `rfc8785` reference does) would refuse JCS's own output (`9007199254740992`,
   `295147905179352830000` are Appendix B rows), so canonical bytes would not re-parse.
   Chosen rule: an integer literal is accepted only if it is its own JCS text, so integer
   literals always pass through canonicalization unchanged (`9007199254740993` is
   `unsafe_integer`). Fraction and exponent forms are rounded per the RFC. Residual risk
   in spec/canon.md: `9007199254740993.0` is accepted and becomes `9007199254740992`.
2. **Noncharacters are refused** (RFC 7493 2.1 MUST NOT; RFC 8785 3.1 requires I-JSON).
   The `rfc8785` reference accepts them.
3. **ryu-js not used at runtime.** It has 43 `unsafe` lines (19 `unsafe {` blocks).
   RUST_REWRITE.md makes an unsafe dependency in dos-core a stop condition, so numbers are
   formatted from core's safe `{:e}` shortest digits plus an exact tie fix (below). ryu-js
   is a dev-dependency test oracle only.

## Evidence

### Tests first (red)

Against the stub (types real, functions refusing everything):

```
$ wsl ... CARGO_TARGET_DIR=/root/target/canon cargo test -p dos-core
test result: FAILED. 5 passed; 32 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.78s
error: test failed, to rerun pass `-p dos-core --test canon`
$ ... cargo test -p dos-core --test canon_vectors
failures:
    jcs_vectors
test result: FAILED. 0 passed; 1 failed; ...
```

The 5 that passed do not depend on the implementation (error code table, NaN refusal by
`Number::new` stub, never-panic properties, syntax errors refused by the stub).

### Bug found by the tests: ECMAScript Note 2 ties

The first implementation used core's `{:e}` digits directly. Three tests failed:

```
---- rfc8785_appendix_b_serialize stdout ----
assertion `left == right` failed: bits 43143ff3c1cb0959
  left: Ok("1424953923781206.3")
 right: Ok("1424953923781206.2")
---- numbers_match_ryu_js stdout ----
  left: `Ok("1120913795580492.3")`,
 right: `Ok("1120913795580492.2")` ...
minimal failing input: bits = 4832322511278445154
```

core breaks an exact tie between two shortest candidates upwards; ECMA-262 7.1.12.1 Note 2
(RFC 8785 3.2.2.3, Appendix B note 4) takes the even one. Fixed in `shortest()`: the tie
is detected exactly by comparing the 2- and 5-adic factorizations of `m * 2^q` and
`(2s -+ 1) * 5 * 10^(x-1)` (no bignum, no overflow). Regression test
`exact_ties_round_to_even` keeps both inputs. Two of my own test expectations were also
wrong and were corrected before any code depended on them: `\udbff\udfff` is U+10FFFF, a
noncharacter (now refused, vector `str-nonchar-10ffff`); `123456789012345678901` is an
unsafe integer under the rule above.

### Green (Linux, WSL, Rust 1.96)

```
$ wsl ... CARGO_TARGET_DIR=/root/target/canon cargo test -p dos-core
     Running tests/canon.rs
test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 41.29s
     Running tests/canon_vectors.rs
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.96s
```

Property tests inside: `idempotent` (4096 random values), `parse_never_panics` (4096
random byte strings up to 512 bytes), `parse_never_panics_on_json_like`,
`mutated_canonical_never_panics`, `integers_in_safe_range_round_trip`,
`numbers_match_ryu_js` (200,000 random f64 bit patterns, output equal to ryu-js and
parses back to the same bits), `tie_prone_numbers_match_ryu_js` (4096 `m * 2^e`).

### Green (Windows, stable-x86_64-pc-windows-gnu 1.96)

```
PS> cargo +stable-x86_64-pc-windows-gnu test -p dos-core
running 39 tests
test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 27.15s
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
test exit=0
```

### Differential against Trail of Bits `rfc8785` 0.1.4

Venv `/root/venv/canon-jcs`, installed with `HOME=/tmp/canon-home`
(`pip install rfc8785==0.1.4`). Reference = `rfc8785.dumps(json.loads(text))`.
Inputs: random nested values (random key order, whitespace, `\u` escapes in both cases,
surrogate pairs, control characters, non-BMP keys, numbers as repr, `%.17e`, trailing
zeros, upper-case exponents), random f64 bit patterns, `m * 2^e` tie-prone doubles,
decimal strings with exponents from -330 to 310, and 20 hand-picked edge inputs.

```
$ python -I crates/dos-core/tests/jcs/differential.py --driver /root/target/canon/release/examples/jcs_lines --values 200000 --floats 1000000 --seed 8785
inputs=1200053 values=200000 floats=1000033 extra=20 seed=8785
agree=1200028 explained={'big_int_canonical': 3, 'noncharacter': 20, 'duplicate_key_python_last_wins': 1, 'depth_python_accepts': 1} unexplained=0
exact-tie floats in corpus (Note 2 cases)=6819
our refusals=32

$ python -I crates/dos-core/tests/jcs/differential.py --driver ... --values 300000 --floats 200000 --seed 20261127
inputs=500053 values=300000 floats=200033 extra=20 seed=20261127
agree=500017 explained={'big_int_canonical': 3, 'noncharacter': 31, 'duplicate_key_python_last_wins': 1, 'depth_python_accepts': 1} unexplained=0
exact-tie floats in corpus (Note 2 cases)=1406
```

1,700,106 inputs, **0 unexplained disagreements**. Explained ones, each by spec rule:
`big_int_canonical` (we accept `2^53`, `-2^53` and `295147905179352830000`; the
reference refuses every int beyond 2^53-1; the check also asserts our output decodes to
the same exact Python ints as the input), `noncharacter` (RFC 7493 2.1), one duplicate
key (Python keeps the last; the reference never sees it) and one 129-deep input (the
reference has no depth limit). Where both refuse, error codes are not compared (the
reference has none).

### Conformance vectors

```
$ python -I crates/dos-core/tests/jcs/gen_vectors.py --check
vectors=106 with_gap_DM-2=48 reference_exceptions=5
exit=0
```

All RFC 8785 examples are vectors: 3.2.2 sample (with the 3.2.3/3.2.4 output), 3.2.3
sort example, the "", a, aa, ab example, and all 26 Appendix B rows (24 values, NaN,
Infinity). Every `ok` vector matches `rfc8785` except the 5 Appendix B integer rows
(the reference raises `IntegerDomainError` on its own RFC's output). `oracle_expected`
is computed by running `json.dumps(json.loads(x), sort_keys=True, separators=(",", ":"))`.
Non-UTF-8 and raw noncharacter inputs use `{"bytes_hex": ...}`, defined in spec/canon.md.

### Attack on my own change

Five inputs most likely to break it, timed through the release driver (includes 2x hex
encoding of the input):

```
10MB-digit fraction          0.89s exit=0 -> ok 302e31313131...   ("0.1111111111111111")
10MB-digit integer           1.82s exit=0 -> err non_finite_number
1e+huge exponent             0.04s exit=0 -> err non_finite_number
0e-huge exponent             0.07s exit=0 -> ok 30
200k distinct keys           1.90s exit=0 -> ok ...
200k keys last dup           0.87s exit=0 -> err duplicate_key
10MB escaped string          1.43s exit=0 -> ok ...
1M-element array             2.33s exit=0 -> ok ...
128-deep x 10000 wide        1.75s exit=0 -> ok ...
```

All linear. Deep nesting: `"[" * 1_000_000` and 200,000 closed levels give
`depth_exceeded` without stack growth (test `depth_limit`). Duplicate names via escapes
(`"a"`/`"\u0061"`, surrogate pair vs raw emoji) are caught (tests and vectors).

Three ways this could cause an incident in six months:

1. **A caller builds a `Value` from a u64 id or amount cast to f64.** `to_jcs` serializes
   any finite double, so two ids above 2^53 can collide in a fingerprint. The parser
   cannot see this. The fingerprint and decision tasks must put big integers in strings
   or refuse them (open risk, below).
2. **Phase 1c oracle JCS built on the `rfc8785` package** would refuse `9007199254740992`
   and accept noncharacters, so Rust and the oracle-v1 would disagree. The vectors
   (`rfc8785-appendix-b-max-pos-int`, `str-nonchar-*`) make this fail loudly in the
   runner, not silently.
3. **A Rust upgrade changes core float formatting.** If `{:e}` changes shape, `shortest()`
   refuses (fail closed, `non_finite_number`) instead of emitting wrong digits; if the
   digit choice changes, the Appendix B tests and the 200,000-case ryu-js property fail
   in CI. Checked: the tie fix only moves an odd candidate to an even neighbour that
   parses back to the same double, so it is harmless if core starts doing ties-to-even.

Cross-platform: no paths, processes or locking in dos-core. Vector files are LF
(`.gitattributes` `*.json eol=lf`); inputs are JSON strings, so line endings inside
inputs are escapes and survive checkout. Tests pass on Linux and Windows (above).

### Fuzzing

FUZZ_SECTION

### Gates

GATE_SECTION

## Environment notes

- The WSL VM stopped mid-task: drive D:, which holds `D:\wsl\Ubuntu\ext4.vhdx`, had 2.7 MB
  free (`Get-PSDrive D`), and `wsl.exe` failed with `Wsl/Service/CreateInstance/E_FAIL`.
  I did not delete anything on D:. It later came back with about 900 MB free.
- WSL cargo reads a global `[patch.crates-io] creusot-std` from `/root/.cargo/config.toml`
  and writes a `[[patch.unused]]` entry into lock files. I removed it from `Cargo.lock`
  and `fuzz/Cargo.lock`; later WSL runs used `CARGO_HOME=/root/cargo-canon` (registry
  symlinked, no config).
- WSL git cannot follow this worktree's `gitdir: C:/...` file, so the WSL gate run used
  `GIT_DIR`/`GIT_WORK_TREE` env vars and `core.filemode=false` (nothing in `.git` was edited).

## Not done

- Kani (optional for this task).
- The conformance runner and adapters are other tasks. The Rust adapter must accept
  `input.bytes_hex` for area `jcs` (spec/canon.md); 6 vectors use it.
- No `ESCALATION.md`: the oracle diverges from the spec on 48 vectors, all deliberate
  DM-2 divergences recorded as `oracle_expected`. Decisions 1 and 2 above still deserve
  Ali's confirmation, since they refuse inputs the oracle accepts.

## Open risks

- Fractional forms of large numbers round (`9007199254740993.0` becomes `...992`), as
  RFC 8785 requires. Exact-decimal receivers can read a different value.
- Programmatic `Value`s accept any finite double (risk 1 above).
- Dropping a programmatically built `Value` nested deeper than the stack allows overflows
  in `Drop`; `parse_strict` never builds one deeper than 128.
- `Number` derives `PartialEq` on f64, so `-0 == 0`; JCS output is equal for both, as
  intended, but callers must not use `Value` equality as a security check.
