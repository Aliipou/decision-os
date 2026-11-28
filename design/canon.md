# Design: canon (RFC 8785 JCS in dos-core)

## Goal

One canonical byte form for every signed or hashed object (ground rule 5; closes the
canonical-form half of DM-2 and DM-3, and gives SG-9 and SG-14 their one definition).
`dos-core::canon` parses untrusted JSON strictly (I-JSON, RFC 7493) and serializes it per
RFC 8785. It never panics, never recurses past a fixed depth, and refuses every input
that two honest parsers could read differently.

Done means: the API below, every RFC 8785 example passing, property tests, a
differential run against an independent implementation, conformance vectors in
`conformance/vectors/jcs/`, a fuzz target run for at least 10 minutes, `spec/canon.md`.

Out of scope: fingerprint, sign, verdict (other tasks build on this API), the conformance
runner and adapters, the oracle change of Phase 1c.

## API

```rust
pub const MAX_DEPTH: usize = 128;
pub struct Number(/* finite f64 */);            // Number::new(f64) -> Result<Number, CanonError>, .get()
pub enum Value { Null, Bool(bool), Number(Number), String(String),
                 Array(Vec<Value>), Object(Vec<(String, Value)>) }
pub enum CanonError { .. }                      // .code() -> &'static str
pub fn parse_strict(bytes: &[u8]) -> Result<Value, CanonError>;
pub fn to_jcs(value: &Value) -> Result<Vec<u8>, CanonError>;
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, CanonError>;
```

## Two approaches

**A. Depend on `ryu-js` for number formatting** (the task's suggestion). ryu-js 1.0.4
is no_std and ECMAScript-exact, but 43 lines of its `src/` use `unsafe`, 19 of them
`unsafe {` blocks (raw pointer writes; see status). RUST_REWRITE.md lists "a dependency that
needs `unsafe` in dos-core" as a stop condition.

**B. Format numbers from core's shortest round-trip digits.** `core::fmt` `{:e}` with no
precision prints the shortest digit string that round-trips to the same f64, choosing
the closest such string (the same digit choice as ECMAScript 7.1.12.1 with Note 2, Ryu,
and Python `repr`). A small safe function places the decimal point and exponent per
ECMAScript Number::toString. Parsing uses core's correctly rounded `f64::from_str`.
dos-core keeps zero runtime dependencies.

**Choice: B.** No new unsafe code enters the TCB. ryu-js becomes a dev-dependency used only
as a test oracle (proptest over random f64 bit patterns), so the digit-choice claim is
checked, not trusted.

## Decisions on input (details and citations in spec/canon.md)

- UTF-8 only, no BOM, validated up front (RFC 7493 2.1, RFC 8785 3.2.4).
- Duplicate member names after unescaping are refused (RFC 8785 3.1, RFC 7493 2.3).
- Lone surrogates, escaped or not, are refused (RFC 8785 3.2.2.2 note). Noncharacters
  are refused (RFC 7493 2.1 "MUST NOT"; RFC 8785 3.1 requires I-JSON).
- Numbers: parsed to the nearest double, as RFC 8785 3.2.2 itself does
  (333333333.33333329 becomes 333333333.3333333). Overflow to infinity is refused.
  Integer literals (no fraction, no exponent) must survive canonicalization as text:
  inside [-(2^53)+1, 2^53-1] they always do; outside, a literal is accepted only if it is
  exactly the JCS text of its nearest double, else `unsafe_integer` (RFC 7493 2.2).
  Receivers parse integer literals as exact integers, so silent rounding would be a parser
  differential (a signed 9007199254740992 executed as ...993). A plain range check is not
  enough: RFC 8785 Appendix B prints 2^53 as `9007199254740992` and 2^68 as
  `295147905179352830000`, so a range check would refuse JCS's own output and break
  idempotence. The Trail of Bits `rfc8785` reference refuses every integer outside the
  range (`IntegerDomainError`), including those two; that difference is expected and
  documented in the differential.
- Nesting deeper than 128 containers is refused before recursing.
- `to_jcs` re-checks what it cannot assume of programmatic values: duplicate keys,
  noncharacters, depth.

## Failure modes, each refuses

| Input | Code |
|---|---|
| bytes start with EF BB BF | `leading_bom` |
| invalid UTF-8 anywhere (overlong, CESU surrogate bytes, truncated) | `invalid_utf8` |
| empty input, bad token, unescaped control char in string, leading zero, `+1`, `1.`, `.5` | `syntax` |
| a second value or garbage after the top value | `trailing_data` |
| `\x`, `\u12G`, `\U0041` | `invalid_escape` |
| `\ud800` alone, `\udc00` first, high followed by non-low | `lone_surrogate` |
| U+FDD0..U+FDEF or U+xFFFE/U+xFFFF, raw or escaped | `noncharacter` |
| same member name twice (also `"a"` and `"a"`) | `duplicate_key` |
| 129 nested containers | `depth_exceeded` |
| `NaN`, `Infinity`, `-Infinity`, `1e400` | `non_finite_number` |
| integer literal above 2^53-1 in magnitude that is not JCS text (`9007199254740993`) | `unsafe_integer` |

Error precedence: `leading_bom`, then `invalid_utf8` (whole input), then the first error
in a left-to-right scan; `duplicate_key` is reported when its object closes.

## Test plan

1. `crates/dos-core/tests/canon.rs`: RFC 8785 3.2.2 example (parse, serialize, exact bytes
   of 3.2.4), 3.2.3 sort example, all Appendix B rows (from the hex bit patterns), each
   failure mode above, 128 vs 129 depth, surrogate pairs vs lone, -0, 1e20/1e21 and
   1e-6/1e-7 boundaries, 5e-324, UTF-16 vs UTF-8 order, `\u001f` vs `\u007f`, integer
   range boundaries, Number::new on NaN and infinities, to_jcs on programmatic duplicates
   and depth.
2. Property tests (proptest): idempotence `to_jcs(parse(to_jcs(v))) == to_jcs(v)`;
   `parse_strict` never panics on arbitrary bytes and on mutated valid JSON; number
   formatting equals ryu-js for random f64 bit patterns; parse of the output gives back
   the same f64 bits (except -0).
3. `crates/dos-core/tests/canon_vectors.rs`: runs every `conformance/vectors/jcs/*.json`.
4. Differential: `crates/dos-core/tests/jcs/differential.py` drives
   `examples/jcs_lines.rs` against `rfc8785` 0.1.4 on at least 100k random values plus
   edge numbers and raw f64 bit patterns.
5. Fuzz: `fuzz/fuzz_targets/canon.rs`, at least 10 minutes; checks no panic and, on
   success, idempotence and that the output re-parses.
