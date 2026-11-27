# Canonical form (v1): JCS over strict I-JSON

Every byte string Decision OS signs or hashes is the RFC 8785 (JCS) serialization of a
value that satisfies I-JSON (RFC 7493). Implementation: `dos-core::canon`. Vectors:
`conformance/vectors/jcs/`. Closes the canonical-form part of DM-2 and DM-3; it is the
one definition SG-9 and SG-14 refer to.

## Operation

`canonicalize(bytes) = to_jcs(parse_strict(bytes))`. Both steps refuse rather than
guess. A refusal is one of the codes below. No input may cause a panic, unbounded
recursion or super-linear work in the input length.

## Parsing (`parse_strict`)

The input is a JSON text (RFC 8259) with these extra rules. Each rule cites the RFC it
comes from. RFC 8785 3.1 requires I-JSON input, and RFC 8785 section 5 says a signature
scheme MUST parse and verify I-JSON before acting.

| Rule | Basis | Code |
|---|---|---|
| The input does not start with EF BB BF. | RFC 8259 8.1 (MUST NOT add a BOM) | `leading_bom` |
| The whole input is valid UTF-8: no overlong forms, no encoded surrogates (ED A0..BF xx), nothing above U+10FFFF. | RFC 7493 2.1, RFC 3629 | `invalid_utf8` |
| Whitespace is only space, tab, LF, CR. No comments. A number token ends at a byte that cannot continue it, so `01`, `1x` and `0x10` are one bad token. | RFC 8259 2, 6 | `syntax` |
| Only whitespace follows the top-level value. | RFC 8259 2 | `trailing_data` |
| Escapes are exactly `\" \\ \/ \b \f \n \r \t \uXXXX` (hex in either case). | RFC 8259 7 | `invalid_escape` |
| `\uD800`..`\uDBFF` must be followed by `\uDC00`..`\uDFFF`; a low surrogate never stands alone. | RFC 8785 3.2.2.2 note, RFC 7493 2.1 | `lone_surrogate` |
| No noncharacter (U+FDD0..U+FDEF, U+xFFFE, U+xFFFF for every plane), raw or escaped, in names or values. | RFC 7493 2.1 (MUST NOT) | `noncharacter` |
| No object has two members with the same name after unescaping (`"a"` and `"a"` are the same). | RFC 7493 2.3, RFC 8785 3.1 | `duplicate_key` |
| At most 128 nested arrays and objects (`MAX_DEPTH`). The 129th opening bracket is refused before it is read further. | RFC 8785 section 5 (sanity checks) | `depth_exceeded` |
| `NaN`, `Infinity`, `-Infinity`, and any number that rounds to an infinity (`1e400`). | RFC 8785 3.2.2.3 note | `non_finite_number` |
| An integer literal (no fraction, no exponent) must come out of canonicalization as the same text, see below. | RFC 7493 2.2 | `unsafe_integer` |

Unescaped control characters (U+0000..U+001F) inside a string are `syntax`.

Error precedence: `leading_bom`, then `invalid_utf8` (checked over the whole input
first), then the first error met in a left-to-right scan. `duplicate_key` is detected when
the object's closing brace is read, so any other error inside that object wins.

Objects keep their members in input order in the parsed value; only serialization sorts.

### Numbers

A number token is converted to the nearest IEEE 754 double, ties to even (correct
rounding). This is what RFC 8785 itself does: its 3.2.2 sample turns
`333333333.33333329` into `333333333.3333333` and `0.000000000000000000000000001` into
`1e-27`. So fractions and exponents may lose precision, as the RFC intends, and an
underflow becomes `0` (`1e-400` is `0`).

Integer literals are different. Receivers commonly parse a token without `.` or `e` as an
exact integer (int64, bignum), so silently rounding one is a parser differential: a kernel
signs `9007199254740992` while the tool executes `9007199254740993`. RFC 7493 2.2: a
sender "cannot expect a receiver to treat an integer whose absolute value is greater than
9007199254740991 ... as an exact value".

The rule: an integer literal is accepted only if its JCS serialization is the same text
(`-0` excepted, which becomes `0`). Inside [-(2^53)+1, 2^53-1] every integer literal is
its own JCS text, so this is the I-JSON range. Outside it, a literal is accepted only
when it is exactly how JCS prints its double: `9007199254740992` and
`295147905179352830000` (RFC 8785 Appendix B rows) are accepted; `9007199254740993`,
`9223372036854775807` and `295147905179352825856` (the exact value of 2^68) are
`unsafe_integer`. A plain range check would refuse JCS's own output for doubles at or
above 2^53, so canonical bytes would not re-parse.

Applications that need exact big numbers put them in strings (RFC 8785 Appendix D).

Known residual: a fraction or exponent form such as `9007199254740993.0` is accepted and
rounded to `9007199254740992`, per RFC 8785 3.2.2. A receiver that parses decimals exactly
reads a different value than the one canonicalized. Policies that compare amounts must
use integer literals or strings, never fractional forms of large numbers.

## Serialization (`to_jcs`)

RFC 8785 section 3.2, exactly:

- no whitespace (3.2.1);
- `null`, `true`, `false` (3.2.2.1);
- strings (3.2.2.2): `\b \t \n \f \r` for U+0008, U+0009, U+000A, U+000C, U+000D; other
  U+0000..U+001F as `\u00xx` with lowercase hex; `\"` and `\\`; everything else, including
  U+007F, U+2028, U+2029 and `/`, as is;
- numbers (3.2.2.3): ECMA-262 Number::prototype.toString (7.1.12.1) including Note 2.
  The shortest digits that round-trip; among those, the closest to the exact value; on an
  exact tie, the even one. -0 is `0`. Decimal notation when the exponent n satisfies
  -6 < n <= 21, otherwise `d.ddde+x` / `de-x`;
- object members sorted by their names as arrays of UTF-16 code units, unsigned, shorter
  first on a common prefix (3.2.3); arrays keep their order;
- UTF-8 output (3.2.4).

`to_jcs` also takes values built by code, so it re-checks what the type does not
guarantee: duplicate names (`duplicate_key`), noncharacters (`noncharacter`) and depth
(`depth_exceeded`). Strings are Rust `String`, so they cannot hold a lone surrogate.
`Number` cannot hold NaN or an infinity (`Number::new` returns `non_finite_number`).
A double built by code is serialized whatever its magnitude; the integer-literal rule
applies to parsing only.

## Not required

- RFC 7493 4.1 recommends an object or array at top level (SHOULD). Any value is accepted.
- Unicode normalization is never applied (RFC 8785 3.1 note): strings are kept as is.

## Error codes

`leading_bom`, `invalid_utf8`, `syntax`, `trailing_data`, `invalid_escape`,
`lone_surrogate`, `noncharacter`, `duplicate_key`, `depth_exceeded`, `non_finite_number`,
`unsafe_integer`. Codes are stable; adding one is a spec change.

## Conformance vectors (area `jcs`)

Format: `spec/CONFORMANCE.md`. Input is one of:

- `{"text": "<json text>"}`: the input bytes are the UTF-8 encoding of the string;
- `{"bytes_hex": "<hex>"}`: the input bytes, for inputs that are not valid UTF-8 or that
  contain a noncharacter (a noncharacter cannot appear in a vector file, which is itself
  read as I-JSON).

Expected is `{"ok": "<canonical text>"}`, compared as bytes of its UTF-8 encoding, or
`{"error": "<code>"}`.

`oracle_expected` with `"gap": "DM-2"` records what decision-os-min computes on the same
input, `json.dumps(json.loads(x), sort_keys=True, separators=(",", ":"))`
(kernel.py:69,143): ASCII escaping, Python float repr, code point sort order, `NaN`,
last-wins duplicates, unbounded integers. Vectors where the oracle refuses too (it raises)
carry no `oracle_expected`; mapping its exceptions to codes is the oracle adapter's job.

## Independent reference

The Trail of Bits `rfc8785` package (0.1.4) agrees with this spec on every input except:
it refuses every integer outside the I-JSON range (including JCS output such as
`9007199254740992`), and it accepts noncharacters. Both differences are deliberate here,
for the reasons above.
