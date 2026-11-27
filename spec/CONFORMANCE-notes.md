# Conformance: precise wording (v1)

`spec/CONFORMANCE.md` is the contract. This file fixes points it leaves open, as the
runner (`crates/dos-conformance`) implements them. Where the two disagree, CONFORMANCE.md
wins and this file is the bug.

## Vector files

1. Required fields: `v`, `area`, `name`, `input`, `expected`, `source`. Optional:
   `oracle_expected`, `gap`. Any other field is an error.
2. `v` is the number 1. `area`, `name`, `source` and `gap` are non-empty strings.
3. `name` and `area` match `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 128 bytes. Two names in
   one area, or two areas, that differ only by ASCII case are an error (they collide on
   Windows and macOS checkouts).
4. `input` is an object. `expected` and `oracle_expected` are exactly `{"ok": <any>}` or
   `{"error": "<non-empty string>"}`; `unsupported` is never expected.
5. The file is UTF-8 without BOM, contains no CR, and is one JSON value. Duplicate object
   keys at any depth are an error, as are nesting deeper than 128 and exponents with
   magnitude 10^15 or more.
6. An area directory holds only regular `<name>.json` files; the vectors directory holds
   only area directories. Anything else (README, `.bak`, symlink, subdirectory) is an
   error, so no file is silently skipped.
7. Every vector error is reported (all of them, not the first) and nothing runs: exit 2.

## Requests

A request is `{"area","name","input"}` on one line. The runner re-serialises `input`:
member order and number lexemes are kept as in the file; whitespace is not, and string
escapes are normalised (`"A"` is sent as `"A"`; control characters, U+007F,
U+2028, U+2029 and lone surrogates are sent `\u`-escaped). An area whose behaviour
depends on raw text (for example a canonicaliser's input bytes) must carry that text
in a string field.

Requests are sent in area order, then name order (byte order), all of them, then stdin
is closed. Adapters may answer before or after reading everything.

## Comparison

- Objects: equal iff same key set and equal values per key; member order ignored.
- Arrays: same length, equal element by element, order matters.
- Strings: equal iff the same sequence of code points after decoding escapes. A
  surrogate pair is one code point; a lone surrogate is its own code point. No Unicode
  normalisation.
- Numbers: equal iff the exact decimal values are equal. `1`, `1.0`, `1e0` and `10E-1`
  are equal; `9007199254740993` and `9007199254740992` are not; `0.1` and
  `0.10000000000000001` are not; every zero (`0`, `-0`, `0.0e5`) is the same value. No
  conversion to binary floating point happens anywhere. An area whose spec cares about
  the textual form of a number (JCS) must put the text in a string.
- `true`, `false`, `null` only equal themselves; `1` is not `true`, `"1"` is not `1`.

## Responses

A response line ends in LF (a CR before it is tolerated), is at most 16 MiB, parses
under the rules of point 5 above, and is exactly `{"name","output"}` with `name` equal
to the request's. `output` is exactly one of `{"ok": v}`, `{"error": "<non-empty>"}`,
`{"unsupported": true}`. Anything else is MALFORMED for that case.

## Verdict per run

Exit 0 only if all hold: at least one case ran; every selected area has at least one
vector; every case is `ok`, or `unsupported` in a non-required area; no line follows
the last response; the adapter exited with status 0 (not by a signal) without being
killed. Exit 1 otherwise. Usage, manifest and vector-format errors exit 2.

Timeouts: each response must arrive within the per-case timeout (default 10 s) of the
previous one (the first one includes adapter start-up); the whole run within the
overall timeout (default 300 s); after the last response the adapter must close stdout
and exit within the per-case timeout. On a timeout the adapter is killed and the
remaining cases are MISSING.

Required areas: `--require <a>` makes `a` selected; it must exist and every case in it
must be supported. Every area in a manifest's `required` list must exist too (a typo
must not weaken the requirement silently: exit 2); it is enforced for the areas that
are selected in the run. Add an area to a manifest's `required` in the same change that
lands its first vectors.

## Area `selftest`

Proves the pipe and the comparator, not any implementation. Every adapter must support
it (both manifests require it).

- `{"op": "echo", "value": v}` gives `{"ok": v}`.
- `{"op": "error", "code": c}` with `c` a non-empty string gives `{"error": c}`.
- Another string `op` gives `{"error": "unknown_op"}`.
- Any other shape (missing or extra field, non-string `op`) gives
  `{"error": "invalid_input"}`.

## Adapter-defined codes (oracle adapter)

The `meet` area spec does not define refusals yet. Until it does, the
`oracle-decision-os-min` adapter answers `{"error": "invalid_input"}` for wrong input
fields (including a non-array `verdicts`), `{"error": "unknown_op"}` for an unknown op,
and `{"error": "oracle_exception"}` if the oracle raises. Values of `a`, `b`, `s` and the
elements of `verdicts` are passed to the oracle as they are, of any JSON type, so its
fail-closed normalisation is what is measured.
