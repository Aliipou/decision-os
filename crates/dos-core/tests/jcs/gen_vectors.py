"""Writes conformance/vectors/jcs/<name>.json (format: spec/CONFORMANCE.md, inputs:
spec/canon.md). Run from the repository root in a venv with rfc8785==0.1.4:

    python -I crates/dos-core/tests/jcs/gen_vectors.py [--check]

`expected` is written by hand below (RFC text or the spec/canon.md rule), never computed
from dos_core. The script cross-checks every `ok` against the independent rfc8785
package (listed exceptions only) and computes `oracle_expected` by running what the
decision-os-min oracle runs: json.dumps(json.loads(x), sort_keys=True,
separators=(",", ":")) (kernel.py:69,143). It refuses to overwrite an existing vector
with different content (vectors are append-only); --check only verifies.
"""

import json
import os
import sys

import rfc8785

OUT = os.path.join("conformance", "vectors", "jcs")
RFC = "RFC 8785"

RFC_SAMPLE_IN = """{
  "numbers": [333333333.33333329, 1E30, 4.50,
              2e-3, 0.000000000000000000000000001],
  "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\"\\/",
  "literals": [null, true, false]
}"""
RFC_SAMPLE_OUT = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'

RFC_SORT_IN = """{
  "\\u20ac": "Euro Sign",
  "\\r": "Carriage Return",
  "\\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\\ud83d\\ude00": "Emoji: Grinning Face",
  "\\u0080": "Control",
  "\\u00f6": "Latin Small Letter O With Diaeresis"
}"""
RFC_SORT_OUT = ('{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
                '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
                '"\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}')

# (name, input, expected, source). input: str (text) or bytes (bytes_hex).
# expected: ("ok", text) or ("error", code).
CASES = [
    ("rfc8785-3.2.2-sample", RFC_SAMPLE_IN, ("ok", RFC_SAMPLE_OUT), f"{RFC} 3.2.2 input, 3.2.3 output"),
    ("rfc8785-3.2.3-sort-example", RFC_SORT_IN, ("ok", RFC_SORT_OUT), f"{RFC} 3.2.3 sorting test data"),
    ("rfc8785-3.2.3-sort-plain", '{"ab":0,"aa":0,"a":0,"":0}', ("ok", '{"":0,"a":0,"aa":0,"ab":0}'), f"{RFC} 3.2.3 plain English example"),
]

APPENDIX_B = [
    ("zero", "0", "0"), ("minus-zero", "-0.0", "0"), ("min-pos", "5e-324", "5e-324"),
    ("min-neg", "-5e-324", "-5e-324"), ("max-pos", "1.7976931348623157e+308", "1.7976931348623157e+308"),
    ("max-neg", "-1.7976931348623157e+308", "-1.7976931348623157e+308"),
    ("max-pos-int", "9007199254740992", "9007199254740992"),
    ("max-neg-int", "-9007199254740992", "-9007199254740992"),
    ("2pow68", "295147905179352830000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001", "0.000001"),
    ("41b3de4355555553", "333333333.3333332", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333", "-0.0000033333333333333333"),
    ("round-to-even", "1424953923781206.25", "1424953923781206.2"),
]
for tag, text, out in APPENDIX_B:
    CASES.append((f"rfc8785-appendix-b-{tag}", text, ("ok", out), f"{RFC} Appendix B, row {tag}"))
CASES += [
    ("rfc8785-appendix-b-nan", "NaN", ("error", "non_finite_number"), f"{RFC} Appendix B note 3, 3.2.2.3"),
    ("rfc8785-appendix-b-infinity", "Infinity", ("error", "non_finite_number"), f"{RFC} Appendix B note 3, 3.2.2.3"),
]

S = "spec/canon.md"
CASES += [
    # numbers
    ("num-minus-zero", "-0", ("ok", "0"), "ECMA-262 7.1.12.1 step 2"),
    ("num-1e20", "1e20", ("ok", "100000000000000000000"), "ECMA-262 7.1.12.1, n <= 21"),
    ("num-1e21", "1e21", ("ok", "1e+21"), "ECMA-262 7.1.12.1, n > 21"),
    ("num-1e-6", "1e-6", ("ok", "0.000001"), "ECMA-262 7.1.12.1, -6 < n <= 0"),
    ("num-1e-7", "1e-7", ("ok", "1e-7"), "ECMA-262 7.1.12.1, n <= -6"),
    ("num-1.0", "1.0", ("ok", "1"), "ECMA-262 7.1.12.1"),
    ("num-exponent-plus", "1E+2", ("ok", "100"), "RFC 8259 6 grammar, ECMA-262 7.1.12.1"),
    ("num-4e-324-rounds", "4e-324", ("ok", "5e-324"), f"{S} numbers: nearest double"),
    ("num-underflow", "1e-400", ("ok", "0"), f"{S} numbers: nearest double (underflow)"),
    ("num-exact-decimal-of-0.1", "0.1000000000000000055511151231257827021181583404541015625", ("ok", "0.1"), f"{S} numbers"),
    ("num-overflow", "1e400", ("error", "non_finite_number"), f"{RFC} 3.2.2.3 note; RFC 7493 2.2"),
    ("num-overflow-negative", "-1e400", ("error", "non_finite_number"), f"{RFC} 3.2.2.3 note"),
    ("num-negative-infinity", "-Infinity", ("error", "non_finite_number"), f"{RFC} 3.2.2.3 note"),
    ("num-nan-in-array", "[1,NaN]", ("error", "non_finite_number"), f"{RFC} 3.2.2.3 note"),
    ("num-int-max-safe", "9007199254740991", ("ok", "9007199254740991"), "RFC 7493 2.2"),
    ("num-int-min-safe", "-9007199254740991", ("ok", "-9007199254740991"), "RFC 7493 2.2"),
    ("num-int-2pow53-plus-1", "9007199254740993", ("error", "unsafe_integer"), f"{S} unsafe_integer; RFC 7493 2.2"),
    ("num-int-in-object", '{"amount":9007199254740993}', ("error", "unsafe_integer"), f"{S} unsafe_integer"),
    ("num-int64-max", "9223372036854775807", ("error", "unsafe_integer"), f"{S} unsafe_integer; {RFC} Appendix D"),
    ("num-int-2pow68-exact", "295147905179352825856", ("error", "unsafe_integer"), f"{S} unsafe_integer"),
    ("num-float-form-rounds", "9007199254740993.0", ("ok", "9007199254740992"), f"{S} numbers: fraction form is a double"),
    ("num-leading-zero", "01", ("error", "syntax"), "RFC 8259 6"),
    ("num-plus-sign", "+1", ("error", "syntax"), "RFC 8259 6"),
    ("num-trailing-dot", "1.", ("error", "syntax"), "RFC 8259 6"),
    ("num-leading-dot", ".5", ("error", "syntax"), "RFC 8259 6"),
    ("num-hex", "0x10", ("error", "syntax"), "RFC 8259 6"),
    ("num-lowercase-nan", "nan", ("error", "syntax"), "RFC 8259 3"),
    # strings
    ("str-escape-001f", '"\\u001f"', ("ok", '"\\u001f"'), f"{RFC} 3.2.2.2"),
    ("str-del-007f", '"\\u007f"', ("ok", '"\u007f"'), f"{RFC} 3.2.2.2: outside U+0000..U+001F, as is"),
    ("str-nul", '"\\u0000"', ("ok", '"\\u0000"'), f"{RFC} 3.2.2.2"),
    ("str-short-escapes", '"\\u0008\\u0009\\u000a\\u000c\\u000d"', ("ok", '"\\b\\t\\n\\f\\r"'), f"{RFC} 3.2.2.2"),
    ("str-vertical-tab-lowercase", '"\\u000B"', ("ok", '"\\u000b"'), f"{RFC} 3.2.2.2 lowercase hex"),
    ("str-solidus", '"\\/"', ("ok", '"/"'), f"{RFC} 3.2.2.2"),
    ("str-quote-backslash", '"\\"\\\\"', ("ok", '"\\"\\\\"'), f"{RFC} 3.2.2.2"),
    ("str-non-ascii-raw", '"\\u00e9\\u20AC"', ("ok", '"é€"'), f"{RFC} 3.2.2.2"),
    ("str-line-separators", '"\\u2028\\u2029"', ("ok", '"  "'), f"{RFC} 3.2.2.2"),
    ("str-surrogate-pair", '"\\ud83d\\ude00"', ("ok", '"\U0001f600"'), "RFC 8259 7"),
    ("str-bom-char-inside", '"﻿"', ("ok", '"﻿"'), "U+FEFF inside a string is an ordinary character"),
    ("str-lone-high", '"\\ud800"', ("error", "lone_surrogate"), f"{RFC} 3.2.2.2 note; RFC 7493 2.1"),
    ("str-lone-low", '"\\udead"', ("error", "lone_surrogate"), "RFC 7493 2.1 example"),
    ("str-high-then-ascii", '"\\ud83d\\u0041"', ("error", "lone_surrogate"), "RFC 7493 2.1"),
    ("str-reversed-pair", '"\\ude00\\ud83d"', ("error", "lone_surrogate"), "RFC 7493 2.1"),
    ("str-lone-surrogate-key", '{"\\udead":1}', ("error", "lone_surrogate"), "RFC 7493 2.1"),
    ("str-invalid-escape-x", '"\\x41"', ("error", "invalid_escape"), "RFC 8259 7"),
    ("str-invalid-escape-short-hex", '"\\u004"', ("error", "invalid_escape"), "RFC 8259 7"),
    ("str-unescaped-control", '"a\u0001b"', ("error", "syntax"), "RFC 8259 7"),
    ("str-nonchar-fdd0", '"\\ufdd0"', ("error", "noncharacter"), "RFC 7493 2.1; RFC 8785 3.1"),
    ("str-nonchar-ffff", '"\\uffff"', ("error", "noncharacter"), "RFC 7493 2.1"),
    ("str-nonchar-10ffff", '"\\udbff\\udfff"', ("error", "noncharacter"), "RFC 7493 2.1"),
    ("str-nonchar-raw-fdef", '"﷯"'.encode(), ("error", "noncharacter"), "RFC 7493 2.1: raw UTF-8 too"),
    ("str-fffd-is-fine", '"\\ufffd\\ufdcf\\ufdf0"', ("ok", '"�﷏ﷰ"'), "RFC 7493 2.1 boundaries"),
    # objects
    ("obj-utf16-order", '{"\\ufb33":3,"\\ud83d\\ude00":2,"\\u20ac":1}', ("ok", '{"€":1,"\U0001f600":2,"דּ":3}'), f"{RFC} 3.2.3 UTF-16 code units"),
    ("obj-utf16-order-ff61", '{"\\uff61":1,"\\ud800\\udc00":2}', ("ok", '{"\U00010000":2,"｡":1}'), f"{RFC} 3.2.3"),
    ("obj-case", '{"a":1,"A":2}', ("ok", '{"A":2,"a":1}'), f"{RFC} 3.2.3"),
    ("obj-nested-sort", '{"b":{"d":1,"c":2},"a":[{"z":0,"y":1}]}', ("ok", '{"a":[{"y":1,"z":0}],"b":{"c":2,"d":1}}'), f"{RFC} 3.2.3 recursive"),
    ("obj-duplicate-key", '{"a":1,"a":2}', ("error", "duplicate_key"), "RFC 7493 2.3; RFC 8785 3.1; sluicegate WA-1"),
    ("obj-duplicate-key-escaped", '{"a":1,"\\u0061":2}', ("error", "duplicate_key"), "RFC 7493 2.3: after unescaping"),
    ("obj-duplicate-key-nested", '{"x":[{"k":1,"k":1}]}', ("error", "duplicate_key"), "RFC 7493 2.3"),
    ("obj-duplicate-pair-vs-raw", '{"\\ud83d\\ude00":1,"\U0001f600":2}', ("error", "duplicate_key"), "RFC 7493 2.3"),
    ("obj-trailing-comma", '{"a":1,}', ("error", "syntax"), "RFC 8259 4"),
    ("obj-single-quotes", "{'a':1}", ("error", "syntax"), "RFC 8259 4"),
    ("obj-literals-and-empties", '[ null , true , false , "" , [ ] , { } ]', ("ok", '[null,true,false,"",[],{}]'), f"{RFC} 3.2.1"),
    # structure
    ("depth-128-arrays", "[" * 128 + "]" * 128, ("ok", "[" * 128 + "]" * 128), f"{S} MAX_DEPTH = 128"),
    ("depth-129-arrays", "[" * 129 + "]" * 129, ("error", "depth_exceeded"), f"{S} MAX_DEPTH = 128"),
    ("depth-129-objects", '{"a":' * 129 + "0" + "}" * 129, ("error", "depth_exceeded"), f"{S} MAX_DEPTH = 128"),
    ("whitespace-only-allowed-kinds", " \t\r\n1 \t\r\n", ("ok", "1"), "RFC 8259 2"),
    ("empty-input", "", ("error", "syntax"), "RFC 8259 2"),
    ("trailing-value", "1 2", ("error", "trailing_data"), "RFC 8259 2"),
    ("trailing-object", "{}{}", ("error", "trailing_data"), "RFC 8259 2"),
    ("comment", "/*c*/1", ("error", "syntax"), "RFC 8259 2"),
    ("bom-text", "﻿{}", ("error", "leading_bom"), "RFC 8259 8.1; RFC 7493 2.1"),
    # raw bytes
    ("utf8-bom-bytes", b"\xef\xbb\xbf{}", ("error", "leading_bom"), "RFC 8259 8.1"),
    ("utf8-invalid-ff", b'"\xff"', ("error", "invalid_utf8"), "RFC 7493 2.1; RFC 3629"),
    ("utf8-overlong-slash", b'"\xc0\xaf"', ("error", "invalid_utf8"), "RFC 3629 3: overlong"),
    ("utf8-encoded-surrogate", b'"\xed\xa0\x80"', ("error", "invalid_utf8"), "RFC 3629 3: surrogates are not UTF-8"),
    ("utf8-truncated", b'"\xe2\x82"', ("error", "invalid_utf8"), "RFC 3629"),
    ("utf8-above-10ffff", b'"\xf4\x90\x80\x80"', ("error", "invalid_utf8"), "RFC 3629"),
]

# Where the independent rfc8785 package is known to differ, with the reason.
REFERENCE_EXCEPTIONS = {
    "rfc8785-appendix-b-max-pos-int": "rfc8785 refuses all ints beyond 2^53-1 (IntegerDomainError); see spec/canon.md",
    "rfc8785-appendix-b-max-neg-int": "same",
    "rfc8785-appendix-b-2pow68": "same",
    "rfc8785-appendix-b-444b1ae4d6e2ef4e": "same",
    "rfc8785-appendix-b-444b1ae4d6e2ef4f": "same",
}


def oracle(raw):
    try:
        return ("ok", json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")))
    except Exception:  # noqa: BLE001 - any oracle exception is a refusal
        return ("refused", None)


def reference(raw):
    try:
        return ("ok", rfc8785.dumps(json.loads(raw)).decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return ("error", type(e).__name__)


def build(name, raw, expected, source):
    case = {"v": 1, "area": "jcs", "name": name}
    case["input"] = {"bytes_hex": raw.hex()} if isinstance(raw, bytes) else {"text": raw}
    case["expected"] = {expected[0]: expected[1]}
    o = oracle(raw)
    if o[0] == "ok" and (expected[0] == "error" or o[1] != expected[1]):
        case["oracle_expected"] = {"ok": o[1]}
        case["gap"] = "DM-2"
    elif o[0] == "refused" and expected[0] == "ok":
        raise SystemExit(f"{name}: oracle refuses an input the spec accepts; needs an oracle error code")
    case["source"] = source
    return case


def main():
    check = "--check" in sys.argv
    names = [c[0] for c in CASES]
    if len(set(names)) != len(names):
        raise SystemExit("duplicate vector names")
    problems = []
    for name, raw, expected, _ in CASES:
        if expected[0] == "ok" and name not in REFERENCE_EXCEPTIONS:
            ref = reference(raw)
            if ref != expected:
                problems.append(f"{name}: rfc8785 gives {ref}, vector says {expected}")
    os.makedirs(OUT, exist_ok=True)
    gaps = 0
    for c in CASES:
        case = build(*c)
        gaps += "gap" in case
        text = json.dumps(case, indent=2, ensure_ascii=True) + "\n"
        path = os.path.join(OUT, case["name"] + ".json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                if f.read() != text:
                    problems.append(f"{path}: exists with different content (append-only)")
            continue
        if check:
            problems.append(f"{path}: missing")
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    print(f"vectors={len(CASES)} with_gap_DM-2={gaps} reference_exceptions={len(REFERENCE_EXCEPTIONS)}")
    for p in problems:
        print("PROBLEM", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
