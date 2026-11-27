"""Differential test: dos_core::canon (examples/jcs_lines.rs) against the independent
Trail of Bits `rfc8785` package (pure Python).

Usage (from the repository root, in a venv with rfc8785==0.1.4):
    python -I crates/dos-core/tests/jcs/differential.py --driver <jcs_lines binary> \
        [--values 200000] [--floats 1000000] [--seed 8785]

Reference = rfc8785.dumps(json.loads(text)). json.loads keeps integer literals as int
and everything else as float, so the reference applies the same lexical split as
dos_core. Exit 1 on any unexplained disagreement.

Explained (expected) disagreements, each with its RFC basis (see spec/canon.md):
  big_int_canonical  integer literal beyond 2^53-1 that is exactly JCS text of its double
                     (e.g. 9007199254740992). rfc8785 raises IntegerDomainError for every
                     int outside the I-JSON range; RFC 8785 Appendix B lists these as JCS
                     output, so refusing them would refuse JCS's own output.
  noncharacter       dos_core refuses noncharacters (RFC 7493 2.1 MUST NOT, required by
                     RFC 8785 3.1); rfc8785 does not check them.
"""

import argparse
import json
import math
import random
import struct
import subprocess
import sys
from decimal import Decimal
from fractions import Fraction

import rfc8785

SAFE = 2**53 - 1


def is_nonchar(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def rand_char(r):
    pick = r.random()
    if pick < 0.35:
        cp = r.randrange(0x20, 0x7F)
    elif pick < 0.45:
        cp = r.randrange(0x00, 0x20)
    elif pick < 0.5:
        cp = r.choice([0x22, 0x5C, 0x2F, 0x7F, 0x2028, 0x2029, 0xFEFF, 0xFFFD])
    elif pick < 0.75:
        cp = r.randrange(0x80, 0x10000)
    else:
        cp = r.randrange(0x10000, 0x110000)
    if 0xD800 <= cp <= 0xDFFF:
        cp = 0x41
    if is_nonchar(cp) and r.random() < 0.9:
        cp = 0x42
    return chr(cp)


def rand_str(r, n=None):
    if n is None:
        n = r.choice([0, 1, 2, 3, 5, 8, 20])
    return "".join(rand_char(r) for _ in range(n))


EDGE_FLOATS = [
    5e-324, -5e-324, 1.7976931348623157e308, 2.2250738585072014e-308, 2.225073858507201e-308,
    1e21, 1e20, 999999999999999900000.0, 1e-6, 1e-7, 9.999999999999997e-7, 1e23, 9.999999999999997e22,
    0.1, 0.2, 0.30000000000000004, 1424953923781206.25, 333333333.33333329, 4.35, 2.5, 0.5, 1.5,
    2.0**53, 2.0**53 + 2, 2.0**68, 2.0**1023, -0.0, 0.0, 123e-20, 1e-5, 1e16, 1e15, 12345678901234567.0,
]


def rand_float(r):
    while True:
        f = _rand_float(r)
        if math.isfinite(f):
            return f


def _rand_float(r):
    pick = r.random()
    if pick < 0.3:
        while True:
            f = struct.unpack("<d", r.getrandbits(64).to_bytes(8, "little"))[0]
            if math.isfinite(f):
                return f
    if pick < 0.5:
        return r.randrange(1, 2**53) * 2.0 ** r.randrange(-8, 80) * r.choice([1, -1])
    if pick < 0.7:
        return round(r.uniform(-1e6, 1e6), r.randrange(0, 8))
    if pick < 0.85:
        return float(f"{r.randrange(1, 10**r.randrange(1, 18))}e{r.randrange(-330, 310)}")
    return r.choice(EDGE_FLOATS)


def rand_int(r):
    pick = r.random()
    if pick < 0.6:
        return r.randrange(-1000, 1000)
    if pick < 0.95:
        return r.randrange(-SAFE, SAFE + 1)
    return r.choice([SAFE, -SAFE, 0, 2**31, -(2**31), 2**32])


def rand_value(r, depth=0):
    pick = r.random()
    if depth < 5 and pick < 0.15:
        return [rand_value(r, depth + 1) for _ in range(r.randrange(0, 6))]
    if depth < 5 and pick < 0.3:
        return {rand_str(r, r.choice([0, 1, 1, 2, 3])): rand_value(r, depth + 1) for _ in range(r.randrange(0, 7))}
    pick = r.random()
    if pick < 0.05:
        return None
    if pick < 0.1:
        return r.random() < 0.5
    if pick < 0.35:
        return rand_int(r)
    if pick < 0.65:
        return rand_float(r)
    return rand_str(r)


def ws(r):
    return r.choice(["", "", "", " ", "\n", "\t", "\r\n  "])


def enc_str(r, s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp < 0x20 or r.random() < 0.15:
            if cp > 0xFFFF:
                v = cp - 0x10000
                hi, lo = 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF)
                fmt = "\\u%04X\\u%04x" if r.random() < 0.5 else "\\u%04x\\u%04X"
                out.append(fmt % (hi, lo))
            elif ch == "\n" and r.random() < 0.5:
                out.append("\\n")
            elif ch == "/" and r.random() < 0.5:
                out.append("\\/")
            else:
                out.append(("\\u%04x" if r.random() < 0.5 else "\\u%04X") % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def enc_float(r, f):
    text = repr(f)
    if text in ("inf", "-inf", "nan"):
        raise ValueError(text)
    pick = r.random()
    if pick < 0.1 and "e" not in text and "." in text:
        return text + "0" * r.randrange(1, 4)  # trailing zeros: same value
    if pick < 0.2:
        return "%.17e" % f  # 18 significant digits, may round differently from repr
    if pick < 0.25 and "e" in text:
        return text.upper()
    return text


def enc(r, v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return enc_float(r, v)
    if isinstance(v, str):
        return enc_str(r, v)
    if isinstance(v, list):
        return "[" + ws(r) + ("," + ws(r)).join(enc(r, x) + ws(r) for x in v) + "]"
    items = list(v.items())
    r.shuffle(items)
    return "{" + ws(r) + ("," + ws(r)).join(enc_str(r, k) + ws(r) + ":" + ws(r) + enc(r, x) + ws(r) for k, x in items) + "}"


def reference(text):
    try:
        return "ok", rfc8785.dumps(json.loads(text)).hex()
    except Exception as e:  # noqa: BLE001 - any refusal counts as a refusal
        return "err", type(e).__name__


def has_nonchar(text):
    try:
        v = json.loads(text)
    except Exception:  # noqa: BLE001
        return False

    def walk(x):
        if isinstance(x, str):
            return any(is_nonchar(ord(c)) for c in x)
        if isinstance(x, list):
            return any(walk(y) for y in x)
        if isinstance(x, dict):
            return any(walk(k) or walk(y) for k, y in x.items())
        return False

    return walk(v)


def is_tie(f):
    """True when f lies exactly halfway between two shortest-digit candidates."""
    if f == 0 or not math.isfinite(f):
        return False
    d = Decimal(repr(abs(f)))
    unit = Fraction(10) ** d.as_tuple().exponent
    exact = Fraction(abs(f))
    return exact in (Fraction(d) - unit / 2, Fraction(d) + unit / 2)


def run_driver(driver, texts):
    payload = "".join(t.encode("utf-8", "surrogatepass").hex() + "\n" for t in texts)
    proc = subprocess.run([driver], input=payload.encode(), capture_output=True, check=True)
    lines = proc.stdout.decode().splitlines()
    if len(lines) != len(texts):
        raise SystemExit(f"driver returned {len(lines)} lines for {len(texts)} inputs")
    return [tuple(line.split(" ", 1)) for line in lines]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--values", type=int, default=200_000)
    ap.add_argument("--floats", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=8785)
    a = ap.parse_args()
    r = random.Random(a.seed)

    texts, kinds = [], []
    for _ in range(a.values):
        texts.append(ws(r) + enc(r, rand_value(r)) + ws(r))
        kinds.append("value")
    floats = [rand_float(r) for _ in range(a.floats)] + EDGE_FLOATS
    for f in floats:
        texts.append(repr(f))
        kinds.append("float")
    # Deliberate edge inputs.
    extra = [str(2**53), str(-(2**53)), str(2**53 + 1), "295147905179352830000", str(2**64), "9223372036854775807",
             "1e400", "-1e400", "1e-400", "NaN", "Infinity", '"\\ud800"', '"\\udc00"', '"\\ufdd0"', '"\\uffff"',
             '{"a":1,"a":2}', "[" * 129 + "]" * 129, "[" * 128 + "]" * 128, "﻿1", '"\\u0000"']
    texts += extra
    kinds += ["extra"] * len(extra)

    ours = run_driver(a.driver, texts)
    agree = 0
    explained = {"big_int_canonical": 0, "noncharacter": 0, "duplicate_key_python_last_wins": 0,
                 "depth_python_accepts": 0}
    unexplained = []
    for text, kind, o in zip(texts, kinds, ours):
        ref = reference(text)
        same = (o[0] == "ok" and ref == ("ok", o[1])) or (o[0] == "err" and ref[0] == "err")
        if same:
            agree += 1
        elif o == ("err", "noncharacter") and ref[0] == "ok" and has_nonchar(text):
            explained["noncharacter"] += 1
        elif (ref == ("err", "IntegerDomainError") and o[0] == "ok"
              and json.loads(bytes.fromhex(o[1])) == json.loads(text)):
            # Exact-int equality in Python: our output kept every big integer literal.
            explained["big_int_canonical"] += 1
        elif o == ("err", "duplicate_key") and ref[0] == "ok":
            explained["duplicate_key_python_last_wins"] += 1
        elif o == ("err", "depth_exceeded") and ref[0] == "ok":
            explained["depth_python_accepts"] += 1
        else:
            unexplained.append((kind, text, o, ref))

    ties = sum(1 for f in floats if is_tie(f))
    print(f"inputs={len(texts)} values={a.values} floats={len(floats)} extra={len(extra)} seed={a.seed}")
    print(f"agree={agree} explained={explained} unexplained={len(unexplained)}")
    print(f"exact-tie floats in corpus (Note 2 cases)={ties}")
    print(f"our refusals={sum(1 for o in ours if o[0] == 'err')}")
    for kind, text, o, ref in unexplained[:20]:
        print("UNEXPLAINED", kind, repr(text[:200]), o[:2], ref)
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
