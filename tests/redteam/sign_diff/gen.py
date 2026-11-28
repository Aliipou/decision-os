"""Red team (findings/sign.md), differential for dos_core::sign.

Generates cases.jsonl: for each case, the spec/sign.md result computed by an
independent pure-Python reference ("spec") and the accept/reject of Python
`cryptography` (OpenSSL) on the same signed message ("py"). The Rust test
crates/dos-core/tests/redteam_sign_diff.rs checks Rust == spec on every case
and reports the cryptography differences, classified.

Run: python3 -I tests/redteam/sign_diff/gen.py tests/redteam/sign_diff/cases.jsonl
Deterministic (fixed seed).
"""

import hashlib
import json
import random
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
TAGS = ["decision", "capability", "revocation", "consent", "audit-head"]


def inv(x):
    return pow(x, P - 2, P)


def add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


IDENT = (0, 1, 1, 0)


def mul(s, pt):
    q = IDENT
    while s > 0:
        if s & 1:
            q = add(q, pt)
        pt = add(pt, pt)
        s >>= 1
    return q


def neg(pt):
    x, y, z, t = pt
    return ((-x) % P, y, z, (-t) % P)


def eq(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def recover_x(y, sign):
    """x for y (already < p), or None. Returns x without canonical checks."""
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    if x2 == 0:
        return 0  # caller handles the sign bit
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def compress(pt):
    x, y, z, _ = pt
    zi = inv(z)
    x, y = x * zi % P, y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def decompress_lenient(b):
    """Like curve25519-dalek decompress: y taken mod p, x=0 with sign 1 allowed."""
    n = int.from_bytes(b, "little")
    sign = n >> 255
    y = (n & ((1 << 255) - 1)) % P
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def small_order(pt):
    return eq(mul(8, pt), IDENT)


G_Y = 4 * inv(5) % P
G = (recover_x(G_Y, 0), G_Y, 1, recover_x(G_Y, 0) * G_Y % P)

TORSION = []
_t = decompress_lenient(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"))
for i in range(8):
    TORSION.append(mul(i, _t))


def spec_key(b):
    pt = decompress_lenient(b)
    if pt is None:
        return "invalid_key", None
    if compress(pt) != b:
        return "non_canonical_key", None
    if small_order(pt):
        return "weak_key", None
    return None, pt


def spec_verify(pk, sig, msg):
    err, a = spec_key(pk)
    if err:
        return err
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return "non_canonical_signature"
    rb = sig[:32]
    r = decompress_lenient(rb)
    if r is None or small_order(r):
        return "bad_signature"
    k = int.from_bytes(hashlib.sha512(rb + pk + msg).digest(), "little") % L
    chk = add(mul(s, G), neg(mul(k, a)))
    return "ok" if compress(chk) == rb else "bad_signature"


def py_verify(pk, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return "ok"
    except (InvalidSignature, ValueError):
        return "reject"
    except Exception as e:  # noqa: BLE001 - any other failure is a reject too
        return "reject:" + type(e).__name__


def signed(tag, payload):
    return b"decision-os/v1/" + tag.encode() + b"\x00" + payload


def all_encodings(pt):
    c = compress(pt)
    n = int.from_bytes(c, "little") & ((1 << 255) - 1)
    ys = [n]
    if n + P < (1 << 255):
        ys.append(n + P)
    out = []
    for y in ys:
        for sgn in (0, 1):
            out.append(int.to_bytes(y | (sgn << 255), 32, "little"))
    return out


def raw_sign(a, prefix, pk, msg, r=None):
    if r is None:
        r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    rb = compress(mul(r, G))
    k = int.from_bytes(hashlib.sha512(rb + pk + msg).digest(), "little") % L
    s = (r + k * a) % L
    return rb + int.to_bytes(s, 32, "little")


def main(out_path):
    rnd = random.Random(0x5EED)
    cases = []

    def case(cat, tag, payload, pk, sig, sign_tag=None):
        msg = signed(tag, payload)
        cases.append(
            {
                "cat": cat,
                "domain": tag,
                "payload": payload.hex(),
                "pk": pk.hex(),
                "sig": sig.hex(),
                "spec": spec_verify(pk, sig, msg),
                "py": py_verify(pk, sig, msg),
            }
        )

    # 1. honest signatures by cryptography, random keys/domains/payloads.
    honest = []
    for _ in range(2500):
        sk = Ed25519PrivateKey.from_private_bytes(rnd.randbytes(32))
        pk = sk.public_key().public_bytes_raw()
        tag = rnd.choice(TAGS)
        payload = rnd.randbytes(rnd.randrange(0, 64))
        sig = sk.sign(signed(tag, payload))
        honest.append((tag, payload, pk, sig))
        case("honest", tag, payload, pk, sig)

    # 2. mutations of honest signatures.
    for tag, payload, pk, sig in honest:
        b = bytearray(sig)
        b[rnd.randrange(64)] ^= 1 << rnd.randrange(8)
        case("mut-sig", tag, payload, pk, bytes(b))
        k = bytearray(pk)
        k[rnd.randrange(32)] ^= 1 << rnd.randrange(8)
        case("mut-key", tag, payload, bytes(k), sig)
        other = rnd.choice([t for t in TAGS if t != tag])
        case("mut-domain", other, payload, pk, sig)
    # S + L, S + 2L on a subset.
    for tag, payload, pk, sig in honest[:500]:
        s = int.from_bytes(sig[32:], "little")
        for m in (1, 2, 15):
            if s + m * L < 2**256:
                case("s-plus-l", tag, payload, pk, sig[:32] + int.to_bytes(s + m * L, 32, "little"))

    # 3. random bytes.
    for _ in range(1500):
        case("random", rnd.choice(TAGS), rnd.randbytes(8), rnd.randbytes(32), rnd.randbytes(64))

    # 4. torsion keys, every encoding, with torsion R (every encoding) and S classes.
    s_classes = [0, 1, L - 1, 8, L - 8]
    for t in TORSION:
        for pk in all_encodings(t):
            for tr in TORSION:
                for rb in all_encodings(tr):
                    for s in s_classes:
                        case("torsion", "decision", b"", pk, rb + int.to_bytes(s, 32, "little"))

    # 5. mixed-order keys with crafted signatures (cofactorless-valid and not).
    for i in range(200):
        a = rnd.randrange(1, L)
        t = TORSION[rnd.randrange(1, 8)]
        apt = add(mul(a, G), t)
        pk = compress(apt)
        tag = rnd.choice(TAGS)
        payload = rnd.randbytes(16)
        msg = signed(tag, payload)
        # mixed key, honest-style R
        for _ in range(16):
            r = rnd.randrange(1, L)
            sig = raw_sign(a, b"", pk, msg, r)
            case("mixed-key", tag, payload, pk, sig)
        # mixed key and mixed R: R = rB + T2, S = r + k a
        for _ in range(16):
            r = rnd.randrange(1, L)
            t2 = TORSION[rnd.randrange(1, 8)]
            rb = compress(add(mul(r, G), t2))
            k = int.from_bytes(hashlib.sha512(rb + pk + msg).digest(), "little") % L
            s = (r + k * a) % L
            case("mixed-key-mixed-r", tag, payload, pk, rb + int.to_bytes(s, 32, "little"))
        # honest key, mixed R
        hpk = compress(mul(a, G))
        r = rnd.randrange(1, L)
        rb = compress(add(mul(r, G), t))
        k = int.from_bytes(hashlib.sha512(rb + hpk + msg).digest(), "little") % L
        case("honest-key-mixed-r", tag, payload, hpk, rb + int.to_bytes((r + k * a) % L, 32, "little"))

    # 6. non-canonical encodings of large-order points (y in 2..18 + p) and
    #    x = 0 sign-bit variants, with signatures from a random honest key.
    tag, payload, _, sig = honest[0]
    for y in range(0, 19):
        for sgn in (0, 1):
            for yy in (y, y + P):
                pk = int.to_bytes(yy | (sgn << 255), 32, "little")
                case("noncanon-key", tag, payload, pk, sig)

    # 7. y >= p for R in an otherwise honest signature: R' = R's y + p only
    #    possible when R's y < 19; emulate with small-y R and computed S.
    #    (Signer knows a; R must be r*B with small y: infeasible.) So instead:
    #    take R = a large-order point with y < 19 (no known r) and random S.
    for y in range(2, 19):
        rb = int.to_bytes(y, 32, "little")
        if decompress_lenient(rb) is None:
            continue
        for alt in all_encodings(decompress_lenient(rb)):
            for _ in range(4):
                tg, pl, pk, sg = rnd.choice(honest)
                case("small-y-r", tg, pl, pk, alt + sg[32:])

    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for c in cases:
            f.write(json.dumps(c, sort_keys=True) + "\n")
    from collections import Counter

    print(len(cases), "cases")
    print(Counter((c["cat"], c["spec"], c["py"]) for c in cases).most_common())


if __name__ == "__main__":
    main(sys.argv[1])
