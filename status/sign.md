# Status: sign

Branch `task/sign`. Spec `spec/sign.md`, design `design/sign.md`.

## What changed

- `crates/dos-core/src/sign.rs`: Ed25519 sign/verify with domain separation, strict checks, kid and hex. 349 non-test lines (lines 1-349; the tests start at line 350).
- `crates/dos-core/tests/sign_vectors.rs`: runs every `conformance/vectors/sign/*.json` through the public API.
- `conformance/vectors/sign/`: 75 new vectors (18 sign, 40 verify, 17 kid).
- `crates/dos-core/Cargo.toml`: `ed25519-dalek =2.2.0` (no default features; `zeroize`, `fast`), `curve25519-dalek =4.1.3`, `sha2 =0.10.9`, `zeroize 1.8`. Dev: `proptest 1.11` (resolved to 1.12.0), `serde_json 1`. `Cargo.lock` updated.
- `.cargo/config.toml`: `--cfg curve25519_dalek_backend="fiat"` and a matching `--check-cfg`.
- `spec/sign.md`, `design/sign.md`, this file.

## Public API (`dos_core::sign`)

```rust
pub enum Domain { Decision, Capability, Revocation, Consent, AuditHead }
  Domain::ALL, tag(self) -> &'static str, from_tag(&str) -> Result<Domain, SignError>
pub fn signed_message(Domain, &[u8]) -> Vec<u8>
pub enum SignError { BadHex, BadLength, InvalidKey, NonCanonicalKey, WeakKey,
                     NonCanonicalSignature, BadSignature, KidMismatch, UnknownDomain }
  code(self) -> &'static str; Display prints the code
pub fn hex_encode(&[u8]) -> String                               // lowercase
pub fn hex_decode(&str) -> Result<Vec<u8>, SignError>            // lowercase only
pub fn hex_decode_array<const N: usize>(&str) -> Result<[u8; N], SignError>
pub struct Kid           from_bytes(&[u8;16]), to_bytes, from_hex, to_hex
pub struct Signature     from_bytes(&[u8;64]) -> Result (refuses S >= L), to_bytes, from_hex, to_hex
pub struct VerifyingKey  from_bytes(&[u8;32]) -> Result, from_hex, to_bytes, to_hex, kid,
                         is_conformance_test_key,
                         verify(Domain, &[u8], &Signature) -> Result<(), SignError>,
                         verify_with_kid(Domain, &[u8], &Signature, &Kid) -> Result<(), SignError>
pub struct SigningKey    from_bytes(&[u8;32]), verifying_key, kid, sign(Domain, &[u8]) -> Signature
                         (ZeroizeOnDrop, not Clone, Debug prints only the kid)
```

Signed bytes: `"decision-os/v1/" || tag || 0x00 || payload`. kid: `hex(SHA-256("decision-os/v1/kid" || 0x00 || A)[0..16])`.

## Evidence

### Tests written first and failing on a stub

The API was first written with stub bodies (accept everything, return zeros). Command:
`wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/admin/dos-wt/sign && CARGO_TARGET_DIR=/root/target/sign cargo test -p dos-core'`

```
test result: FAILED. 4 passed; 28 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
test sign::tests::all_eight_small_order_keys_refused ... FAILED
test sign::tests::all_zero_key_refused ... FAILED
test sign::tests::arbitrary_key_and_signature_bytes_never_verify ... FAILED
test sign::tests::debug_never_prints_secret ... FAILED
test sign::tests::demonstrates_plain_verify_is_weaker ... FAILED
test sign::tests::domain_a_signature_rejected_under_every_other_domain ... FAILED
test sign::tests::domain_tags_are_closed_and_round_trip ... FAILED
test sign::tests::error_codes_are_stable ... FAILED
test sign::tests::fiat_backend_selected ... ok
test sign::tests::hex_decode_never_panics ... ok
test sign::tests::hex_policy ... FAILED
test sign::tests::key_bit_flip_fails ... FAILED
test sign::tests::non_canonical_key_encodings_refused ... FAILED
test sign::tests::non_canonical_large_order_key_exists_and_is_refused ... FAILED
test sign::tests::non_canonical_r_refused ... FAILED
test sign::tests::not_on_curve_refused ... FAILED
test sign::tests::payload_bit_flip_fails ... FAILED
test sign::tests::rfc8032_7_1_vectors_raw_primitive ... FAILED
test sign::tests::rfc_signature_is_not_valid_in_any_domain ... FAILED
test sign::tests::round_trip ... ok
test sign::tests::s_equal_l_refused_and_l_minus_1_parses ... FAILED
test sign::tests::s_plus_l_refused ... FAILED
test sign::tests::s_top_bits_refused ... FAILED
test sign::tests::signature_bit_flip_fails ... FAILED
test sign::tests::signed_message_layout ... FAILED
test sign::tests::signed_messages_are_injective_across_domains ... FAILED
test sign::tests::signing_key_zeroizes_on_drop ... ok
test sign::tests::small_order_list_is_complete ... FAILED
test sign::tests::small_order_r_refused ... FAILED
test sign::tests::test_key_public_and_kid ... FAILED
test sign::tests::truncated_and_extended_hex_refused ... FAILED
test sign::tests::wrong_kid_is_refused_before_signature ... FAILED
```

4 tests passed on the stub. `fiat_backend_selected` checks the build config, not the code. `hex_decode_never_panics` and `round_trip` pass on a stub that accepts everything. `signing_key_zeroizes_on_drop` passed because the stub already had the marker trait. Each one means something only together with the others (for example, `round_trip` together with the bit-flip properties).

### All tests pass after the implementation

Same command:

```
     Running unittests src/lib.rs (/root/target/sign/debug/deps/dos_core-e41b4f99c5cb3eb9)
test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.35s
     Running tests/sign_vectors.rs (/root/target/sign/debug/deps/sign_vectors-49eb518497cffca9)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.70s
```

`cargo test -p dos-core --test sign_vectors -- --nocapture`:

```
75 sign vectors checked, 0 failed
test every_sign_vector_passes ... ok
```

### RFC 8032 section 7.1

`rfc8032_7_1_vectors_raw_primitive` checks all five vectors (TEST 1, 2, 3, 1024, SHA(abc)): public key derivation, exact signature bytes and `verify_strict`. A script parsed the hex from `https://www.rfc-editor.org/rfc/rfc8032.txt`. It stripped the page breaks and checked every length against the RFC's "length N bytes". Nothing was typed by hand.

### Step 3: plain `verify` is weaker than `verify_strict`

`cargo test -p dos-core --lib demonstrates_plain_verify_is_weaker -- --nocapture`:

```
running 1 test
plain verify accepted the forged signature for 3/3 messages; verify_strict rejected 3/3
test sign::tests::demonstrates_plain_verify_is_weaker ... ok
```

The public key is the identity point (small order), `R` is the identity and `S` = 0. Plain `verify` accepts this for every message, including `"pay 1000 to mallory"`. `verify_strict` rejects all three. Our `VerifyingKey::from_bytes` refuses the key with `weak_key`. This is the only use of non-strict verify in the repo. Its `use ed25519_dalek::Verifier` is scoped inside that test function.

There is a second case that `verify_strict` alone does NOT catch: non-canonical public key encodings of large-order points (y + p for y in {3,4,5,6,9,10,14,15,16,18}). `ed25519-dalek` accepts them and `is_weak()` is false for them (`non_canonical_large_order_key_exists_and_is_refused`). We refuse them with `non_canonical_key`, so one point has exactly one key and one kid.

On `S >= L`: `ed25519-dalek` 2.x (without `legacy_compatibility`) already rejects a non-canonical `S` in plain `verify` too, as sluicegate PR #18 suspected. We refuse it earlier, at parse time, with a precise code.

### The Fiat-Crypto backend is selected

```
$ cargo tree -p dos-core -e normal -i fiat-crypto
fiat-crypto v0.2.9
└── curve25519-dalek v4.1.3
    ├── dos-core v0.1.0 (/mnt/c/Users/admin/dos-wt/sign/crates/dos-core)
    └── ed25519-dalek v2.2.0
        └── dos-core v0.1.0 (/mnt/c/Users/admin/dos-wt/sign/crates/dos-core)

$ RUSTFLAGS="-Cdebuginfo=0" cargo tree -p dos-core -e normal -i fiat-crypto
warning: nothing to print.

$ RUSTFLAGS="-Cdebuginfo=0" CARGO_TARGET_DIR=/root/target/sign-nofiat cargo test -p dos-core --lib fiat
error[E0080]: evaluation panicked: curve25519-dalek must build with the Fiat-Crypto backend (.cargo/config.toml); RUSTFLAGS in the environment overrides it
```

`fiat_backend_selected` is a `const` assertion. Without the flag the test target does not compile, so the suite cannot pass on the default backend. Only the field arithmetic is Fiat-verified. Decompression, encoding, the small-order check and the scalar check are not.

### The vectors do not depend on the Rust code

The expected `sign` values (exact signatures) and the kids were computed with Python `cryptography` 46.0.5 (OpenSSL Ed25519) and `hashlib`. Curve membership was checked with plain modular arithmetic. The generator script is in the appendix below. It was run as `python3 -I gen_sign_vectors.py conformance/vectors/sign` and printed `75 vectors; large-order non-canonical y = [3, 4, 5, 6, 9, 10, 14, 15, 16, 18] ; off-curve y = 2`. The TEST 1 kid `b1f1515d964ca23d4f37283c507551d3` was computed the same way. Both the generator and `test_key_public_and_kid` assert it.

### Gates

In WSL I had to set `export GIT_DIR=/mnt/c/Users/admin/decision-os/.git/worktrees/sign GIT_WORK_TREE=/mnt/c/Users/admin/dos-wt/sign`. The worktree's `.git` file holds a Windows path that WSL git cannot follow. Without these variables every git call in the scripts printed `fatal: not a git repository`.

```
$ CARGO_TARGET_DIR=/root/target/sign bash scripts/gate-fast.sh fast; echo gate-exit=$?
ok       cargo fmt
ok       cargo clippy
ok       cargo test (dos-conformance dos-core )
skipped  conformance (conformance/run.sh not present yet)
ok       protected paths unchanged
gate-exit=0
$ bash scripts/check-protected.sh; echo protected-exit=$?
protected paths: unchanged
protected-exit=0
```

## Attack on my own change (checklist)

I tested the five inputs most likely to break it:

- small-order keys: all 8, plus the all-zero key;
- non-canonical key encodings of large-order points;
- `S + L`, `S = L` and the top bits of `S`;
- a signature from another domain, and raw RFC or oracle-style signatures that have no prefix;
- hex edge cases: uppercase, odd length, truncated, extended, non-ASCII.

proptest also checks that random key, R and S bytes never verify, that any single bit flip in the payload, signature or key fails, and that hex parsing never panics.

Three ways this could cause an incident in six months:

1. **Someone adds a call to plain `verify`.** Checked: `grep -n "Verifier\|\.verify(" crates/dos-core/src/sign.rs` finds the only plain call inside `demonstrates_plain_verify_is_weaker`. Every other `.verify(` call is our strict wrapper. The fields of `VerifyingKey` and `Signature` are private, so code outside the module cannot build an unchecked key or `S`. A CI grep for `Verifier` outside that test would enforce this instead of relying on review. I did not add one because the gate scripts are not mine.
2. **The Fiat flag silently disappears.** This happens if CI sets `RUSTFLAGS`, or if `dos-py`/maturin builds outside the workspace. Checked: the test target then does not compile (output above). This does not cover a build of `dos-core` from outside this workspace. Such a build gets the default backend and nothing detects it.
3. **A key is reused across protocols.** Every v1 message starts with `decision-os/v1/<tag>\0`. So it never equals an oracle message (which starts with `{`) or a message from another domain. This does not protect against a future signer that signs arbitrary raw bytes with the same key, so the decision task must not expose one. I did not check sluicegate's binary payloads against our prefix.

Secrets: `SigningKey` has a hand-written `Debug` that prints only the kid. A test checks that the hex and decimal forms of the secret do not appear. It is not `Clone`. It is `ZeroizeOnDrop` through `ed25519_dalek::SigningKey` (feature `zeroize`). Two temporary copies are not covered by this: the caller's `[u8; 32]`, and the expanded secret that `ed25519-dalek` builds for each signature (that type is itself `ZeroizeOnDrop`).

Platforms: the core uses no paths and starts no processes. The vector test builds its path from `CARGO_MANIFEST_DIR` and relative parts. It was run on Linux only; Windows-native and macOS were not run. The JSON vectors use LF line endings (`.gitattributes`).

## Not done

- No Rust conformance adapter, because `dos-conformance` is not mine. The dos-core integration test checks the vectors instead, and `conformance/run.sh` does not exist yet.
- The oracle adapter was not run on these vectors. The oracle has no `sign` area and no domain tag, so every `sign` vector is a deliberate divergence (see open risks). No `oracle_expected` was written.
- No fuzz target (a Phase 2 item) and no Kani harness.
- `cargo audit` and `cargo deny` are not installed in WSL, so dependency advisories were not checked.
- No Windows-native or macOS test runs.
- `unsafe` in dependencies: `curve25519-dalek` 4.1.3 has `unsafe` in `lib.rs`, in `constants.rs` and in the SIMD backend (which is not built with `fiat`). I did not inspect `fiat-crypto`. `dos-core` itself is `forbid(unsafe_code)`.

## Open risks

- **Deliberate incompatibility with the oracle (DM-4, SG-9).** The oracle signs `json.dumps(sort_keys=True)` bytes. It has no domain tag, no `v`, no `kid`, and a fixed `issued_by`. Rust decisions are NOT signature-compatible with oracle decisions: an oracle signature never verifies here, and a Rust signature never verifies in the oracle (`verify-oracle-style-untagged-signature`). Phase 2 requires "signatures that verify across implementations". To meet it, either the oracle adopts this construction (an `oracle-v1`-style spec change that Ali approves), or the requirement is restated. Ali has to decide this; it is not a bug to fix here.
- `signed_message` copies the payload, so peak memory is twice the payload size.
- The kid is 128 bits and does not authenticate anything. A collision only makes a verifier try the wrong key, and the signature check still fails.
- Gate behaviour: one run of `gate-fast.sh fast` printed `FAIL cargo clippy`, yet the shell reported `gate-exit=0` for that run. I did not find the cause. The final run is fully green, so the result is not affected. The verifier should check that a failing step makes the gate exit 1.

## Appendix: vector generator

```python
"""Generate conformance/vectors/sign/*.json independently of the Rust code.

Signatures: Python `cryptography` (OpenSSL Ed25519). kid: hashlib. Curve checks:
plain modular arithmetic below. Usage: python3 -I gen_sign_vectors.py <outdir>
"""
import hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

OUT = sys.argv[1]
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
TAGS = ["decision", "capability", "revocation", "consent", "audit-head"]
TEST1_SK = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
TEST2_SK = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
SMALL_ORDER = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]


def msg(tag, payload):
    return b"decision-os/v1/" + tag.encode() + b"\x00" + payload


def key(sk):
    return Ed25519PrivateKey.from_private_bytes(sk)


def pub(sk):
    return key(sk).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign(sk, tag, payload):
    return key(sk).sign(msg(tag, payload))


def kid(pk):
    return hashlib.sha256(b"decision-os/v1/kid\x00" + pk).hexdigest()[:32]


def on_curve_y(y):
    """True iff some x satisfies the curve equation for this y (mod p)."""
    y %= P
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    return x2 == 0 or pow(x2, (P - 1) // 2, P) == 1


def enc_int(n):
    return n.to_bytes(32, "little")


TEST1_PK = pub(TEST1_SK)
TEST2_PK = pub(TEST2_SK)
assert TEST1_PK.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
assert kid(TEST1_PK) == "b1f1515d964ca23d4f37283c507551d3"

vectors = []


def add(name, inp, expected, source, gap=None):
    v = {"v": 1, "area": "sign", "name": name, "input": inp, "expected": expected, "source": source}
    if gap:
        v["gap"] = gap
    vectors.append(v)


def ok_sign(name, tag, payload, source):
    s = sign(TEST1_SK, tag, payload)
    add(name, {"op": "sign", "domain": tag, "payload_hex": payload.hex()},
        {"ok": {"sig": s.hex(), "kid": kid(TEST1_PK)}}, source, "SG-9")


# ---- sign ----
ok_sign("sign-decision-empty", "decision", b"", "spec/sign.md signed bytes")
ok_sign("sign-decision-one-zero-byte", "decision", b"\x00", "spec/sign.md signed bytes")
ok_sign("sign-decision-ascii", "decision", b"hello", "spec/sign.md signed bytes")
JCS = b'{"action_fingerprint":"ab","v":1,"verdict":"PERMIT"}'
ok_sign("sign-decision-jcs-object", "decision", JCS, "spec/sign.md; payload is JCS bytes")
ok_sign("sign-decision-all-ff", "decision", b"\xff" * 64, "spec/sign.md signed bytes")
ok_sign("sign-decision-1024-bytes", "decision", bytes(range(256)) * 4, "spec/sign.md signed bytes")
ok_sign("sign-decision-payload-with-nul", "decision", b"a\x00b", "spec/sign.md; 0x00 inside payload is data")
ok_sign("sign-decision-payload-mimics-other-domain", "decision", b"decision-os/v1/capability\x00x",
        "spec/sign.md; payload that looks like another domain's message")
for t in TAGS[1:]:
    ok_sign(f"sign-{t}-empty", t, b"", "spec/sign.md reserved domain")
for bad in ["Decision", "", "decision\u0000", "audit_head"]:
    nm = {"Decision": "capitalized", "": "empty", "decision\u0000": "trailing-nul", "audit_head": "underscore"}[bad]
    add(f"sign-unknown-domain-{nm}", {"op": "sign", "domain": bad, "payload_hex": ""},
        {"error": "unknown_domain"}, "spec/sign.md domains")
add("sign-payload-uppercase-hex", {"op": "sign", "domain": "decision", "payload_hex": "AB"},
    {"error": "bad_hex"}, "spec/sign.md text encoding")
add("sign-payload-odd-hex", {"op": "sign", "domain": "decision", "payload_hex": "abc"},
    {"error": "bad_hex"}, "spec/sign.md text encoding")

# ---- kid ----
add("kid-test-key", {"op": "kid", "public_key": TEST1_PK.hex()}, {"ok": kid(TEST1_PK)}, "spec/sign.md key id", "DM-4")
add("kid-rfc8032-test2-key", {"op": "kid", "public_key": TEST2_PK.hex()}, {"ok": kid(TEST2_PK)}, "spec/sign.md key id", "DM-4")
add("kid-uppercase-key", {"op": "kid", "public_key": TEST1_PK.hex().upper()}, {"error": "bad_hex"}, "spec/sign.md text encoding")
add("kid-truncated-key", {"op": "kid", "public_key": TEST1_PK.hex()[:-2]}, {"error": "bad_length"}, "spec/sign.md text encoding")
add("kid-extended-key", {"op": "kid", "public_key": TEST1_PK.hex() + "00"}, {"error": "bad_length"}, "spec/sign.md text encoding")
for i, so in enumerate(SMALL_ORDER):
    add(f"kid-small-order-key-{i}", {"op": "kid", "public_key": so}, {"error": "weak_key"},
        "spec/sign.md public key checks; the 8 torsion points", "SG-8")
add("kid-non-canonical-identity-y-plus-p", {"op": "kid", "public_key": enc_int(P + 1).hex()},
    {"error": "non_canonical_key"}, "spec/sign.md public key checks", "SG-8")
neg0 = bytearray(enc_int(1)); neg0[31] |= 0x80
add("kid-non-canonical-identity-sign-bit", {"op": "kid", "public_key": bytes(neg0).hex()},
    {"error": "non_canonical_key"}, "spec/sign.md public key checks", "SG-8")
large = [y for y in range(2, 19) if on_curve_y(y)]
assert large, "need a non-canonical encoding of a large-order point"
add("kid-non-canonical-large-order-point", {"op": "kid", "public_key": enc_int(P + large[0]).hex()},
    {"error": "non_canonical_key"},
    f"spec/sign.md public key checks; y = {large[0]} encoded as p + {large[0]}: not small order, so verify_strict alone would accept it", "SG-8")
off = [y for y in range(2, 41) if not on_curve_y(y)]
add("kid-not-on-curve", {"op": "kid", "public_key": enc_int(off[0]).hex()},
    {"error": "invalid_key"}, f"spec/sign.md public key checks; y = {off[0]} has no x")

# ---- verify ----
S_EMPTY = sign(TEST1_SK, "decision", b"")
S_X = sign(TEST1_SK, "decision", b"x")
K1 = kid(TEST1_PK)


def ver(name, expected, source, gap=None, **kw):
    inp = {"op": "verify", "domain": "decision", "payload_hex": "78", "sig": S_X.hex()}
    inp.update(kw)
    add(name, inp, expected, source, gap)


ver("verify-ok", {"ok": True}, "spec/sign.md")
ver("verify-ok-empty-payload", {"ok": True}, "spec/sign.md", payload_hex="", sig=S_EMPTY.hex())
ver("verify-ok-with-kid", {"ok": True}, "spec/sign.md kid check", "DM-4", kid=K1)
ver("verify-ok-explicit-public-key", {"ok": True}, "spec/sign.md", public_key=TEST1_PK.hex(), kid=K1)
s2 = sign(TEST2_SK, "decision", b"x")
ver("verify-ok-other-key", {"ok": True}, "spec/sign.md", public_key=TEST2_PK.hex(), sig=s2.hex(), kid=kid(TEST2_PK))
ver("verify-other-keys-signature-under-test-key", {"error": "bad_signature"}, "spec/sign.md", sig=s2.hex())
ver("verify-wrong-payload", {"error": "bad_signature"}, "spec/sign.md", payload_hex="79")
ver("verify-payload-extended", {"error": "bad_signature"}, "spec/sign.md", payload_hex="7800")
for t in TAGS[1:]:
    ver(f"verify-decision-signature-under-{t}", {"error": "bad_signature"},
        "spec/sign.md; cross-domain reuse impossible", "SG-9", domain=t)
cap = sign(TEST1_SK, "capability", b"x")
ver("verify-capability-signature-under-decision", {"error": "bad_signature"},
    "spec/sign.md; cross-domain reuse impossible", "SG-9", sig=cap.hex())
raw_rfc = key(TEST1_SK).sign(b"")
assert raw_rfc.hex().startswith("e5564300c360ac72")
ver("verify-raw-rfc8032-test1-signature", {"error": "bad_signature"},
    "RFC 8032 7.1 TEST 1 raw signature (no domain prefix) is never valid", "SG-9", payload_hex="", sig=raw_rfc.hex())
oracle_style = key(TEST1_SK).sign(JCS)
ver("verify-oracle-style-untagged-signature", {"error": "bad_signature"},
    "oracle kernel.py signs untagged JSON bytes; deliberately incompatible", "DM-4", payload_hex=JCS.hex(), sig=oracle_style.hex())
ver("verify-unknown-domain", {"error": "unknown_domain"}, "spec/sign.md check order", domain="DECISION")
ver("verify-payload-bad-hex", {"error": "bad_hex"}, "spec/sign.md check order", payload_hex="7G")
wrong_kid = bytearray(bytes.fromhex(K1)); wrong_kid[0] ^= 1
ver("verify-wrong-kid", {"error": "kid_mismatch"}, "spec/sign.md kid check", "SG-10", kid=bytes(wrong_kid).hex())
ver("verify-kid-of-other-key", {"error": "kid_mismatch"}, "spec/sign.md kid check", "SG-10", kid=kid(TEST2_PK))
ver("verify-kid-mismatch-before-bad-signature", {"error": "kid_mismatch"}, "spec/sign.md check order",
    kid=kid(TEST2_PK), sig="00" * 64)
ver("verify-kid-uppercase", {"error": "bad_hex"}, "spec/sign.md text encoding", kid=K1.upper())
ver("verify-kid-truncated", {"error": "bad_length"}, "spec/sign.md text encoding", kid=K1[:-2])
ver("verify-sig-truncated", {"error": "bad_length"}, "spec/sign.md text encoding", sig=S_X.hex()[:-2])
ver("verify-sig-extended", {"error": "bad_length"}, "spec/sign.md text encoding", sig=S_X.hex() + "00")
ver("verify-sig-odd-length", {"error": "bad_hex"}, "spec/sign.md text encoding", sig=S_X.hex()[:-1])
ver("verify-sig-uppercase", {"error": "bad_hex"}, "spec/sign.md text encoding", sig=S_X.hex().upper())
ver("verify-sig-empty", {"error": "bad_length"}, "spec/sign.md text encoding", sig="")
s_int = int.from_bytes(S_X[32:], "little")
assert s_int < L
mall = S_X[:32] + (s_int + L).to_bytes(32, "little")
ver("verify-s-plus-l-malleability", {"error": "non_canonical_signature"}, "spec/sign.md signature checks", "SG-8", sig=mall.hex())
top = bytearray(S_X); top[63] |= 0x80
ver("verify-s-top-bit-set", {"error": "non_canonical_signature"}, "spec/sign.md signature checks", "SG-8", sig=bytes(top).hex())
ver("verify-s-equal-l", {"error": "non_canonical_signature"}, "spec/sign.md signature checks", "SG-8",
    sig=(S_X[:32] + L.to_bytes(32, "little")).hex())
ver("verify-all-zero-signature", {"error": "bad_signature"}, "spec/sign.md; R small order", "SG-8", sig="00" * 64)
ver("verify-identity-r-zero-s", {"error": "bad_signature"}, "spec/sign.md; R small order", "SG-8",
    sig=SMALL_ORDER[0] + "00" * 32)
ver("verify-non-canonical-r", {"error": "bad_signature"}, "spec/sign.md; R compared as bytes", "SG-8",
    sig=enc_int(P + 1).hex() + S_X[32:].hex())
flip_r = bytearray(S_X); flip_r[0] ^= 1
ver("verify-r-bit-flip", {"error": "bad_signature"}, "spec/sign.md", sig=bytes(flip_r).hex())
ver("verify-forgery-under-identity-key", {"error": "weak_key"},
    "plain verify accepts R=identity,S=0 under the identity key for every message; refused at key parse", "SG-8",
    public_key=SMALL_ORDER[0], sig=SMALL_ORDER[0] + "00" * 32)
ver("verify-all-zero-key", {"error": "weak_key"}, "spec/sign.md public key checks", "SG-8", public_key="00" * 32)
ver("verify-non-canonical-key", {"error": "non_canonical_key"}, "spec/sign.md public key checks", "SG-8",
    public_key=enc_int(P + large[0]).hex())
ver("verify-key-not-on-curve", {"error": "invalid_key"}, "spec/sign.md public key checks", public_key=enc_int(off[0]).hex())
ver("verify-key-bad-length", {"error": "bad_length"}, "spec/sign.md text encoding", public_key=TEST1_PK.hex()[:-2])
ver("verify-key-checked-before-kid", {"error": "weak_key"}, "spec/sign.md check order", public_key="00" * 32, kid=K1)

names = [v["name"] for v in vectors]
assert len(names) == len(set(names))
os.makedirs(OUT, exist_ok=True)
for v in vectors:
    with open(os.path.join(OUT, v["name"] + ".json"), "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(v, indent=2, ensure_ascii=True) + "\n")
print(len(vectors), "vectors; large-order non-canonical y =", large, "; off-curve y =", off[0])
```
