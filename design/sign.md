# Design: sign (Ed25519 signatures in dos-core)

## Goal

`crates/dos-core/src/sign.rs` gives the core one way to sign and one way to verify.

- Ed25519 (RFC 8032), via `ed25519-dalek` 2.2.0 and `curve25519-dalek` 4.1.3 (versions from `Cargo.lock`).
- Verification is `verify_strict` only, plus our own key checks (ground rule 4, closes SG-8 for the Rust core).
- Every signed message is domain separated and versioned (closes SG-9 for the Rust core).
- `kid` is a fixed function of the public key, so a verifier can pick the key by `kid` (prepares DM-4, SG-10).
- No I/O, no RNG, no clock, no `unsafe`, no panics. Secret keys are zeroized on drop and never printed.

Out of scope: key storage, key rotation, the decision object itself (its JCS form, `v`, `kid` field), batch verification, the Rust conformance adapter (owned by `dos-conformance`).

## Signed bytes: two approaches

**A. Fixed ASCII prefix.** `msg = "decision-os/v1/" || tag || 0x00 || payload`, where `tag` is one of a closed set of lowercase ASCII names (`decision`, `capability`, `revocation`, `consent`, `audit-head`).

**B. Wrap the payload in a JCS object** `{"v":1,"type":"decision","payload":...}` and sign its bytes.

B needs `canon.rs` (not this task), forces every payload to be JSON and makes the signer depend on a canonicalizer being bug-free. A works for any byte payload, including the JCS bytes that the decision task will pass in, and its parsing is trivial.

Ed25519ctx (RFC 8032 section 5.1 with a context string) would be the standard tool, but `ed25519-dalek` 2.2.0 supports a context only for Ed25519ph (prehashed). Prehashing changes the security assumption (collision resistance of SHA-512 on the message), so we do not use it.

**Choice: A.** Why it makes cross-domain reuse impossible:

- No tag contains `0x00`, and the tag is followed by `0x00`. So the bytes up to the first `0x00` after the 15-byte prefix name exactly one tag, and no tag's encoding is a prefix of another's (`decision` vs a hypothetical `decisions` differ at the terminator).
- The map from `(domain, payload)` to `msg` is therefore injective across all domains: a signature for domain A is a signature on a message that domain B can never produce.
- The version is inside the prefix. A v2 construction uses `decision-os/v2/` and can never equal a v1 message.
- Every message starts with `d` (0x64). The oracle signs JSON objects, which start with `{` (0x7b). So a Rust signature can never be a valid oracle decision signature and the reverse, even under one key.

## kid

`kid = lowercase_hex( SHA-256( "decision-os/v1/kid" || 0x00 || A )[0..16] )`, where `A` is the 32-byte canonical public key. 32 hex characters, 128 bits. It identifies a key; it is not an authenticator (the signature check is). A collision would only make a verifier try the wrong key, and the signature check would still fail.

## Key and signature checks (strict profile)

`VerifyingKey::from_bytes` refuses, in this order:

1. bytes that do not decompress to a curve point: `invalid_key`;
2. a non-canonical encoding (y not reduced mod p, or the sign bit set when x = 0): `non_canonical_key`. `curve25519-dalek` decompression accepts these, and `verify_strict` hashes the raw bytes, so without this check one point has several keys and several kids;
3. a point of small order (the 8 torsion points): `weak_key`. `verify_strict` also rejects these, but we refuse at parse time so a weak key can never be stored.

`Signature::from_bytes` refuses `S` that is not canonical (`S >= L`, which includes any of the top 3 bits set): `non_canonical_signature`. `ed25519-dalek` rejects this inside verification too; we refuse earlier with a precise code.

`verify` then calls `verify_strict`, which also rejects a small-order `R` and any non-canonical `R` (it compares recomputed `R` bytes with the given ones). Failure: `bad_signature`.

## Hex

Encode: lowercase. Decode: lowercase only. Uppercase, odd length, or any non-hex character: `bad_hex`; correct hex with the wrong byte length: `bad_length`. Lowercase-only gives every key, kid and signature exactly one text form, so string comparison of kids is sound.

## Failure modes, each refusing with a code

| Input | Code |
|---|---|
| hex with uppercase, odd length, non-hex char | `bad_hex` |
| key not 32 bytes, signature not 64 bytes, kid not 16 bytes | `bad_length` |
| key bytes not a curve point | `invalid_key` |
| key encoding not canonical | `non_canonical_key` |
| small-order key (incl. all-zero bytes, identity) | `weak_key` |
| `S >= L` | `non_canonical_signature` |
| any other verification failure (wrong payload, domain, key, R) | `bad_signature` |
| kid does not match the key | `kid_mismatch` |
| domain name not in the closed set | `unknown_domain` |

No path returns success on an error. There is no non-strict verify in the crate.

## Fiat-Crypto backend

`curve25519-dalek` 4.1.3 selects its field backend from `--cfg curve25519_dalek_backend="fiat"`; with it, the field arithmetic comes from the `fiat-crypto` crate (formally verified, sluicegate PR #22). `.cargo/config.toml` sets this flag and declares it for `check-cfg`. Proof of selection: a test asserts `cfg!(curve25519_dalek_backend = "fiat")` in dos-core (the same rustflags reach every crate), and `cargo tree -i fiat-crypto` shows it in the graph. If `RUSTFLAGS` is set in the environment, Cargo ignores the config rustflags; the test then fails instead of silently falling back.

## Test plan

Tests are written first and must fail on the stub.

- RFC 8032 section 7.1, all five vectors (TEST 1, 2, 3, 1024, SHA(abc)) against the raw primitive: public key derivation, signature bytes, `verify_strict` ok.
- All 8 small-order points (cross-checked against `curve25519_dalek::constants::EIGHT_TORSION`): `weak_key`.
- Non-canonical key encodings (y + p, sign bit on x = 0, sign bit on a real point is a different valid key): `non_canonical_key`.
- Not-on-curve bytes: `invalid_key`.
- `S + L` of a valid signature, `S` with top bit set: `non_canonical_signature`.
- Domain A signature rejected under every other domain.
- Wrong kid: `kid_mismatch`. kid of TEST 1 key computed independently (Python `hashlib`).
- Hex: truncated, extended, odd, uppercase, non-hex: refused with the right code.
- `demonstrates_plain_verify_is_weaker`: a forged signature under the identity key that plain `verify` accepts for any message and `verify_strict` rejects.
- proptest: sign/verify round trip; any single bit flip in payload, signature or public key fails.
- Fiat backend selected.
- Conformance vectors `conformance/vectors/sign/*.json` (at least 40), expected values for `sign` computed with an independent implementation (Python `cryptography` + `hashlib`), checked by a dos-core integration test that runs every vector.
