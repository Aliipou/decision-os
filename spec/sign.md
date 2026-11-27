# Signatures (v1)

Normative. Checked by `conformance/vectors/sign/`. Implementation: `crates/dos-core/src/sign.rs`.

## Algorithm

Ed25519 as in RFC 8032 section 5.1 (pure Ed25519, no context, no prehash), with the strict checks below. A conforming verifier MUST reject everything this section rejects; accepting more is a bug.

## Domains

| Domain | Tag (ASCII) | Use |
|---|---|---|
| Decision | `decision` | signed kernel decisions |
| Capability | `capability` | reserved |
| Revocation | `revocation` | reserved |
| Consent | `consent` | reserved |
| AuditHead | `audit-head` | reserved |

In conformance input the domain is written as its tag. Any other string is `unknown_domain` (exact, case-sensitive match).

## Signed bytes

```
msg = "decision-os/v1/" || tag || 0x00 || payload
```

`payload` is the caller's bytes (for a decision: its JCS bytes, defined in the decision spec). Raw payload bytes are never signed. No tag contains `0x00`, so `(domain, payload) -> msg` is injective, and a signature for one domain never verifies under another. A future version changes the `v1` prefix.

## Key id

```
kid = lowercase_hex( SHA-256( "decision-os/v1/kid" || 0x00 || A )[0..16] )
```

`A` is the 32-byte canonical encoding of the public key. A kid is 32 lowercase hex characters.

For the fixed test key (RFC 8032 TEST 1, public key `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`) the kid is `b1f1515d964ca23d4f37283c507551d3`.

## Text encoding

Keys, kids and signatures are hex. Encoders write lowercase. Decoders accept lowercase only (`0-9a-f`). Anything else, or an odd length, is `bad_hex`. Valid hex of the wrong byte length (key 32, signature 64, kid 16) is `bad_length`.

## Public key checks

Applied when a public key is parsed, in this order:

1. The 32 bytes decompress to a point on the curve, else `invalid_key`.
2. The encoding is canonical: re-encoding the point gives the same 32 bytes (rejects y >= p and a set sign bit when x = 0), else `non_canonical_key`.
3. The point is not of small order (none of the 8 torsion points), else `weak_key`.

## Signature checks

A signature is `R || S` (32 + 32 bytes).

1. `S` is a canonical scalar, `S < L` (L = 2^252 + 27742317777372353535851937790883648493), else `non_canonical_signature`.
2. Strict verification (`ed25519-dalek` `verify_strict`): `R` is not of small order, and `[S]B = R + [k]A` with `k = SHA-512(R || A || msg)` and `R` compared as bytes (so a non-canonical `R` fails). Any failure is `bad_signature`.

## Kid check

If a verifier is given an expected kid, it MUST compute the kid of the key it uses and refuse a mismatch with `kid_mismatch`, before checking the signature.

## Error codes

`bad_hex`, `bad_length`, `invalid_key`, `non_canonical_key`, `weak_key`, `non_canonical_signature`, `bad_signature`, `kid_mismatch`, `unknown_domain`.

## Conformance input

All signing uses the fixed test key (`spec/CONFORMANCE.md`).

- `{"op":"sign","domain":"<tag>","payload_hex":"<hex>"}` -> `{"ok":{"sig":"<128 hex>","kid":"<32 hex>"}}`.
- `{"op":"verify","domain":"<tag>","payload_hex":"<hex>","sig":"<hex>"}` with optional `"public_key":"<hex>"` (default: the test key) and optional `"kid":"<hex>"` (expected kid) -> `{"ok":true}` or `{"error":"<code>"}`.
- `{"op":"kid","public_key":"<hex>"}` -> `{"ok":"<kid>"}` or `{"error":"<code>"}`.

Check order for `verify`: domain, payload hex, public key (hex, length, the three key checks), kid (hex, length, match), signature (hex, length, S, strict verify). The first failure is the result.

## Relation to the oracle

The oracle (`decision_os_min/kernel.py`) signs `json.dumps(sort_keys=True)` bytes of the decision with no domain tag, no `v` and no `kid`, and identifies the signer by the fixed string `issued_by`. Rust signatures are deliberately not compatible with oracle signatures (KNOWN_GAPS SG-9, DM-4): an oracle signature never verifies under this spec and the reverse, because every v1 message begins with `decision-os/v1/` and an oracle message begins with `{`.
