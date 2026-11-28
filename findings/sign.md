# Red team findings: sign (task/sign, bc9a265)

## First-pass hypotheses (written before reading design/sign.md and status/sign.md)

Inputs and trust boundary: public key bytes/hex (untrusted), signature bytes/hex (untrusted),
kid hex (untrusted), domain tag string (untrusted, conformance), payload bytes (untrusted),
secret key bytes (trusted, secret), build flags/environment (RUSTFLAGS, downstream build: platform).

Ranked by impact:

1. H1 Cross-domain: a signature for one domain verifies under another (tag prefix, separator in tag, from_tag variants). S0 if true.
2. H2 Message collision: two different (domain, payload) pairs give the same signed message. S0.
3. H3 Weak keys: any of the 8 torsion points, any non-canonical encoding of them (y >= p, x=0 sign bit), accepted as a key. S0 (universal forgery under identity key).
4. H4 Non-canonical encoding of a large-order key accepted (two encodings, two kids, one key). S1.
5. H5 Small-order / non-canonical / mixed-order R accepted; forged sig with R=identity S=0. S0.
6. H6 S malleability: S >= L, S+L, high bits accepted. S0 (replay under fresh sig bytes).
7. H7 Kid not binding the key: verify_with_kid checks after the signature, ignores it, or kid computed over attacker-controlled data / non-canonical bytes. S0.
8. H8 Non-strict verify reachable anywhere in non-test code. S0.
9. H9 Hex parser accepts uppercase, whitespace, 0x, odd length, unicode digits, '+'/'-'. S3 (encoding malleability of ids).
10. H10 Panic on any input: from_bytes, from_hex, verify, from_tag (fuzz). S2.
11. H11 Secret leak via Debug/Display/error/Clone/Copy of SigningKey. S1.
12. H12 Zeroize not happening on drop (or a copy left around by the wrapper). S3/S1.
13. H13 Fiat backend not selected in some build config (RUSTFLAGS set, cargo fuzz, downstream crate, other cwd, --release, --target). S3.
14. H14 Conformance test key accepted where it must not (any production path). S1.
15. H15 no_std build broken (std leaking in via deps/features). S2.
16. H16 Differential vs Python cryptography (OpenSSL): accept/reject differences on random and adversarial keys/sigs. Classify against spec.
17. H17 Spec check order violated (kid vs signature parse; key before kid). S3.
18. H18 Conformance harness fail-open (missing fields defaulting to accepting values). S3.
