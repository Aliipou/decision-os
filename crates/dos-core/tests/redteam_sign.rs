//! Red team, task `sign` (findings/sign.md). New file; tests here are meant to
//! FAIL on the target when they demonstrate a finding, and PASS (as permanent
//! regression tests) when the hypothesis held.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use dos_core::sign::{
    Domain, Kid, SignError, Signature, SigningKey, VerifyingKey, hex_decode, hex_decode_array,
    hex_encode, signed_message,
};
use sha2::{Digest, Sha512};

const TEST1_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// L, little endian.
const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn test_key() -> Result<SigningKey, SignError> {
    Ok(SigningKey::from_bytes(&hex_decode_array::<32>(
        TEST1_SECRET,
    )?))
}

fn concat_sig(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (o, b) in out.iter_mut().zip(r.iter().chain(s.iter())) {
        *o = *b;
    }
    out
}

fn split_sig(sig: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    for (o, b) in r.iter_mut().zip(sig.iter()) {
        *o = *b;
    }
    for (o, b) in s.iter_mut().zip(sig.iter().skip(32)) {
        *o = *b;
    }
    (r, s)
}

/// Little-endian 256-bit add; returns None on overflow past 2^256.
fn add256(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for ((o, x), y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        let v = u16::from(*x) + u16::from(*y) + carry;
        *o = (v & 0xff) as u8;
        carry = v >> 8;
    }
    if carry == 0 { Some(out) } else { None }
}

/// p = 2^255 - 19, little endian.
fn p_le() -> [u8; 32] {
    let mut p = [0xffu8; 32];
    if let Some(f) = p.first_mut() {
        *f = 0xed;
    }
    if let Some(l) = p.last_mut() {
        *l = 0x7f;
    }
    p
}

/// Every 32-byte string that decodes (in some decoder) to `point`: canonical,
/// sign bit flipped, and y + p when y + p < 2^255, each with both sign bits.
fn all_encodings(point: &EdwardsPoint) -> Vec<[u8; 32]> {
    let canon = point.compress().to_bytes();
    let mut y = canon;
    if let Some(l) = y.last_mut() {
        *l &= 0x7f;
    }
    let mut out = Vec::new();
    let mut ys = vec![y];
    if let Some(yp) = add256(&y, &p_le())
        && yp.last().is_some_and(|l| *l & 0x80 == 0)
    {
        ys.push(yp);
    }
    for y in ys {
        for sign in [0u8, 0x80] {
            let mut e = y;
            if let Some(l) = e.last_mut() {
                *l |= sign;
            }
            out.push(e);
        }
    }
    out
}

// ---------- H1/H2: domain separation and message injectivity ----------

/// Parse a v1 signed message back into (domain, payload). If parsing is unique,
/// `(domain, payload) -> msg` is injective.
fn parse_signed(msg: &[u8]) -> Option<(Domain, Vec<u8>)> {
    let rest = msg.strip_prefix(b"decision-os/v1/")?;
    let nul = rest.iter().position(|b| *b == 0)?;
    let tag = core::str::from_utf8(rest.get(..nul)?).ok()?;
    let d = Domain::from_tag(tag).ok()?;
    Some((d, rest.get(nul + 1..)?.to_vec()))
}

#[test]
fn h1_signed_message_parses_back_uniquely() {
    let payloads: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        b"\x00decision".to_vec(),
        b"decision-os/v1/capability\x00x".to_vec(),
        b"-head\x00".to_vec(),
        vec![0xff; 40],
    ];
    for d in Domain::ALL {
        for p in &payloads {
            let m = signed_message(d, p);
            assert_eq!(parse_signed(&m), Some((d, p.clone())), "{d:?} {p:?}");
        }
    }
    // No tag is a prefix of another tag followed by NUL, no tag contains NUL,
    // and the kid hash input tag ("kid") is not a signing domain.
    for a in Domain::ALL {
        assert!(!a.tag().as_bytes().contains(&0));
        assert!(a.tag().is_ascii());
        assert_ne!(a.tag(), "kid");
        for b in Domain::ALL {
            if a != b {
                let mut ta = a.tag().as_bytes().to_vec();
                ta.push(0);
                assert!(!b.tag().as_bytes().starts_with(&ta));
            }
        }
    }
}

#[test]
fn h1_from_tag_rejects_variants() {
    for d in Domain::ALL {
        let t = d.tag();
        let variants = [
            t.to_uppercase(),
            format!("{t} "),
            format!(" {t}"),
            format!("{t}\0"),
            format!("{t}\n"),
            format!("decision-os/v1/{t}"),
            t.replace('-', "_"),
            t.replace('e', "\u{0435}"), // Cyrillic e
            format!("{t}\u{200b}"),     // zero width space
            String::from(t.get(..t.len() - 1).unwrap_or("")),
        ];
        for v in variants {
            if v != t {
                assert_eq!(Domain::from_tag(&v), Err(SignError::UnknownDomain), "{v:?}");
            }
        }
    }
}

#[test]
fn h1_cross_domain_with_shifted_payload_never_verifies() -> Result<(), SignError> {
    // Try to move bytes between tag and payload: sign (a, p) and verify (b, q)
    // where q is p with the tag difference shifted in or out.
    let sk = test_key()?;
    let vk = sk.verifying_key();
    for a in Domain::ALL {
        for b in Domain::ALL {
            if a == b {
                continue;
            }
            let p = b"{\"v\":1}".to_vec();
            let sig = sk.sign(a, &p);
            let mut q1 = a.tag().as_bytes().to_vec();
            q1.push(0);
            q1.extend_from_slice(&p);
            for q in [p.clone(), q1, signed_message(a, &p)] {
                assert_eq!(vk.verify(b, &q, &sig), Err(SignError::BadSignature));
            }
        }
    }
    Ok(())
}

// ---------- H3/H4: weak and non-canonical keys, every encoding ----------

/// Expected result for key bytes per spec/sign.md, computed independently of
/// the target: decompress, canonical re-encode, small order.
fn expected_key_result(e: &[u8; 32]) -> Result<(), SignError> {
    let Some(pt) = CompressedEdwardsY(*e).decompress() else {
        return Err(SignError::InvalidKey);
    };
    if pt.compress().to_bytes() != *e {
        return Err(SignError::NonCanonicalKey);
    }
    if pt.is_small_order() {
        return Err(SignError::WeakKey);
    }
    Ok(())
}

#[test]
fn h3_every_encoding_of_every_torsion_point_is_refused() {
    let mut tried = 0;
    for t in EIGHT_TORSION.iter() {
        for e in all_encodings(t) {
            tried += 1;
            let r = VerifyingKey::from_bytes(&e).map(|_| ());
            assert!(r.is_err(), "{} accepted", hex_encode(&e));
            assert_eq!(r, expected_key_result(&e), "{}", hex_encode(&e));
        }
    }
    // 8 points * 2 sign bits + (y=0, y=1) * y+p * 2 sign bits.
    assert!(tried >= 20, "{tried}");
}

#[test]
fn h4_every_encoding_with_y_below_19_matches_spec() {
    // The only y with a second encoding are y in 0..19 (y + p < 2^255).
    let mut non_canonical = 0;
    for y in 0u8..19 {
        let mut b = [0u8; 32];
        if let Some(f) = b.first_mut() {
            *f = y;
        }
        let Some(pt) = CompressedEdwardsY(b).decompress() else {
            continue;
        };
        for e in all_encodings(&pt) {
            let r = VerifyingKey::from_bytes(&e).map(|_| ());
            let want = expected_key_result(&e);
            if want == Err(SignError::NonCanonicalKey) {
                non_canonical += 1;
            }
            assert_eq!(r, want, "y={y} {}", hex_encode(&e));
        }
    }
    assert!(non_canonical >= 4, "{non_canonical}");
}

#[test]
fn h4_one_point_one_kid() -> Result<(), SignError> {
    // For every accepted key bytes, re-encoding is the identity, so a point has
    // exactly one kid. Check over many derived keys plus their bit flips.
    for i in 0u8..64 {
        let sk = SigningKey::from_bytes(&[i; 32]);
        let pk = sk.verifying_key().to_bytes();
        for bit in 0..256usize {
            let mut b = pk;
            if let Some(x) = b.get_mut(bit / 8) {
                *x ^= 1 << (bit % 8);
            }
            if let Ok(vk) = VerifyingKey::from_bytes(&b) {
                assert_eq!(vk.to_bytes(), b);
                assert_ne!(vk.kid(), sk.kid());
            }
        }
    }
    Ok(())
}

// ---------- H5: R variants ----------

#[test]
fn h5_r_plus_torsion_and_r_encodings_never_verify() -> Result<(), SignError> {
    let sk = test_key()?;
    let vk = sk.verifying_key();
    for msg in [&b""[..], b"x", b"{\"v\":1}"] {
        let sig = sk.sign(Domain::Decision, msg).to_bytes();
        let (r, s) = split_sig(&sig);
        let rp = CompressedEdwardsY(r)
            .decompress()
            .ok_or(SignError::BadSignature)?;
        for t in EIGHT_TORSION.iter().skip(1) {
            for e in all_encodings(&(rp + t)) {
                let forged = concat_sig(&e, &s);
                if let Ok(fs) = Signature::from_bytes(&forged) {
                    assert_eq!(
                        vk.verify(Domain::Decision, msg, &fs),
                        Err(SignError::BadSignature)
                    );
                }
            }
        }
        // R with sign bit flipped (the negated point).
        for e in all_encodings(&rp) {
            if e != r {
                let fs = Signature::from_bytes(&concat_sig(&e, &s))?;
                assert_eq!(
                    vk.verify(Domain::Decision, msg, &fs),
                    Err(SignError::BadSignature)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn h5_small_order_r_with_every_s_class_refused() -> Result<(), SignError> {
    // R a torsion point (every encoding), S in {0, 1, L-1}: never valid.
    let vk = test_key()?.verifying_key();
    let mut lm1 = L_LE;
    if let Some(f) = lm1.first_mut() {
        *f = 0xec;
    }
    let mut one = [0u8; 32];
    if let Some(f) = one.first_mut() {
        *f = 1;
    }
    for t in EIGHT_TORSION.iter() {
        for e in all_encodings(t) {
            for s in [[0u8; 32], one, lm1] {
                let fs = Signature::from_bytes(&concat_sig(&e, &s))?;
                for d in Domain::ALL {
                    assert_eq!(vk.verify(d, b"", &fs), Err(SignError::BadSignature));
                }
            }
        }
    }
    Ok(())
}

// ---------- H6: S malleability ----------

#[test]
fn h6_s_plus_k_l_refused_for_every_k() -> Result<(), SignError> {
    let sk = test_key()?;
    for msg in [&b""[..], b"a", b"bb", b"ccc"] {
        let sig = sk.sign(Domain::Decision, msg).to_bytes();
        let (r, mut s) = split_sig(&sig);
        let mut k = 0;
        while let Some(next) = add256(&s, &L_LE) {
            s = next;
            k += 1;
            assert_eq!(
                Signature::from_bytes(&concat_sig(&r, &s)),
                Err(SignError::NonCanonicalSignature),
                "S + {k}L"
            );
        }
        assert!(k >= 14, "{k}");
    }
    Ok(())
}

#[test]
fn h6_any_s_with_high_byte_bits_refused() {
    // 2^252 < L is canonical; 0x11 * 2^248 > L is not.
    let mut s = [0u8; 32];
    if let Some(l) = s.last_mut() {
        *l = 0x10;
    }
    assert!(Signature::from_bytes(&concat_sig(&[0u8; 32], &s)).is_ok());
    for hi in 0x11u8..=0xff {
        let mut s = [0u8; 32];
        if let Some(l) = s.last_mut() {
            *l = hi;
        }
        assert_eq!(
            Signature::from_bytes(&concat_sig(&[0u8; 32], &s)),
            Err(SignError::NonCanonicalSignature),
            "{hi:#x}"
        );
    }
}

// ---------- H7: kid binding ----------

#[test]
fn h7_kid_matches_spec_formula_and_binds_key() -> Result<(), SignError> {
    use sha2::Sha256;
    for i in 0u8..32 {
        let sk = SigningKey::from_bytes(&[i.wrapping_mul(7).wrapping_add(1); 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut h = Sha256::new();
        h.update(b"decision-os/v1/kid\x00");
        h.update(pk);
        let d = h.finalize();
        assert_eq!(sk.kid().to_hex(), hex_encode(d.get(..16).unwrap_or(&[])));
        assert_eq!(sk.kid().to_hex().len(), 32);
    }
    // A signature valid under key B, presented with key A and A's kid: refused.
    let a = test_key()?;
    let b = SigningKey::from_bytes(&[9u8; 32]);
    let sig_b = b.sign(Domain::Decision, b"m");
    assert_eq!(
        a.verifying_key()
            .verify_with_kid(Domain::Decision, b"m", &sig_b, &a.kid()),
        Err(SignError::BadSignature)
    );
    // Key B with A's kid: kid_mismatch even though the signature is valid.
    assert_eq!(
        b.verifying_key()
            .verify_with_kid(Domain::Decision, b"m", &sig_b, &a.kid()),
        Err(SignError::KidMismatch)
    );
    // Kid hex round trip is exact and case-strict.
    assert_eq!(Kid::from_hex(&a.kid().to_hex()), Ok(a.kid()));
    Ok(())
}

/// H17. spec/sign.md: "If a verifier is given an expected kid, it MUST compute
/// the kid of the key it uses and refuse a mismatch with kid_mismatch, before
/// checking the signature", and the check order puts kid before "signature
/// (hex, length, S, strict verify)". The public API cannot express this order:
/// `verify_with_kid` takes an already-parsed `Signature`, and `Signature` can
/// only be built after the S check. A caller using the library's only kid-aware
/// entry point gets `non_canonical_signature` where the spec requires
/// `kid_mismatch`. (The conformance test had to re-implement the kid check by
/// hand before parsing the signature.) Expected to FAIL on bc9a265.
#[test]
fn h17_wrong_kid_with_non_canonical_s_through_public_api_is_kid_mismatch() -> Result<(), SignError>
{
    let sk = test_key()?;
    let vk = sk.verifying_key();
    let wrong = Kid::from_bytes(&[0u8; 16]);
    let mut sig = sk.sign(Domain::Decision, b"x").to_bytes();
    if let Some(l) = sig.last_mut() {
        *l |= 0xe0;
    }
    let sig_hex = hex_encode(&sig);
    // The wire path applies the spec order: kid before the signature is parsed.
    let got = vk.verify_wire(Domain::Decision, b"x", Some(&wrong.to_hex()), &sig_hex);
    assert_eq!(
        got,
        Err(SignError::KidMismatch),
        "spec check order: kid before S"
    );
    // The two-step typed path still refuses the signature first (documented on verify_wire).
    let typed = Signature::from_hex(&sig_hex)
        .and_then(|s| vk.verify_with_kid(Domain::Decision, b"x", &s, &wrong));
    assert_eq!(typed, Err(SignError::NonCanonicalSignature));
    Ok(())
}

// ---------- H9: hex ----------

#[test]
fn h9_hex_rejects_every_non_lowercase_form() {
    let bad = [
        "0A",
        "A0",
        "0x00",
        "0X00",
        "+0",
        "-0",
        " 0",
        "0 ",
        "00\n",
        "\t0",
        "0\u{0}",
        "\u{ff10}\u{ff10}", // fullwidth digits
        "\u{0660}\u{0660}", // arabic-indic digits
        "\u{00e9}",         // 2 bytes, one char
        "g0",
        "0g",
        "z",
        "..",
        "0_",
        "1,",
        "\u{1d7ce}0",
        "%0",
        "ab\r",
    ];
    for s in bad {
        assert_eq!(hex_decode(s), Err(SignError::BadHex), "{s:?}");
    }
    // Odd length with valid chars is bad_hex, not bad_length.
    assert_eq!(Kid::from_hex(&"0".repeat(31)), Err(SignError::BadHex));
    assert_eq!(
        Signature::from_hex(&"0".repeat(127)),
        Err(SignError::BadHex)
    );
    assert_eq!(
        VerifyingKey::from_hex(&"0".repeat(63)),
        Err(SignError::BadHex)
    );
    // Every accepted string is exactly the canonical encoding of its bytes.
    for b in 0u8..=255 {
        for c in 0u8..=255 {
            let s: String = [char::from(b), char::from(c)].iter().collect();
            if let Ok(v) = hex_decode(&s) {
                assert_eq!(hex_encode(&v), s);
            }
        }
    }
}

// ---------- H10: no panic on structured extremes ----------

#[test]
fn h10_no_panic_on_extreme_inputs() -> Result<(), SignError> {
    let sk = test_key()?;
    let vk = sk.verifying_key();
    let big = vec![0xa5u8; 1 << 20];
    let sig = sk.sign(Domain::AuditHead, &big);
    assert_eq!(vk.verify(Domain::AuditHead, &big, &sig), Ok(()));
    let long_hex = "0".repeat(1 << 16);
    let _ = hex_decode(&long_hex);
    let _ = Signature::from_hex(&long_hex);
    let _ = VerifyingKey::from_hex(&long_hex);
    let _ = Kid::from_hex(&long_hex);
    for b in [[0u8; 64], [0xffu8; 64]] {
        let _ = Signature::from_bytes(&b);
    }
    for b in [[0u8; 32], [0xffu8; 32], [0x80u8; 32]] {
        let _ = VerifyingKey::from_bytes(&b);
    }
    Ok(())
}

// ---------- H11: secrets ----------

#[test]
fn h11_debug_does_not_print_secret_or_expanded_secret() -> Result<(), SignError> {
    let secret = hex_decode_array::<32>(TEST1_SECRET)?;
    let sk = SigningKey::from_bytes(&secret);
    let dbg = format!("{sk:?}|{sk:#?}");
    let h = Sha512::digest(secret);
    let mut needles: Vec<String> = vec![hex_encode(&secret), hex_encode(h.as_slice())];
    // Decimal and hex byte lists as printed by derived Debug of arrays.
    for chunk in [secret.get(..4), h.get(..4), h.get(32..36)]
        .into_iter()
        .flatten()
    {
        needles.push(format!("{chunk:?}").trim_matches(['[', ']']).to_string());
        needles.push(hex_encode(chunk));
    }
    for n in needles {
        assert!(!dbg.contains(&n), "{n} in {dbg}");
    }
    Ok(())
}

/// SigningKey must not be Clone or Copy. This fails to COMPILE if either is
/// implemented (ambiguous impl), which counts as a failing test.
#[test]
fn h11_signing_key_is_not_clone_or_copy() {
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    struct IsClone;
    impl<T: ?Sized + Clone> AmbiguousIfClone<IsClone> for T {}
    <SigningKey as AmbiguousIfClone<_>>::check();
}

// ---------- H14: conformance test key ----------

#[test]
fn h14_test_key_detection_is_exact() -> Result<(), SignError> {
    let vk = test_key()?.verifying_key();
    assert!(vk.is_conformance_test_key());
    // No other key (including bit neighbours that parse) is flagged.
    let pk = vk.to_bytes();
    for bit in 0..256usize {
        let mut b = pk;
        if let Some(x) = b.get_mut(bit / 8) {
            *x ^= 1 << (bit % 8);
        }
        if let Ok(k) = VerifyingKey::from_bytes(&b) {
            assert!(!k.is_conformance_test_key());
        }
    }
    Ok(())
}

// ---------- H16 support: mixed-order key (spec allows) ----------

/// Mixed-order keys A = aB + T are not small order, so the spec accepts them.
/// A signature by `a` for A never verifies under A + T. A malicious holder of a
/// mixed-order key can still sign (when k*T = 0); that is the holder's own key.
#[test]
fn h16_mixed_order_key_accepted_but_not_substitutable() -> Result<(), SignError> {
    let a = Scalar::from_bytes_mod_order([7u8; 32]);
    let pub_a = ED25519_BASEPOINT_POINT * a;
    let honest_bytes = pub_a.compress().to_bytes();
    let honest = VerifyingKey::from_bytes(&honest_bytes)?;
    for t in EIGHT_TORSION.iter().skip(1) {
        let mixed = (pub_a + t).compress().to_bytes();
        let vk = VerifyingKey::from_bytes(&mixed)?; // accepted per spec
        assert_ne!(vk.kid(), honest.kid());
        // Craft a cofactorless-valid signature under the mixed key.
        let msg = b"m";
        let full = signed_message(Domain::Decision, msg);
        let mut found = false;
        for i in 1u8..=255 {
            let r = Scalar::from_bytes_mod_order([i; 32]);
            let rb = (ED25519_BASEPOINT_POINT * r).compress().to_bytes();
            let mut h = Sha512::new();
            h.update(rb);
            h.update(mixed);
            h.update(&full);
            let mut wide = [0u8; 64];
            for (o, b) in wide.iter_mut().zip(h.finalize().iter()) {
                *o = *b;
            }
            let k = Scalar::from_bytes_mod_order_wide(&wide);
            if !(t * k).is_identity() {
                continue;
            }
            let s = r + k * a;
            let sig = Signature::from_bytes(&concat_sig(&rb, &s.to_bytes()))?;
            assert_eq!(vk.verify(Domain::Decision, msg, &sig), Ok(()));
            // Same signature is not valid under the honest key.
            assert_eq!(
                honest.verify(Domain::Decision, msg, &sig),
                Err(SignError::BadSignature)
            );
            found = true;
            break;
        }
        assert!(found);
    }
    Ok(())
}
