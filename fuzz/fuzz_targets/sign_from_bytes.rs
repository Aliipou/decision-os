//! Arbitrary key, signature and payload bytes: no panic, and any acceptance
//! must satisfy every spec check (independently recomputed).
#![no_main]
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use dos_core::sign::{Domain, Kid, Signature, VerifyingKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut pk = [0u8; 32];
    let mut sig = [0u8; 64];
    let mut kid = [0u8; 16];
    let mut it = data.iter();
    for b in pk.iter_mut().chain(sig.iter_mut()).chain(kid.iter_mut()) {
        *b = it.next().copied().unwrap_or(0);
    }
    let dsel = it.next().copied().unwrap_or(0);
    let payload: Vec<u8> = it.copied().collect();
    let domain = Domain::ALL[usize::from(dsel) % Domain::ALL.len()];

    let key = VerifyingKey::from_bytes(&pk);
    if key.is_ok() {
        let pt = CompressedEdwardsY(pk).decompress();
        assert!(pt.is_some_and(|p| p.compress().to_bytes() == pk && !p.is_small_order()));
    }
    let s = Signature::from_bytes(&sig);
    if s.is_ok() {
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&sig[32..]);
        assert!(bool::from(Scalar::from_canonical_bytes(sb).is_some()));
    }
    if let (Ok(k), Ok(s)) = (key, s) {
        let ok = k.verify(domain, &payload, &s).is_ok();
        let r = k.verify_with_kid(domain, &payload, &s, &Kid::from_bytes(&kid));
        if Kid::from_bytes(&kid) != k.kid() {
            assert!(r.is_err());
        } else {
            assert_eq!(r.is_ok(), ok);
        }
        if ok {
            for d in Domain::ALL {
                if d != domain {
                    assert!(k.verify(d, &payload, &s).is_err());
                }
            }
        }
    }
});
