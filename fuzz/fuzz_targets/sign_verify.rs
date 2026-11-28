//! Sign with a fuzzed key, then apply one fuzzed mutation to key, signature,
//! payload or domain: the mutated input must never verify.
#![no_main]
use dos_core::sign::{Domain, Signature, SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 36 {
        return;
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&data[..32]);
    let what = data[32];
    let pos = usize::from(u16::from_le_bytes([data[33], data[34]]));
    let xor = data[35] | 1;
    let payload = &data[36..];
    let domain = Domain::ALL[usize::from(what >> 4) % Domain::ALL.len()];
    let sk = SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();
    let sig = sk.sign(domain, payload);
    assert!(vk.verify(domain, payload, &sig).is_ok());
    match what % 4 {
        0 => {
            let mut b = sig.to_bytes();
            b[pos % 64] ^= xor;
            if let Ok(s) = Signature::from_bytes(&b) {
                assert!(vk.verify(domain, payload, &s).is_err());
            }
        }
        1 => {
            let mut b = vk.to_bytes();
            b[pos % 32] ^= xor;
            if let Ok(k) = VerifyingKey::from_bytes(&b) {
                assert!(k.verify(domain, payload, &sig).is_err());
            }
        }
        2 => {
            if payload.is_empty() {
                let mut p = payload.to_vec();
                p.push(xor);
                assert!(vk.verify(domain, &p, &sig).is_err());
            } else {
                let mut p = payload.to_vec();
                let i = pos % p.len();
                p[i] ^= xor;
                assert!(vk.verify(domain, &p, &sig).is_err());
                p.truncate(i);
                assert!(vk.verify(domain, &p, &sig).is_err());
            }
        }
        _ => {
            for d in Domain::ALL {
                if d != domain {
                    assert!(vk.verify(d, payload, &sig).is_err());
                }
            }
        }
    }
});
