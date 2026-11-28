//! Red team (findings/sign.md): time-bounded random fuzzing of dos_core::sign
//! with the same invariants as fuzz/fuzz_targets/*. Used because cargo-fuzz
//! could not run to completion (WSL down). Not coverage guided.
//! Replays fuzz/corpus/<target>/* first, then random + mutated inputs.
//!
//! Run: RT_FUZZ_SECS=320 cargo test -p dos-core --release --test redteam_sign_randfuzz -- --ignored --nocapture
//! Without RT_FUZZ_SECS each target runs 2 s (so the normal suite stays fast).

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use dos_core::sign::{
    Domain, Kid, Signature, SigningKey, VerifyingKey, hex_decode, hex_encode,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

fn budget() -> Duration {
    let secs = std::env::var("RT_FUZZ_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2);
    Duration::from_secs(secs)
}

fn corpus(target: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| std::fs::read(e.path()).ok())
        .collect()
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(5) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                if let Some(b) = v.get_mut(i) {
                    *b ^= 1 << rng.below(8);
                }
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                if let Some(b) = v.get_mut(i) {
                    *b = rng.byte();
                }
            }
            2 => v.push(rng.byte()),
            3 if !v.is_empty() => {
                let n = rng.below(v.len());
                v.truncate(n);
            }
            _ => {
                let interesting = [0u8, 0x7f, 0x80, 0xff, 0xed, 0xec, 0x10, b'0', b'a', b'f', b'g', b'A'];
                let i = rng.below(v.len() + 1);
                let b = interesting.get(rng.below(interesting.len())).copied().unwrap_or(0);
                v.insert(i, b);
            }
        }
    }
    v
}

fn take<const N: usize>(it: &mut std::slice::Iter<'_, u8>) -> [u8; N] {
    let mut a = [0u8; N];
    for b in a.iter_mut() {
        *b = it.next().copied().unwrap_or(0);
    }
    a
}

fn from_bytes_case(data: &[u8]) {
    let mut it = data.iter();
    let pk: [u8; 32] = take(&mut it);
    let sig: [u8; 64] = take(&mut it);
    let kid: [u8; 16] = take(&mut it);
    let dsel = it.next().copied().unwrap_or(0);
    let payload: Vec<u8> = it.copied().collect();
    let domain = Domain::ALL
        .get(usize::from(dsel) % Domain::ALL.len())
        .copied()
        .unwrap_or(Domain::Decision);
    let key = VerifyingKey::from_bytes(&pk);
    if key.is_ok() {
        let pt = CompressedEdwardsY(pk).decompress();
        assert!(pt.is_some_and(|p| p.compress().to_bytes() == pk && !p.is_small_order()));
    }
    let s = Signature::from_bytes(&sig);
    if s.is_ok() {
        let mut sb = [0u8; 32];
        for (o, b) in sb.iter_mut().zip(sig.iter().skip(32)) {
            *o = *b;
        }
        assert!(bool::from(Scalar::from_canonical_bytes(sb).is_some()));
    }
    if let (Ok(k), Ok(s)) = (key, s) {
        let ok = k.verify(domain, &payload, &s).is_ok();
        assert!(!ok, "random signature verified: {}", hex_encode(data));
        let r = k.verify_with_kid(domain, &payload, &s, &Kid::from_bytes(&kid));
        assert!(r.is_err());
    }
}

fn from_hex_case(data: &[u8]) {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(v) = hex_decode(s) {
        assert_eq!(hex_encode(&v), s);
    }
    if let Ok(k) = Kid::from_hex(s) {
        assert_eq!(k.to_hex(), s);
    }
    if let Ok(sig) = Signature::from_hex(s) {
        assert_eq!(sig.to_hex(), s);
    }
    if let Ok(vk) = VerifyingKey::from_hex(s) {
        assert_eq!(vk.to_hex(), s);
    }
    if let Ok(d) = Domain::from_tag(s) {
        assert_eq!(d.tag(), s);
    }
}

fn verify_case(data: &[u8]) {
    let mut it = data.iter();
    let secret: [u8; 32] = take(&mut it);
    let what = it.next().copied().unwrap_or(0);
    let pos = usize::from(u16::from_le_bytes([
        it.next().copied().unwrap_or(0),
        it.next().copied().unwrap_or(0),
    ]));
    let xor = it.next().copied().unwrap_or(0) | 1;
    let payload: Vec<u8> = it.copied().collect();
    let domain = Domain::ALL
        .get(usize::from(what >> 4) % Domain::ALL.len())
        .copied()
        .unwrap_or(Domain::Decision);
    let sk = SigningKey::from_bytes(&secret);
    let vk = sk.verifying_key();
    let sig = sk.sign(domain, &payload);
    assert!(vk.verify(domain, &payload, &sig).is_ok());
    match what % 4 {
        0 => {
            let mut b = sig.to_bytes();
            if let Some(x) = b.get_mut(pos % 64) {
                *x ^= xor;
            }
            if let Ok(s) = Signature::from_bytes(&b) {
                assert!(vk.verify(domain, &payload, &s).is_err());
            }
        }
        1 => {
            let mut b = vk.to_bytes();
            if let Some(x) = b.get_mut(pos % 32) {
                *x ^= xor;
            }
            if let Ok(k) = VerifyingKey::from_bytes(&b) {
                assert!(k.verify(domain, &payload, &sig).is_err());
            }
        }
        2 => {
            let mut p = payload.clone();
            if p.is_empty() {
                p.push(xor);
            } else {
                let i = pos % p.len();
                if let Some(x) = p.get_mut(i) {
                    *x ^= xor;
                }
            }
            assert!(vk.verify(domain, &p, &sig).is_err());
        }
        _ => {
            for d in Domain::ALL {
                if d != domain {
                    assert!(vk.verify(d, &payload, &sig).is_err());
                }
            }
        }
    }
}

fn run(target: &str, seed: u64, max_len: usize, case: fn(&[u8])) {
    let mut rng = Rng(seed);
    let seeds = corpus(target);
    let mut n = 0u64;
    for s in &seeds {
        case(s);
        n += 1;
    }
    let start = Instant::now();
    let deadline = budget();
    let mut pool = seeds;
    while start.elapsed() < deadline {
        for _ in 0..64 {
            let input = if !pool.is_empty() && rng.below(2) == 0 {
                let base = pool.get(rng.below(pool.len())).cloned().unwrap_or_default();
                mutate(&mut rng, &base)
            } else {
                let len = rng.below(max_len);
                rng.bytes(len)
            };
            case(&input);
            if pool.len() < 4096 && rng.below(64) == 0 {
                pool.push(input);
            }
            n += 1;
        }
    }
    println!(
        "{target}: {n} executions in {:.1}s (corpus replayed first)",
        start.elapsed().as_secs_f64()
    );
}

#[test]
#[ignore = "time-bounded fuzz; run with --ignored"]
fn randfuzz_sign_from_bytes() {
    run("sign_from_bytes", 0x0123_4567_89ab_cdef, 256, from_bytes_case);
}

#[test]
#[ignore = "time-bounded fuzz; run with --ignored"]
fn randfuzz_sign_from_hex() {
    run("sign_from_hex", 0x0fed_cba9_8765_4321, 200, from_hex_case);
}

#[test]
#[ignore = "time-bounded fuzz; run with --ignored"]
fn randfuzz_sign_verify() {
    run("sign_verify", 0x1357_9bdf_2468_ace0, 256, verify_case);
}

#[test]
fn randfuzz_smoke() {
    // A short non-ignored pass so these invariants run in the normal suite.
    for (t, s, l, f) in [
        ("sign_from_bytes", 1u64, 256usize, from_bytes_case as fn(&[u8])),
        ("sign_from_hex", 2, 200, from_hex_case),
        ("sign_verify", 3, 256, verify_case),
    ] {
        let mut rng = Rng(s);
        for _ in 0..300 {
            let len = rng.below(l);
            f(&rng.bytes(len));
        }
        let _ = t;
    }
}
