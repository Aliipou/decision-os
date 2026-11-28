//! Stand-in for the libFuzzer target (which needs nightly): deterministic pseudo-random
//! and JSON-shaped garbage through the verifier and the sink. Nothing may panic or hang,
//! and nothing but the real log may verify.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use dos_audit::*;
use dos_core::store::{AuditSink, KeyStore, StoreError};

struct NoKeys;
impl KeyStore for NoKeys {
    fn verifying_key(&self, _: &str, _: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(None)
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const FRAGMENTS: [&str; 24] = [
    "{",
    "}",
    "[",
    "]",
    "\"",
    ",",
    ":",
    "\n",
    "\r\n",
    "seq",
    "prev_hash",
    "entry_hash",
    "sig",
    "kid",
    "0",
    "-1",
    "1e999",
    "9007199254740993",
    "null",
    "true",
    "\\u0000",
    "\\ud800",
    "é😀",
    "{\"seq\":0}",
];

fn garbage(rng: &mut Rng) -> Vec<u8> {
    if rng.below(3) == 0 {
        let n = rng.below(300);
        (0..n).map(|_| rng.next() as u8).collect()
    } else {
        let mut s = String::new();
        for _ in 0..rng.below(40) {
            s.push_str(FRAGMENTS[rng.below(FRAGMENTS.len())]);
        }
        s.into_bytes()
    }
}

#[test]
fn random_garbage_never_panics_and_never_verifies() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..20_000 {
        let b = garbage(&mut rng);
        for compat in [false, true] {
            let o = VerifyOptions {
                keys: &NoKeys,
                now_unix_ms: 0,
                python_compat: compat,
                anchor: None,
            };
            if let Ok(v) = verify_bytes(&b, &o) {
                // Only the empty log (or blank lines in compat mode) can verify keyless.
                assert_eq!(v.entries, 0, "garbage verified: {b:?}");
            }
        }
    }
}

#[test]
fn random_garbage_as_a_log_file_makes_the_sink_refuse_not_panic() {
    let d = std::env::temp_dir().join(format!("dos-audit-rb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("audit.log");
    let sink = FileSink::open(&p, &[7u8; 32]).unwrap();
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for _ in 0..1500 {
        let b = garbage(&mut rng);
        std::fs::write(&p, &b).unwrap();
        let r = sink.append(b"{}");
        if !b.is_empty() {
            assert!(r.is_err(), "sink appended to garbage: {b:?}");
            assert_eq!(std::fs::read(&p).unwrap(), b, "garbage log was modified");
        }
        let _ = sink.head();
        let _ = sink.repair_torn_tail();
    }
}
