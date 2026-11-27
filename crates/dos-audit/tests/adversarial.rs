//! Deliberate attempts to break the log: randomized multi-mutation, Windows line endings,
//! read-only files, oversized entries, odd JSON in entries, head() during appends.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::sync::Arc;

use dos_audit::*;
use dos_core::sign::{SigningKey, hex_encode};
use dos_core::store::{AuditSink, KeyStore, StoreError};
use sha2::{Digest, Sha256};

const SECRET: [u8; 32] = [7u8; 32];

struct Keys(Vec<(String, [u8; 32])>);
impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(self.0.iter().find(|(k, _)| k == kid).map(|(_, v)| *v))
    }
}
fn keys() -> Keys {
    let sk = SigningKey::from_bytes(&SECRET);
    Keys(vec![(sk.kid().to_hex(), sk.verifying_key().to_bytes())])
}
fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dos-audit-adv-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.log")
}
fn opts<'a>(k: &'a Keys, compat: bool, anchor: Option<Head>) -> VerifyOptions<'a> {
    VerifyOptions {
        keys: k,
        now_unix_ms: 0,
        python_compat: compat,
        anchor,
    }
}

/// xorshift64*: deterministic, no dependency.
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

fn anchored_log(name: &str, n: usize) -> (Vec<u8>, Head) {
    let p = tmp(name);
    let s = FileSink::open(&p, &SECRET).unwrap();
    for i in 0..n {
        s.append(format!(r#"{{"actor":"a","tool":"t{i}","verdict":"ALLOW"}}"#).as_bytes())
            .unwrap();
    }
    (std::fs::read(&p).unwrap(), s.head().unwrap().unwrap())
}

#[test]
fn random_multi_mutations_never_verify_against_the_anchor() {
    let k = keys();
    let (orig, head) = anchored_log("rand", 6);
    assert!(verify_bytes(&orig, &opts(&k, false, Some(head.clone()))).is_ok());
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for round in 0..3000 {
        let mut b = orig.clone();
        let steps = 1 + rng.below(4);
        for _ in 0..steps {
            match rng.below(6) {
                0 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    b[i] = rng.next() as u8;
                }
                1 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    b.remove(i);
                }
                2 => {
                    let i = rng.below(b.len() + 1);
                    b.insert(i, rng.next() as u8);
                }
                3 => {
                    // duplicate or drop a whole line
                    let mut lines: Vec<Vec<u8>> =
                        b.split(|c| *c == b'\n').map(<[u8]>::to_vec).collect();
                    if lines.len() > 1 {
                        let i = rng.below(lines.len() - 1);
                        if rng.below(2) == 0 {
                            lines.insert(i, lines[i].clone());
                        } else {
                            lines.remove(i);
                        }
                        b = lines.join(&b'\n');
                    }
                }
                4 => {
                    let mut lines: Vec<Vec<u8>> =
                        b.split(|c| *c == b'\n').map(<[u8]>::to_vec).collect();
                    if lines.len() > 2 {
                        let (i, j) = (rng.below(lines.len() - 1), rng.below(lines.len() - 1));
                        lines.swap(i, j);
                        b = lines.join(&b'\n');
                    }
                }
                _ => {
                    let n = rng.below(b.len() + 1);
                    b.truncate(n);
                }
            }
        }
        if b == orig {
            continue;
        }
        for compat in [false, true] {
            // Strict must never accept a mutated log. Compat may accept benign whitespace
            // changes, but never one that changes entries: check strict only for equality.
            let r = verify_bytes(&b, &opts(&k, compat, Some(head.clone())));
            if !compat {
                assert!(r.is_err(), "round {round}: mutated log verified: {b:?}");
            }
        }
    }
}

#[test]
fn crlf_logs_from_python_on_windows_verify_in_compat_and_extend() {
    // Python text-mode append on Windows writes \r\n. The chain hash is unaffected.
    let k = keys();
    let p = tmp("crlf");
    let h0 = {
        let hashed = format!(r#"{{"actor":"x","prev_hash":"{GENESIS}","seq":0}}"#);
        hex_encode(&Sha256::digest(hashed.as_bytes()))
    };
    let line =
        format!(r#"{{"seq": 0, "actor": "x", "prev_hash": "{GENESIS}", "entry_hash": "{h0}"}}"#);
    std::fs::write(&p, format!("{line}\r\n")).unwrap();
    assert!(verify_file(&p, &opts(&k, true, None)).is_ok());
    assert!(verify_file(&p, &opts(&k, false, None)).is_err());
    // A tail that ends in \r\n: the sink must either continue or refuse, never corrupt.
    let s = FileSink::open(&p, &SECRET).unwrap();
    match s.append(b"{}") {
        Ok(r) => {
            assert_eq!(r.seq, 1);
            assert!(verify_file(&p, &opts(&k, true, None)).is_ok());
        }
        Err(e) => assert_eq!(e, StoreError::Unavailable),
    }
}

#[test]
fn read_only_log_refuses_and_writes_nothing() {
    let p = tmp("ro");
    let s = FileSink::open(&p, &SECRET).unwrap();
    s.append(b"{}").unwrap();
    let before = std::fs::read(&p).unwrap();
    let original = std::fs::metadata(&p).unwrap().permissions();
    let mut ro = original.clone();
    ro.set_readonly(true);
    std::fs::set_permissions(&p, ro).unwrap();
    let r = s.append(b"{}");
    std::fs::set_permissions(&p, original).unwrap();
    assert_eq!(r, Err(StoreError::Unavailable));
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

#[test]
fn deleted_log_is_not_silently_recreated_by_append() {
    // If an attacker deletes the log, append must fail (or the anchor will expose it);
    // it must not start a fresh chain that verifies against nothing.
    let k = keys();
    let p = tmp("deleted");
    let s = FileSink::open(&p, &SECRET).unwrap();
    s.append(b"{}").unwrap();
    s.append(b"{}").unwrap();
    std::fs::remove_file(&p).unwrap();
    let r = s.append(b"{}");
    assert_eq!(r, Err(StoreError::Unavailable));
    let mut a = p.as_os_str().to_os_string();
    a.push(".anchor");
    let v = verify_file_with_anchor_file(&p, &PathBuf::from(a), opts(&k, false, None));
    assert!(v.is_err());
}

#[test]
fn oversized_entry_is_refused() {
    let p = tmp("big");
    let s = FileSink::open(&p, &SECRET).unwrap();
    let big = format!(r#"{{"blob":"{}"}}"#, "x".repeat(2 << 20));
    assert_eq!(s.append(big.as_bytes()), Err(StoreError::InvalidInput));
    assert_eq!(std::fs::read(&p).unwrap().len(), 0);
}

#[test]
fn odd_but_valid_entries_round_trip() {
    let k = keys();
    let p = tmp("odd");
    let s = FileSink::open(&p, &SECRET).unwrap();
    let entries = [
        r#"{}"#,
        r#"{"a":null,"b":true,"c":false,"d":[],"e":{},"f":[1,2,{"g":"h"}]}"#,
        r#"{"u":"café 😀   \u0000 \u001f \" \\ /"}"#,
        r#"{"n":[0,-0,1e21,1.5,4.9e-324,9007199254740991,-9007199254740991]}"#,
        r#"{"kéy":1,"😀":2,"a":3}"#,
        r#"{"seq_":1,"prev":2,"sig_":3,"nested":{"seq":9,"entry_hash":"x","sig":"y","kid":"z"}}"#,
    ];
    for e in entries {
        s.append(e.as_bytes()).unwrap();
    }
    let v = verify_file(&p, &opts(&k, false, None)).unwrap();
    assert_eq!(v.entries, entries.len() as u64);
}

#[test]
fn entries_the_canonical_form_cannot_carry_are_refused_not_corrupted() {
    let p = tmp("refused");
    let s = FileSink::open(&p, &SECRET).unwrap();
    for e in [
        r#"{"n":9007199254740993}"#,
        r#"{"n":1e999}"#,
        r#"{"s":"\ud800"}"#,
        r#"{"s":"﷐"}"#,
        r#"{"a":1,"a":2}"#,
    ] {
        assert_eq!(s.append(e.as_bytes()), Err(StoreError::InvalidInput), "{e}");
    }
    assert_eq!(std::fs::read(&p).unwrap().len(), 0);
    assert_eq!(s.append(b"{}").unwrap().seq, 0);
}

#[test]
fn head_during_concurrent_appends_is_always_consistent() {
    let p = tmp("headrace");
    let s = Arc::new(FileSink::open(&p, &SECRET).unwrap());
    let w = s.clone();
    let writer = std::thread::spawn(move || {
        for i in 0..80 {
            w.append(format!(r#"{{"i":{i}}}"#).as_bytes()).unwrap();
        }
    });
    let mut last = 0u64;
    for _ in 0..400 {
        if let Some(h) = s.head().unwrap() {
            assert!(h.seq >= last, "head went backwards");
            last = h.seq;
        }
    }
    writer.join().unwrap();
    assert_eq!(s.head().unwrap().unwrap().seq, 79);
}

#[test]
fn anchor_cannot_be_used_as_an_entry_signature() {
    // The head signature and an entry signature share a domain; their payloads must never
    // be interchangeable: an entry payload always has prev_hash, a head payload never does.
    let p = tmp("xdomain");
    let s = FileSink::open(&p, &SECRET).unwrap();
    s.append(b"{}").unwrap();
    s.append(b"{}").unwrap();
    let mut a = p.as_os_str().to_os_string();
    a.push(".anchor");
    let anchor: serde_json::Value =
        serde_json::from_slice(&std::fs::read(PathBuf::from(a)).unwrap()).unwrap();
    // Put the anchor's signature into entry 1 and rehash: must fail as bad_signature.
    let text = std::fs::read_to_string(&p).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let mut e: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    e["sig"] = anchor["sig"].clone();
    e.as_object_mut().unwrap().remove("entry_hash");
    let h = hex_encode(&Sha256::digest(
        serde_json::to_string(&e).unwrap().as_bytes(),
    ));
    e["entry_hash"] = h.into();
    lines[1] = serde_json::to_string(&e).unwrap();
    let k = keys();
    let log = format!("{}\n{}\n", lines[0], lines[1]);
    let r = verify_bytes(log.as_bytes(), &opts(&k, false, None));
    assert_eq!(r.unwrap_err().kind, VerifyErrorKind::BadSignature);
}
