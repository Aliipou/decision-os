//! Red-team tests: exhaustive mutation, replay, stripping, multi-process, hostile input.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use dos_audit::*;
use dos_core::sign::{Domain, SigningKey, hex_encode};
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
    let d = std::env::temp_dir().join(format!("dos-audit-rt-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.log")
}

fn fill(path: &PathBuf, n: usize) -> FileSink {
    let sink = FileSink::open(path, &SECRET).unwrap();
    for i in 0..n {
        let e = format!(r#"{{"actor":"a","tool":"t{i}","verdict":"ALLOW"}}"#);
        sink.append(e.as_bytes()).unwrap();
    }
    sink
}

fn strict(bytes: &[u8], anchor: Option<Head>) -> Result<Verified, VerifyError> {
    let k = keys();
    verify_bytes(
        bytes,
        &VerifyOptions {
            keys: &k,
            now_unix_ms: 0,
            python_compat: false,
            anchor,
        },
    )
}

fn lines_of(b: &[u8]) -> Vec<String> {
    String::from_utf8(b.to_vec())
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

fn rehash(mut v: serde_json::Value) -> String {
    v.as_object_mut().unwrap().remove("entry_hash");
    let h = hex_encode(&Sha256::digest(ser(&v).as_bytes()));
    v["entry_hash"] = h.into();
    ser(&v)
}

fn anchored(name: &str) -> (PathBuf, Vec<u8>, Head) {
    let p = tmp(name);
    let s = fill(&p, 3);
    let head = s.head().unwrap().unwrap();
    (p.clone(), std::fs::read(&p).unwrap(), head)
}

#[test]
fn every_single_bit_mutation_is_detected() {
    let (_p, orig, head) = anchored("bytes");
    assert!(strict(&orig, Some(head.clone())).is_ok());
    for i in 0..orig.len() {
        for bit in [0x01u8, 0x20] {
            let mut b = orig.clone();
            b[i] ^= bit;
            assert!(
                strict(&b, Some(head.clone())).is_err(),
                "mutation at byte {i} bit {bit:#x} was not detected"
            );
        }
    }
}

#[test]
fn every_prefix_is_detected_and_extensions_refused() {
    let (_p, orig, head) = anchored("prefix");
    for n in 0..orig.len() {
        assert!(
            strict(&orig[..n], Some(head.clone())).is_err(),
            "prefix {n} verified"
        );
    }
    let last = lines_of(&orig).last().unwrap().clone();
    for extra in [format!("{last}\n"), "{}\n".to_string()] {
        let mut b = orig.clone();
        b.extend_from_slice(extra.as_bytes());
        assert!(strict(&b, None).is_err());
    }
}

#[test]
fn every_permutation_and_removal_is_detected() {
    let (_p, orig, head) = anchored("perm");
    let l = lines_of(&orig);
    for perm in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let b: String = perm.iter().map(|i| format!("{}\n", l[*i])).collect();
        assert!(strict(b.as_bytes(), Some(head.clone())).is_err());
    }
    for skip in 0..3 {
        let b: String = l
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, x)| format!("{x}\n"))
            .collect();
        assert!(strict(b.as_bytes(), Some(head.clone())).is_err());
    }
}

#[test]
fn signature_cannot_be_replayed_across_entries() {
    let (_p, orig, _) = anchored("replay");
    let l = lines_of(&orig);
    let a: serde_json::Value = serde_json::from_str(&l[0]).unwrap();
    let mut b: serde_json::Value = serde_json::from_str(&l[1]).unwrap();
    b["sig"] = a["sig"].clone();
    let log = format!("{}\n{}\n", l[0], rehash(b));
    assert_eq!(
        strict(log.as_bytes(), None).unwrap_err().kind,
        VerifyErrorKind::BadSignature
    );
}

#[test]
fn signature_from_another_domain_is_rejected() {
    let sk = SigningKey::from_bytes(&SECRET);
    let payload = br#"{"a":1}"#;
    for d in Domain::ALL {
        if d == Domain::AuditHead {
            continue;
        }
        let sig = sk.sign(d, payload);
        assert!(
            sk.verifying_key()
                .verify(Domain::AuditHead, payload, &sig)
                .is_err()
        );
    }
}

#[test]
fn stripping_signature_and_rehashing_is_refused_in_strict_mode() {
    let (_p, orig, _) = anchored("strip");
    let mut v: serde_json::Value = serde_json::from_str(&lines_of(&orig)[0]).unwrap();
    for k in ["sig", "kid"] {
        v.as_object_mut().unwrap().remove(k);
    }
    let log = format!("{}\n", rehash(v));
    assert_eq!(
        strict(log.as_bytes(), None).unwrap_err().kind,
        VerifyErrorKind::MissingSignature
    );
}

#[test]
fn sink_follows_the_disk_not_a_cache() {
    // Replace the log by another of the same length between two appends from one sink.
    let p = tmp("swap");
    let s = fill(&p, 2);
    let q = tmp("swap-other");
    // same shape and length, different content (so a different chain)
    let sq = FileSink::open(&q, &SECRET).unwrap();
    for i in 0..2 {
        sq.append(format!(r#"{{"actor":"a","tool":"u{i}","verdict":"ALLOW"}}"#).as_bytes())
            .unwrap();
    }
    let other = std::fs::read(&q).unwrap();
    assert_ne!(other, std::fs::read(&p).unwrap());
    assert_eq!(other.len(), std::fs::read(&p).unwrap().len());
    std::fs::write(&p, &other).unwrap();
    // The sink reads the disk, not a cache: it sees a log that does not match its anchor and
    // refuses to continue it, leaving the file as it found it.
    assert_eq!(s.append(b"{}"), Err(StoreError::Unavailable));
    assert_eq!(std::fs::read(&p).unwrap(), other);
}

#[test]
fn child_appender() {
    // Does nothing unless run as a child of `multiple_processes_append`.
    let Ok(path) = std::env::var("DOS_AUDIT_CHILD_LOG") else {
        return;
    };
    let s = FileSink::open(&path, &SECRET).unwrap();
    for i in 0..25 {
        s.append(format!(r#"{{"child":{i}}}"#).as_bytes()).unwrap();
    }
}

#[test]
fn multiple_processes_append() {
    let p = tmp("procs");
    let exe = std::env::current_exe().unwrap();
    let kids: Vec<_> = (0..3)
        .map(|_| {
            std::process::Command::new(&exe)
                .args(["child_appender", "--exact", "--test-threads=1"])
                .env("DOS_AUDIT_CHILD_LOG", &p)
                .spawn()
                .unwrap()
        })
        .collect();
    for mut k in kids {
        assert!(k.wait().unwrap().success());
    }
    let v = strict(&std::fs::read(&p).unwrap(), None).unwrap();
    assert_eq!(v.entries, 75);
}

#[test]
fn hostile_inputs_never_panic() {
    let deep = format!("{}1{}\n", "[".repeat(5000), "]".repeat(5000));
    let k = keys();
    for b in [
        &b"\xff\xfe\n"[..],
        b"\n\n\n",
        b"{",
        b"null\n",
        b"[]\n",
        b"{\"seq\":-1}\n",
        b"{\"seq\":1e400}\n",
        b"{\"seq\":0,\"prev_hash\":1}\n",
        deep.as_bytes(),
        b"\xef\xbb\xbf{}\n",
        &[0u8; 100],
    ] {
        assert!(strict(b, None).is_err());
        let o = VerifyOptions {
            keys: &k,
            now_unix_ms: 0,
            python_compat: true,
            anchor: None,
        };
        let _ = verify_bytes(b, &o);
    }
}

#[test]
fn sink_refuses_hostile_input_without_writing() {
    let p = tmp("hostile-in");
    let s = FileSink::open(&p, &SECRET).unwrap();
    let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
    for b in [
        &b""[..],
        b"\xff",
        b"{\"kid\":\"x\"}",
        b"{\"a\":1e999}",
        deep.as_bytes(),
        b"{} {}",
    ] {
        assert_eq!(s.append(b), Err(StoreError::InvalidInput));
    }
    assert_eq!(std::fs::read(&p).unwrap().len(), 0);
    // the head is still genesis and the next append is seq 0
    assert_eq!(s.append(b"{}").unwrap().seq, 0);
}

/// Sort object keys recursively. Other workspace crates (dos-install) enable serde_json's
/// `preserve_order`, so serialisation order cannot be assumed.
fn sorted(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(x) = m.get(k) {
                    out.insert(k.clone(), sorted(x));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn ser(v: &serde_json::Value) -> String {
    serde_json::to_string(&sorted(v)).unwrap()
}
