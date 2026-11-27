//! Interop with the Python gateway's `LockedHashLog` (oracle/decision-os-min/.../gateway/audit.py):
//! same chain, same lock file, last-line head read, Python-written tails.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

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

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dos-audit-io-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.jsonl")
}

/// One line the way Python's `json.dumps(entry)` writes it, with its Python hash.
fn python_line(seq: u64, prev: &str, actor: &str, escaped_actor: &str) -> (String, String) {
    let hashed = format!(
        r#"{{"actor":"{escaped_actor}","executed":null,"payload_digest":null,"prev_hash":"{prev}","reason":"ok","seq":{seq},"tool":"t","ts":"2026-01-01T00:00:00+00:00","verdict":"ALLOW"}}"#
    );
    let h = hex_encode(&Sha256::digest(hashed.as_bytes()));
    let _ = actor;
    let line = format!(
        r#"{{"seq": {seq}, "ts": "2026-01-01T00:00:00+00:00", "actor": "{escaped_actor}", "tool": "t", "verdict": "ALLOW", "reason": "ok", "executed": null, "payload_digest": null, "prev_hash": "{prev}", "entry_hash": "{h}"}}"#
    );
    (line, h)
}

#[test]
fn rust_continues_a_python_log_with_non_ascii_tail() {
    let p = tmp("nonascii");
    let (l0, h0) = python_line(0, GENESIS, "x", "x");
    let (l1, _) = python_line(1, &h0, "caf\u{e9}", r"café 😀");
    std::fs::write(&p, format!("{l0}\n{l1}\n")).unwrap();
    let s = FileSink::open(&p, &SECRET).unwrap().adopt_unanchored(true);
    assert_eq!(s.append(br#"{"actor":"rust"}"#).unwrap().seq, 2);
    let sk = SigningKey::from_bytes(&SECRET);
    let keys = Keys(vec![(sk.kid().to_hex(), sk.verifying_key().to_bytes())]);
    let o = VerifyOptions {
        keys: &keys,
        now_unix_ms: 0,
        python_compat: true,
        anchor: None,
    };
    assert_eq!(verify_file(&p, &o).unwrap().entries, 3);
}

#[test]
fn python_head_read_accepts_rust_lines() {
    // Python's LockedHashLog reads the last line and needs `seq` and `entry_hash` as plain JSON.
    let p = tmp("pyhead");
    let s = FileSink::open(&p, &SECRET).unwrap();
    s.append(br#"{"actor":"a"}"#).unwrap();
    let last = std::fs::read_to_string(&p)
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .to_string();
    let v: serde_json::Value = serde_json::from_str(&last).unwrap();
    assert_eq!(v["seq"], 0);
    assert_eq!(v["entry_hash"].as_str().unwrap().len(), 64);
}

#[test]
fn shared_explicit_lock_file_is_used() {
    // Python gateway: home.locks / "audit.lock". The lock file must be the one every writer uses.
    let p = tmp("lockpath");
    let lock = p.parent().unwrap().join("locks").join("audit.lock");
    let s = FileSink::open(&p, &SECRET).unwrap().with_lock_path(&lock);
    s.append(b"{}").unwrap();
    assert!(lock.exists());
    assert!(!p.with_extension("jsonl.lock").exists());
}

#[test]
fn corrupt_python_tail_still_fails_closed() {
    let p = tmp("badtail");
    let (l0, _) = python_line(0, GENESIS, "x", "x");
    std::fs::write(&p, format!("{}\n", l0.replace("ALLOW", "DENY_"))).unwrap();
    let s = FileSink::open(&p, &SECRET).unwrap();
    assert_eq!(s.append(b"{}"), Err(StoreError::Unavailable));
}
