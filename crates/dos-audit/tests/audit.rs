#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
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

fn keys_for(secret: &[u8; 32]) -> Keys {
    let sk = SigningKey::from_bytes(secret);
    Keys(vec![(sk.kid().to_hex(), sk.verifying_key().to_bytes())])
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dos-audit-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("audit.log")
}

fn opts(keys: &Keys) -> VerifyOptions<'_> {
    VerifyOptions { keys, now_unix_ms: 0, python_compat: false, anchor: None }
}

fn kind(r: Result<Verified, VerifyError>) -> VerifyErrorKind {
    r.unwrap_err().kind
}

fn fill(path: &Path, n: usize) -> FileSink {
    let sink = FileSink::open(path, &SECRET).unwrap();
    for i in 0..n {
        let e = format!(r#"{{"actor":"a","tool":"t{i}","verdict":"ALLOW","executed":true}}"#);
        let r = sink.append(e.as_bytes()).unwrap();
        assert_eq!(r.seq, i as u64);
    }
    sink
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path).unwrap().lines().map(String::from).collect()
}

fn write_lines(path: &Path, l: &[String]) {
    let mut s = l.join("\n");
    s.push('\n');
    std::fs::write(path, s).unwrap();
}

fn anchor_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(".anchor");
    PathBuf::from(s)
}

fn full(path: &Path, keys: &Keys) -> Result<Verified, VerifyError> {
    verify_file_with_anchor_file(path, &anchor_path(path), opts(keys))
}

#[test]
fn round_trip_and_resume() {
    let p = tmp("rt");
    let keys = keys_for(&SECRET);
    let sink = fill(&p, 3);
    let v = full(&p, &keys).unwrap();
    assert_eq!(v.entries, 3);
    assert_eq!(v.head, sink.head().unwrap());
    drop(sink);
    // a new sink resumes the chain
    let sink = FileSink::open(&p, &SECRET).unwrap();
    assert_eq!(sink.append(br#"{"x":1}"#).unwrap().seq, 3);
    assert_eq!(full(&p, &keys).unwrap().entries, 4);
}

#[test]
fn empty_log_verifies() {
    let p = tmp("empty");
    let keys = keys_for(&SECRET);
    let _s = FileSink::open(&p, &SECRET).unwrap();
    assert_eq!(full(&p, &keys).unwrap().entries, 0);
}

#[test]
fn refuses_reserved_and_bad_input() {
    let p = tmp("bad");
    let s = FileSink::open(&p, &SECRET).unwrap();
    for bad in [&br#"{"seq":5}"#[..], br#"{"sig":"x"}"#, br#"{"entry_hash":"x"}"#, br#"[1]"#, b"nope", br#"{"a":1,"a":2}"#] {
        assert_eq!(s.append(bad), Err(StoreError::InvalidInput));
    }
    assert_eq!(std::fs::read(&p).unwrap().len(), 0);
}

#[test]
fn edit_field_detected() {
    let p = tmp("edit");
    let keys = keys_for(&SECRET);
    fill(&p, 3);
    let mut l = lines(&p);
    l[1] = l[1].replace("ALLOW", "DENY_");
    write_lines(&p, &l);
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::HashMismatch);
}

#[test]
fn rehash_without_key_detected() {
    let p = tmp("rehash");
    let keys = keys_for(&SECRET);
    fill(&p, 2);
    let mut l = lines(&p);
    // edit entry 1 and recompute entry_hash correctly, but cannot re-sign
    let mut v: serde_json::Value = serde_json::from_str(&l[1]).unwrap();
    v["verdict"] = "DENY".into();
    v.as_object_mut().unwrap().remove("entry_hash");
    let h = hex_encode(&Sha256::digest(serde_json::to_string(&v).unwrap().as_bytes()));
    v["entry_hash"] = h.into();
    l[1] = serde_json::to_string(&v).unwrap();
    write_lines(&p, &l);
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::BadSignature);
}

#[test]
fn wrong_and_unknown_key() {
    let p = tmp("key");
    fill(&p, 1);
    assert_eq!(kind(verify_file(&p, &opts(&keys_for(&[9u8; 32])))), VerifyErrorKind::UnknownKey);
    assert_eq!(kind(verify_file(&p, &opts(&Keys(vec![])))), VerifyErrorKind::UnknownKey);
}

#[test]
fn reorder_delete_insert_detected() {
    let keys = keys_for(&SECRET);
    let p = tmp("reorder");
    fill(&p, 4);
    let orig = lines(&p);

    let mut l = orig.clone();
    l.swap(1, 2);
    write_lines(&p, &l);
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::SeqMismatch);

    let mut l = orig.clone();
    l.remove(1);
    write_lines(&p, &l);
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::SeqMismatch);

    let mut l = orig.clone();
    l.remove(0);
    write_lines(&p, &l);
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::SeqMismatch);

    let mut l = orig.clone();
    l.insert(2, orig[1].clone());
    write_lines(&p, &l);
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::SeqMismatch);
}

#[test]
fn tail_truncation_needs_anchor() {
    let keys = keys_for(&SECRET);
    let p = tmp("trunc");
    fill(&p, 4);
    let mut l = lines(&p);
    l.truncate(2);
    write_lines(&p, &l);
    // chain alone cannot see it
    assert_eq!(verify_file(&p, &opts(&keys)).unwrap().entries, 2);
    // the anchor does
    assert_eq!(kind(full(&p, &keys)), VerifyErrorKind::Truncated);
    // truncating everything too
    std::fs::write(&p, b"").unwrap();
    assert_eq!(kind(full(&p, &keys)), VerifyErrorKind::Truncated);
}

#[test]
fn fork_detected_by_anchor() {
    let keys = keys_for(&SECRET);
    let p = tmp("fork");
    fill(&p, 3);
    let anchored = std::fs::read(anchor_path(&p)).unwrap();
    // an attacker with the key rewrites the last entry; the old anchor disagrees
    std::fs::remove_file(&p).unwrap();
    let s = FileSink::open(&p, &SECRET).unwrap();
    for i in 0..3 {
        s.append(format!(r#"{{"other":{i}}}"#).as_bytes()).unwrap();
    }
    std::fs::write(anchor_path(&p), anchored).unwrap();
    assert_eq!(kind(full(&p, &keys)), VerifyErrorKind::AnchorMismatch);
}

#[test]
fn anchor_missing_forged_or_edited() {
    let keys = keys_for(&SECRET);
    let p = tmp("anchor");
    fill(&p, 2);
    let a = anchor_path(&p);
    let good = std::fs::read_to_string(&a).unwrap();
    std::fs::write(&a, good.replace("\"seq\":1", "\"seq\":0")).unwrap();
    assert_eq!(kind(full(&p, &keys)), VerifyErrorKind::BadSignature);
    std::fs::write(&a, "garbage\n").unwrap();
    assert_eq!(kind(full(&p, &keys)), VerifyErrorKind::AnchorInvalid);
    std::fs::remove_file(&a).unwrap();
    assert_eq!(kind(full(&p, &keys)), VerifyErrorKind::AnchorMissing);
}

#[test]
fn partial_line_garbage_and_blank() {
    let keys = keys_for(&SECRET);
    let p = tmp("partial");
    fill(&p, 2);
    let orig = std::fs::read(&p).unwrap();

    let mut b = orig.clone();
    b.pop();
    std::fs::write(&p, &b).unwrap();
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::PartialLine);
    // the sink refuses to append after a torn tail (fail closed)
    let s = FileSink::open(&p, &SECRET).unwrap();
    assert_eq!(s.append(b"{}"), Err(StoreError::Unavailable));

    let mut b = orig.clone();
    b.extend_from_slice(b"junk\n");
    std::fs::write(&p, &b).unwrap();
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::Malformed);
    assert_eq!(s.append(b"{}"), Err(StoreError::Unavailable));

    let mut b = orig.clone();
    b.extend_from_slice(b"\n");
    std::fs::write(&p, &b).unwrap();
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::PartialLine);
}

#[test]
fn non_canonical_line_detected() {
    let keys = keys_for(&SECRET);
    let p = tmp("noncanon");
    fill(&p, 1);
    let l = lines(&p);
    write_lines(&p, &[l[0].replacen(",", ", ", 1)]);
    assert_eq!(kind(verify_file(&p, &opts(&keys))), VerifyErrorKind::NonCanonical);
}

#[test]
fn concurrent_threads_and_two_sinks() {
    let keys = keys_for(&SECRET);
    let p = tmp("conc");
    let a = Arc::new(FileSink::open(&p, &SECRET).unwrap());
    let b = Arc::new(FileSink::open(&p, &SECRET).unwrap());
    let mut hs = vec![];
    for t in 0..4 {
        let s = if t % 2 == 0 { a.clone() } else { b.clone() };
        hs.push(std::thread::spawn(move || {
            for i in 0..15 {
                s.append(format!(r#"{{"t":{t},"i":{i}}}"#).as_bytes()).unwrap();
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(verify_file(&p, &opts(&keys)).unwrap().entries, 60);
}

#[test]
fn anchor_failure_is_an_error() {
    struct Fail;
    impl Anchor for Fail {
        fn publish(&self, _: &Head) -> Result<(), StoreError> {
            Err(StoreError::Unavailable)
        }
    }
    let p = tmp("anchorfail");
    let s = FileSink::open_with_anchor(&p, &SECRET, Some(Box::new(Fail))).unwrap();
    assert_eq!(s.append(b"{}"), Err(StoreError::Unavailable));
}

#[test]
fn unwritable_location_fails() {
    let p = tmp("dirasfile");
    std::fs::create_dir_all(&p).unwrap(); // log path is a directory
    assert!(FileSink::open(&p, &SECRET).is_err());
}

// ---- oracle compatibility ----

fn python_log(entries: &[serde_json::Value]) -> String {
    // Python recipe: sha256(json.dumps(entry minus entry_hash, sort_keys, compact, ensure_ascii))
    let mut out = String::new();
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        let mut e = e.clone();
        e["seq"] = i.into();
        e["prev_hash"] = prev.clone().into();
        let h = hex_encode(&Sha256::digest(serde_json::to_string(&e).unwrap().as_bytes()));
        e["entry_hash"] = h.clone().into();
        // Python writes json.dumps(entry): spaces after separators
        out.push_str(&serde_json::to_string(&e).unwrap().replace("\":", "\": ").replace("\",", "\", "));
        out.push('\n');
        prev = h;
    }
    out
}

#[test]
fn python_log_verifies_in_compat_mode_only() {
    let keys = keys_for(&SECRET);
    let p = tmp("py");
    let entries: Vec<_> = (0..3)
        .map(|i| serde_json::json!({"ts":"2026-01-01T00:00:00+00:00","actor":"a","tool":format!("t{i}"),"verdict":"ALLOW","reason":"ok","executed":null,"payload_digest":null}))
        .collect();
    std::fs::write(&p, python_log(&entries)).unwrap();
    let mut o = opts(&keys);
    assert!(verify_file(&p, &o).is_err());
    o.python_compat = true;
    assert_eq!(verify_file(&p, &o).unwrap().entries, 3);
    // tamper still caught in compat mode
    let s = std::fs::read_to_string(&p).unwrap().replace("ALLOW", "DENY_");
    std::fs::write(&p, s).unwrap();
    assert_eq!(kind(verify_file(&p, &o)), VerifyErrorKind::HashMismatch);
}

#[test]
fn python_non_ascii_legacy_hash() {
    let keys = keys_for(&SECRET);
    let p = tmp("pyuni");
    // Python's ensure_ascii hash input: "café" and an astral char as a surrogate pair
    let e = r#"{"actor":"café 😀","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":0}"#;
    let h = hex_encode(&Sha256::digest(e.as_bytes()));
    let line = format!(r#"{{"actor": "café 😀", "seq": 0, "prev_hash": "{GENESIS}", "entry_hash": "{h}"}}"#);
    std::fs::write(&p, format!("{line}\n")).unwrap();
    let mut o = opts(&keys);
    o.python_compat = true;
    assert_eq!(verify_file(&p, &o).unwrap().entries, 1);
}

#[test]
fn rust_log_matches_python_recipe() {
    // Python's verify: sha256(json.dumps(all fields but entry_hash, sort_keys, compact))
    let p = tmp("pyrecipe");
    fill(&p, 3);
    for l in lines(&p) {
        let mut v: serde_json::Value = serde_json::from_str(&l).unwrap();
        let stored = v["entry_hash"].as_str().unwrap().to_string();
        v.as_object_mut().unwrap().remove("entry_hash");
        let h = hex_encode(&Sha256::digest(serde_json::to_string(&v).unwrap().as_bytes()));
        assert_eq!(h, stored);
    }
}

#[test]
fn rust_extends_python_log() {
    let keys = keys_for(&SECRET);
    let p = tmp("pyext");
    std::fs::write(&p, python_log(&[serde_json::json!({"actor":"a"})])).unwrap();
    let s = FileSink::open(&p, &SECRET).unwrap();
    assert_eq!(s.append(b"{}").unwrap().seq, 1);
    let mut o = opts(&keys);
    assert_eq!(kind(verify_file(&p, &o)), VerifyErrorKind::NonCanonical);
    o.python_compat = true;
    assert_eq!(verify_file(&p, &o).unwrap().entries, 2);
}
