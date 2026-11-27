//! Runs `conformance/vectors/audit/*.json` against the verifier. Missing vector files
//! are generated deterministically (Ed25519 is deterministic, entries are fixed);
//! existing files are never rewritten (vectors are append-only).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use dos_audit::*;
use dos_core::sign::{SigningKey, hex_decode_array};
use dos_core::store::{AuditSink, KeyStore, StoreError};
use serde_json::{Value, json};

/// RFC 8032 section 7.1 TEST 1: the fixed conformance test key.
const SECRET_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// RFC 8032 section 7.1 TEST 2.
const OTHER_HEX: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/audit")
}

fn secret(h: &str) -> [u8; 32] {
    hex_decode_array::<32>(h).unwrap()
}

struct Keys(Vec<(String, [u8; 32])>);
impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(self.0.iter().find(|(k, _)| k == kid).map(|(_, v)| *v))
    }
}

fn key_entry(h: &str) -> (String, Value) {
    let sk = SigningKey::from_bytes(&secret(h));
    (
        sk.kid().to_hex(),
        Value::String(dos_core::sign::hex_encode(&sk.verifying_key().to_bytes())),
    )
}

/// A fresh 3-entry log written by the real sink. Returns its lines and head.
fn good_log(name: &str) -> (Vec<String>, Value) {
    let p = std::env::temp_dir().join(format!("dos-audit-vec-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    let log = p.join("audit.log");
    let s = FileSink::open(&log, &secret(SECRET_HEX)).unwrap();
    for i in 0..3 {
        s.append(
            format!(r#"{{"actor":"agent","executed":true,"reason":"ok","tool":"t{i}","ts":"2026-01-01T00:00:00+00:00","verdict":"ALLOW"}}"#)
                .as_bytes(),
        )
        .unwrap();
    }
    let head = s.head().unwrap().unwrap();
    let lines = std::fs::read_to_string(&log).unwrap().lines().map(String::from).collect();
    (lines, json!({"seq": head.seq, "entry_hash": head.entry_hash}))
}

fn vector(name: &str, log: Vec<String>, keys: &[&str], extra: Value, expected: Value, source: &str) -> Value {
    let mut input = json!({
        "op": "verify",
        "log": log,
        "keys": keys.iter().map(|k| key_entry(k)).collect::<serde_json::Map<_, _>>(),
    });
    for (k, v) in extra.as_object().unwrap() {
        input[k] = v.clone();
    }
    json!({"v":1,"area":"audit","name":name,"input":input,"expected":expected,"source":source})
}

fn generate() {
    let (good, head) = good_log("gen");
    let err = |c: &str| json!({"error": c});
    let mut all: Vec<Value> = vec![];
    let none = json!({});
    all.push(vector("valid-chain", good.clone(), &[SECRET_HEX], none.clone(), json!({"ok": {"entries": 3}}), "spec U-CHAIN-LOG"));
    all.push(vector("valid-chain-anchored", good.clone(), &[SECRET_HEX], json!({"anchor": head}), json!({"ok": {"entries": 3}}), "DM-5"));
    let mut l = good.clone();
    l[1] = l[1].replace("ALLOW", "DENY_");
    all.push(vector("edited-field", l, &[SECRET_HEX], none.clone(), err("hash_mismatch"), "DM HB-2 edit"));
    let mut l = good.clone();
    l.swap(1, 2);
    all.push(vector("reordered", l, &[SECRET_HEX], none.clone(), err("seq_mismatch"), "DM HB-2 reorder"));
    let mut l = good.clone();
    l.remove(1);
    all.push(vector("deleted-middle", l, &[SECRET_HEX], none.clone(), err("seq_mismatch"), "DM HB-2 delete"));
    let mut l = good.clone();
    l.remove(0);
    all.push(vector("deleted-head", l, &[SECRET_HEX], none.clone(), err("seq_mismatch"), "DM HB-2 head deletion"));
    let mut l = good.clone();
    l.insert(1, good[0].clone());
    all.push(vector("duplicated-entry", l, &[SECRET_HEX], none.clone(), err("seq_mismatch"), "insert"));
    let mut l = good.clone();
    l.truncate(2);
    all.push(vector("truncated-no-anchor", l.clone(), &[SECRET_HEX], none.clone(), json!({"ok": {"entries": 2}}), "chain alone cannot see truncation (HB-2)"));
    all.push(vector("truncated-with-anchor", l, &[SECRET_HEX], json!({"anchor": head}), err("truncated"), "DM-5"));
    let mut a = head.clone();
    a["entry_hash"] = json!("f".repeat(64));
    all.push(vector("anchor-hash-differs", good.clone(), &[SECRET_HEX], json!({"anchor": a}), err("anchor_mismatch"), "fork"));
    all.push(vector("unknown-key", good.clone(), &[OTHER_HEX], none.clone(), err("unknown_key"), "U-SIG"));
    all.push(vector("empty-log", vec![], &[SECRET_HEX], none.clone(), json!({"ok": {"entries": 0}}), "empty chain"));
    all.push(vector("partial-last-line", good.clone(), &[SECRET_HEX], json!({"final_newline": false}), err("partial_line"), "torn write"));
    let mut l = good.clone();
    l[0] = l[0].replacen(',', ", ", 1);
    all.push(vector("non-canonical-line", l, &[SECRET_HEX], none.clone(), err("non_canonical"), "DM-3"));
    // Entry without signature: strict refuses, compat accepts (oracle logs).
    let unsigned = {
        use sha2::{Digest, Sha256};
        let e = format!(r#"{{"actor":"a","prev_hash":"{GENESIS}","seq":0}}"#);
        let h = dos_core::sign::hex_encode(&Sha256::digest(e.as_bytes()));
        format!(r#"{{"actor": "a", "seq": 0, "prev_hash": "{GENESIS}", "entry_hash": "{h}"}}"#)
    };
    all.push(vector("oracle-log-strict", vec![unsigned.clone()], &[SECRET_HEX], none.clone(), err("non_canonical"), "oracle audit.py line format"));
    all.push(vector("oracle-log-compat", vec![unsigned], &[SECRET_HEX], json!({"python_compat": true}), json!({"ok": {"entries": 1}}), "oracle audit.py"));
    std::fs::create_dir_all(dir()).unwrap();
    for v in all {
        let path = dir().join(format!("{}.json", v["name"].as_str().unwrap()));
        if !path.exists() {
            std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
        }
    }
}

fn run(v: &Value) -> Value {
    let input = &v["input"];
    let mut keys = Keys(vec![]);
    for (kid, pk) in input["keys"].as_object().unwrap() {
        keys.0.push((kid.clone(), hex_decode_array::<32>(pk.as_str().unwrap()).unwrap()));
    }
    let mut bytes = input["log"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect::<Vec<_>>().join("\n").into_bytes();
    if !bytes.is_empty() && input.get("final_newline") != Some(&json!(false)) {
        bytes.push(b'\n');
    }
    let anchor = input.get("anchor").map(|a| Head {
        seq: a["seq"].as_u64().unwrap(),
        entry_hash: a["entry_hash"].as_str().unwrap().to_string(),
    });
    let opts = VerifyOptions {
        keys: &keys,
        now_unix_ms: 0,
        python_compat: input.get("python_compat") == Some(&json!(true)),
        anchor,
    };
    match verify_bytes(&bytes, &opts) {
        Ok(v) => json!({"ok": {"entries": v.entries}}),
        Err(e) => json!({"error": e.kind.code()}),
    }
}

#[test]
fn audit_vectors() {
    generate();
    let mut n = 0;
    for f in std::fs::read_dir(dir()).unwrap() {
        let path = f.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(run(&v), v["expected"], "vector {}", path.display());
        n += 1;
    }
    assert!(n >= 16, "only {n} vectors");
}
