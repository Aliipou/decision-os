//! Red team (findings/sign.md): differential of dos_core::sign against an
//! independent pure-Python spec reference and Python `cryptography` (OpenSSL).
//! Cases: tests/redteam/sign_diff/cases.jsonl (generator: gen.py, same dir).
//! Rust must equal the spec reference on every case (error code included).
//! Differences with `cryptography` are counted and classified; Rust may only be
//! stricter than OpenSSL, and only where the spec rejects.

use dos_core::sign::{Domain, SignError, Signature, VerifyingKey, hex_decode, hex_decode_array};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn rust_result(c: &Value) -> Result<(), SignError> {
    let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or("");
    let d = Domain::from_tag(s("domain"))?;
    let payload = hex_decode(s("payload"))?;
    let vk = VerifyingKey::from_bytes(&hex_decode_array::<32>(s("pk"))?)?;
    let sig = Signature::from_bytes(&hex_decode_array::<64>(s("sig"))?)?;
    vk.verify(d, &payload, &sig)
}

#[test]
fn differential_rust_equals_spec_reference_and_is_never_looser_than_openssl() -> Result<(), String>
{
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/redteam/sign_diff/cases.jsonl");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut n = 0usize;
    let mut spec_mismatch = Vec::new();
    let mut looser_than_openssl = Vec::new();
    let mut stricter: BTreeMap<String, usize> = BTreeMap::new();
    for line in text.lines() {
        let c: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        n += 1;
        let got = match rust_result(&c) {
            Ok(()) => String::from("ok"),
            Err(e) => String::from(e.code()),
        };
        let spec = c.get("spec").and_then(Value::as_str).unwrap_or("?");
        let py = c.get("py").and_then(Value::as_str).unwrap_or("?");
        let cat = c.get("cat").and_then(Value::as_str).unwrap_or("?");
        if got != spec {
            spec_mismatch.push(format!("{cat}: rust {got} spec {spec}: {line}"));
        }
        if got == "ok" && py != "ok" {
            looser_than_openssl.push(format!("{cat}: rust ok, openssl {py}: {line}"));
        }
        if got != "ok" && py == "ok" {
            *stricter.entry(format!("{cat}/{got}")).or_default() += 1;
        }
    }
    println!("{n} differential cases");
    println!("rust stricter than openssl (spec rejects, openssl accepts): {stricter:?}");
    assert!(n >= 10_000, "{n}");
    assert!(
        spec_mismatch.is_empty(),
        "{} spec mismatches:\n{}",
        spec_mismatch.len(),
        spec_mismatch.join("\n")
    );
    assert!(
        looser_than_openssl.is_empty(),
        "{}",
        looser_than_openssl.join("\n")
    );
    Ok(())
}
