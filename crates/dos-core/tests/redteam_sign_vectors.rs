//! Red team (findings/sign.md): runs conformance/vectors/redteam/*.json (area
//! "sign") through the library's own entry points in their natural order:
//! parse domain, payload, key, kid, signature, then `verify_with_kid` or
//! `verify`. No hand-written check is added on top of the library, so this
//! measures what a caller of `dos_core::sign` actually gets.

use dos_core::sign::{Domain, SignError, VerifyingKey, hex_decode, hex_decode_array};
use serde_json::{Value, json};
use std::path::PathBuf;

const TEST1_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn verify(input: &Value) -> Result<(), SignError> {
    let s = |k: &str| input.get(k).and_then(Value::as_str);
    let domain = Domain::from_tag(s("domain").unwrap_or(""))?;
    let payload = hex_decode(s("payload_hex").unwrap_or("\u{0}"))?;
    let vk = VerifyingKey::from_bytes(&hex_decode_array::<32>(
        s("public_key").unwrap_or(TEST1_PUBLIC),
    )?)?;
    vk.verify_wire(domain, &payload, s("kid"), s("sig").unwrap_or(""))
}

#[test]
fn redteam_sign_vectors_through_library_order() -> Result<(), String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/redteam");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("redteam-sign-"))
        })
        .collect();
    paths.sort();
    let mut n = 0;
    let mut failures = Vec::new();
    for p in &paths {
        let text = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        if v.get("area").and_then(Value::as_str) != Some("sign") {
            continue;
        }
        n += 1;
        let name = v.get("name").and_then(Value::as_str).unwrap_or("?");
        let input = v.get("input").ok_or("no input")?;
        if input.get("op").and_then(Value::as_str) != Some("verify") {
            return Err(format!("{name}: only verify vectors here"));
        }
        let got = match verify(input) {
            Ok(()) => json!({"ok": true}),
            Err(e) => json!({"error": e.code()}),
        };
        if Some(&got) != v.get("expected") {
            failures.push(format!(
                "{name}: expected {:?} got {got}",
                v.get("expected")
            ));
        }
    }
    println!("{n} redteam sign vectors, {} failed", failures.len());
    assert!(n >= 9, "{n}");
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}
