//! Runs every `conformance/vectors/sign/*.json` case through the public API of
//! `dos_core::sign`, using the semantics of `spec/sign.md` (conformance input).
//! Expected values for `sign` were computed by an independent implementation
//! (Python `cryptography` + `hashlib`, see status/sign.md).

use dos_core::sign::{
    Domain, Kid, SignError, Signature, SigningKey, VerifyingKey, hex_decode, hex_decode_array,
};
use serde_json::{Value, json};
use std::path::PathBuf;

const TEST1_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn field<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
    input
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {name}"))
}

fn run_verify(input: &Value, test_key: &SigningKey) -> Result<(), SignError> {
    let domain = Domain::from_tag(input.get("domain").and_then(Value::as_str).unwrap_or(""))?;
    let payload = hex_decode(
        input
            .get("payload_hex")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )?;
    let vk = match input.get("public_key").and_then(Value::as_str) {
        Some(pk) => VerifyingKey::from_hex(pk)?,
        None => test_key.verifying_key(),
    };
    let kid = match input.get("kid").and_then(Value::as_str) {
        Some(k) => Some(Kid::from_hex(k)?),
        None => None,
    };
    // spec/sign.md check order: the kid is checked before the signature is parsed.
    if let Some(k) = kid
        && vk.kid() != k
    {
        return Err(SignError::KidMismatch);
    }
    let sig = Signature::from_hex(input.get("sig").and_then(Value::as_str).unwrap_or(""))?;
    match kid {
        Some(k) => vk.verify_with_kid(domain, &payload, &sig, &k),
        None => vk.verify(domain, &payload, &sig),
    }
}

fn run(input: &Value, test_key: &SigningKey) -> Result<Value, String> {
    let out = match field(input, "op")? {
        "sign" => {
            let r = Domain::from_tag(field(input, "domain")?).and_then(|d| {
                let payload = hex_decode(field(input, "payload_hex").unwrap_or("\u{0}"))?;
                Ok(test_key.sign(d, &payload))
            });
            match r {
                Ok(sig) => json!({"ok": {"sig": sig.to_hex(), "kid": test_key.kid().to_hex()}}),
                Err(e) => json!({"error": e.code()}),
            }
        }
        "verify" => match run_verify(input, test_key) {
            Ok(()) => json!({"ok": true}),
            Err(e) => json!({"error": e.code()}),
        },
        "kid" => match VerifyingKey::from_hex(field(input, "public_key")?) {
            Ok(vk) => json!({"ok": vk.kid().to_hex()}),
            Err(e) => json!({"error": e.code()}),
        },
        other => return Err(format!("unknown op {other}")),
    };
    Ok(out)
}

#[test]
fn every_sign_vector_passes() -> Result<(), String> {
    let test_key =
        SigningKey::from_bytes(&hex_decode_array::<32>(TEST1_SECRET).map_err(|e| e.to_string())?);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/sign");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();
    let mut failures = Vec::new();
    for path in &entries {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let v: Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let name = v.get("name").and_then(Value::as_str).unwrap_or("");
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if name != stem || v.get("area").and_then(Value::as_str) != Some("sign") {
            failures.push(format!("{stem}: name/area mismatch"));
            continue;
        }
        let input = v.get("input").ok_or_else(|| format!("{name}: no input"))?;
        let expected = v
            .get("expected")
            .ok_or_else(|| format!("{name}: no expected"))?;
        let got = run(input, &test_key).map_err(|e| format!("{name}: {e}"))?;
        if &got != expected {
            failures.push(format!("{name}: expected {expected} got {got}"));
        }
    }
    println!(
        "{} sign vectors checked, {} failed",
        entries.len(),
        failures.len()
    );
    if entries.len() < 40 {
        return Err(format!("only {} sign vectors", entries.len()));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}
