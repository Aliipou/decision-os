//! Entry hashing and signing payloads, shared by the sink and the verifier.

use dos_core::canon::{self, CanonError, Number, Value};
use dos_core::sign::hex_encode;
use sha2::{Digest, Sha256};

/// `prev_hash` of the first entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Keys the sink assigns; an input entry must not contain them.
pub(crate) const RESERVED: [&str; 5] = ["seq", "prev_hash", "entry_hash", "sig", "kid"];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

/// The object's members without the named keys.
pub(crate) fn without(members: &[(String, Value)], drop: &[&str]) -> Vec<(String, Value)> {
    members
        .iter()
        .filter(|(k, _)| !drop.contains(&k.as_str()))
        .cloned()
        .collect()
}

pub(crate) fn field<'a>(members: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    members.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

pub(crate) fn str_field<'a>(members: &'a [(String, Value)], name: &str) -> Option<&'a str> {
    match field(members, name) {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

pub(crate) fn seq_field(members: &[(String, Value)]) -> Option<u64> {
    match field(members, "seq") {
        Some(Value::Number(n)) => {
            let f = n.get();
            if f >= 0.0 && f.fract() == 0.0 && f <= MAX_SAFE {
                Some(f as u64)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(crate) fn seq_value(seq: u64) -> Result<Value, CanonError> {
    if seq as f64 > MAX_SAFE {
        return Err(CanonError::UnsafeInteger);
    }
    Ok(Value::Number(Number::new(seq as f64)?))
}

/// JCS of the entry without `entry_hash` and `sig`: the bytes that are signed.
pub(crate) fn signing_bytes(members: &[(String, Value)]) -> Result<Vec<u8>, CanonError> {
    canon::to_jcs(&Value::Object(without(members, &["entry_hash", "sig"])))
}

/// `entry_hash`: SHA-256 over the JCS of every field except `entry_hash` (includes `sig`).
pub(crate) fn hash_of(members: &[(String, Value)]) -> Result<String, CanonError> {
    let bytes = canon::to_jcs(&Value::Object(without(members, &["entry_hash"])))?;
    Ok(sha256_hex(&bytes))
}

/// The hash Python computes: `json.dumps(sort_keys=True, separators=(",", ":"))`
/// (ASCII-escaped, code point key order). Differs from JCS only for non-ASCII text.
/// `None` for values the oracle's entries do not contain (arrays, floats).
pub(crate) fn legacy_hash_of(members: &[(String, Value)]) -> Option<String> {
    let mut out = String::new();
    legacy_object(&without(members, &["entry_hash"]), &mut out)?;
    Some(sha256_hex(out.as_bytes()))
}

fn legacy_object(members: &[(String, Value)], out: &mut String) -> Option<()> {
    let mut sorted: Vec<&(String, Value)> = members.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    out.push('{');
    for (i, (k, v)) in sorted.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        legacy_string(k, out);
        out.push(':');
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::String(s) => legacy_string(s, out),
            Value::Number(n) => {
                let f = n.get();
                if f.fract() != 0.0 || f.abs() > MAX_SAFE {
                    return None;
                }
                out.push_str(&format!("{}", f as i64));
            }
            Value::Object(m) => legacy_object(m, out)?,
            Value::Array(_) => return None,
        }
    }
    out.push('}');
    Some(())
}

fn legacy_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
        }
    }
    out.push('"');
}
