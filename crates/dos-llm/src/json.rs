//! Strict JSON in, Python-`json.dumps`-shaped JSON out.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt::{self, Write as _};

/// Parses one JSON document and refuses anything ambiguous: duplicate object keys
/// (clients disagree on which one wins), a byte-order mark, NaN or Infinity, invalid
/// UTF-8, trailing data, nesting deeper than serde_json's limit (128).
pub fn parse_strict(raw: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    let mut de = serde_json::Deserializer::from_slice(raw);
    NoDup::deserialize(&mut de).map_err(|e| e.to_string())?;
    Ok(v)
}

/// Parses a tool-call argument string like the oracle (`json.loads`): `Ok(None)` when it
/// is not JSON, `Err` when it is JSON with duplicate keys.
pub(crate) fn parse_args_text(s: &str) -> Result<Option<Value>, String> {
    match serde_json::from_str::<Value>(s) {
        Err(_) => Ok(None),
        Ok(v) => {
            let mut de = serde_json::Deserializer::from_str(s);
            NoDup::deserialize(&mut de).map_err(|e| e.to_string())?;
            Ok(Some(v))
        }
    }
}

struct NoDup;

impl<'de> Deserialize<'de> for NoDup {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDupVisitor)
    }
}

struct NoDupVisitor;

impl<'de> Visitor<'de> for NoDupVisitor {
    type Value = NoDup;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_i64<E>(self, _: i64) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_u64<E>(self, _: u64) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_i128<E>(self, _: i128) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_u128<E>(self, _: u128) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_f64<E>(self, _: f64) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_str<E>(self, _: &str) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_unit<E>(self) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_none<E>(self) -> Result<NoDup, E> {
        Ok(NoDup)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDup, A::Error> {
        while seq.next_element::<NoDup>()?.is_some() {}
        Ok(NoDup)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDup, A::Error> {
        let mut seen = HashSet::new();
        while let Some(k) = map.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                return Err(de::Error::custom(format!("duplicate key {k:?}")));
            }
            map.next_value::<NoDup>()?;
        }
        Ok(NoDup)
    }
}

/// `json.dumps(value, ensure_ascii=False)`: `", "` and `": "` separators, non-ASCII
/// kept, control characters escaped. Numbers keep their parsed text.
pub fn dumps_py(v: &Value) -> String {
    let mut out = String::new();
    write_py(v, &mut out);
    out
}

fn write_py(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_str(k, out);
                out.push_str(": ");
                write_py(x, out);
            }
            out.push('}');
        }
    }
}

fn write_str(s: &str, out: &mut String) {
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
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Python truthiness of a JSON value.
pub(crate) fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// `x.get(key)` that treats a non-object as having no keys.
pub(crate) fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(key))
}

/// A non-empty string field.
pub(crate) fn name_of(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// An integer index field (`p.get(key, 0)` in the oracle); `Err` when present and not an
/// integer.
pub(crate) fn index_of(v: &Value, key: &str) -> Result<i64, String> {
    match get(v, key) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n.as_i64().ok_or_else(|| format!("{key} is not an integer")),
        Some(_) => Err(format!("{key} is not an integer")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn strict_refuses_ambiguous() {
        for bad in [
            &br#"{"a":1,"a":2}"#[..],
            br#"{"a":{"x":1,"x":2}}"#,
            br#"[{"k":1,"k":1}]"#,
            br#"{"a":NaN}"#,
            b"\xef\xbb\xbf{}",
            b"{} x",
            b"\xff",
            b"",
        ] {
            assert!(
                parse_strict(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert!(parse_strict("{\"a\":[1,2.5,{\"b\":null}],\"c\":\"\u{e9}\"}".as_bytes()).is_ok());
    }

    #[test]
    fn dumps_like_python() {
        let v: Value =
            serde_json::from_str(r#"{"a":[1,"x\n\u0001é"],"b":{},"c":[],"d":1.50,"e":null}"#)
                .unwrap();
        assert_eq!(
            dumps_py(&v),
            r#"{"a": [1, "x\n\u0001é"], "b": {}, "c": [], "d": 1.50, "e": null}"#
        );
    }
}
