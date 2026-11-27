//! Strict JSON for client messages: one parse, duplicate keys refused.
//!
//! A message the proxy cannot read unambiguously must not reach the server,
//! because the server's parser might read a `tools/call` the proxy never saw.
//! serde_json already refuses NaN, Infinity, lone surrogates, trailing commas
//! and nesting deeper than 128; this adds duplicate object keys.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            let Strict(v) = map.next_value()?;
            if out.insert(k.clone(), v).is_some() {
                return Err(de::Error::custom(format!("duplicate key {k:?}")));
            }
        }
        Ok(Value::Object(out))
    }
}

/// Parse one line strictly. `Err` means: do not forward this line.
pub fn parse(raw: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<Strict>(raw)
        .map(|Strict(v)| v)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn refuses_ambiguous_input() {
        for bad in [
            &br#"{"method":"ping","method":"tools/call"}"#[..],
            br#"{"a":{"x":1,"x":2}}"#,
            br#"{"a":NaN}"#,
            br#"{"a":Infinity}"#,
            br#"{"a":"\ud800"}"#,
            br#"{"a":1,}"#,
            b"{\"a\":1} x",
            b"",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn accepts_plain_json() {
        let ok = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1,2.5,null,true,"é","é"]}"#;
        assert!(parse(ok.as_bytes()).is_ok());
        assert!(parse(b"  {\"a\":1}\r\n").is_ok());
    }
}
