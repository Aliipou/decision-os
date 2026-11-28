//! cargo fuzz run json -- -max_total_time=600   (Linux, nightly)
//!
//! Same properties as `fuzz/standalone` (`json_diff`), driven by libFuzzer:
//! no panic; write round trip; acceptance and value agreement with serde_json outside
//! the documented differences (duplicate keys, exponent range, lone surrogates, f64
//! overflow).
#![no_main]

use dos_conformance::json::{self, ErrorKind, Json};
use libfuzzer_sys::fuzz_target;

fn same(a: &Json, b: &serde_json::Value) -> bool {
    use serde_json::Value as V;
    match (a, b) {
        (Json::Null, V::Null) => true,
        (Json::Bool(x), V::Bool(y)) => x == y,
        (Json::String(_), V::String(s)) => a.as_string().as_deref() == Some(s.as_str()),
        (Json::Array(x), V::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        (Json::Object(m), V::Object(n)) => {
            m.len() == n.len()
                && m.iter().all(|(k, v)| {
                    k.to_string_strict()
                        .and_then(|k| n.get(&k))
                        .is_some_and(|w| same(v, w))
                })
        }
        (Json::Number(x), V::Number(y)) => {
            if y.is_u64() || y.is_i64() {
                json::parse(&y.to_string()).is_ok_and(|n| n == Json::Number(x.clone()))
            } else {
                true // f64: precision differs by design
            }
        }
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let ours = json::parse(s);
    let theirs = serde_json::from_str::<serde_json::Value>(s);
    match (&ours, &theirs) {
        (Ok(v), Ok(w)) => assert!(same(v, w), "value mismatch on {s:?}"),
        (Ok(_), Err(e)) => {
            let m = e.to_string();
            assert!(
                m.contains("surrogate") || m.contains("out of range") || m.contains("recursion"),
                "we accept, serde refuses ({m}): {s:?}"
            );
        }
        (Err(e), Ok(_)) => assert!(
            matches!(e.kind, ErrorKind::DuplicateKey | ErrorKind::NumberRange | ErrorKind::TooDeep),
            "we refuse ({e}), serde accepts: {s:?}"
        ),
        (Err(_), Err(_)) => {}
    }
    if let Ok(v) = ours {
        let w = json::write(&v);
        let v2 = json::parse(&w);
        assert!(v2.as_ref().is_ok_and(|v2| *v2 == v), "round trip {s:?} -> {w:?}");
        if let Ok(v2) = v2 {
            assert_eq!(json::write(&v2), w, "writer not idempotent");
        }
    }
});
