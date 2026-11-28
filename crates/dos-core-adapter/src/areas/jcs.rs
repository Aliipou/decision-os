//! The `jcs` area (spec/canon.md): `{"text": s}` or `{"bytes_hex": h}` -> the RFC 8785
//! canonical form as a string, or the refusal code of `dos_core::canon`.

use dos_conformance::json::Json;
use dos_conformance::protocol::{Output, exact_keys};
use dos_core::canon;

fn invalid() -> Output {
    Output::Error("invalid_input".into())
}

/// Lowercase or uppercase hex to bytes; `None` on odd length or a non-hex digit.
fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect()
}

pub fn handle(input: &Json) -> Output {
    let bytes = if exact_keys(input, &["text"]).is_ok() {
        match input.get("text").and_then(Json::as_string) {
            Some(t) => t.into_bytes(),
            None => return invalid(),
        }
    } else if exact_keys(input, &["bytes_hex"]).is_ok() {
        match input
            .get("bytes_hex")
            .and_then(Json::as_string)
            .and_then(|h| from_hex(&h))
        {
            Some(b) => b,
            None => return invalid(),
        }
    } else {
        return invalid();
    };
    match canon::canonicalize(&bytes) {
        Ok(out) => match String::from_utf8(out) {
            Ok(s) => Output::Ok(Json::str(&s)),
            // Canonical output of valid input is UTF-8; anything else is a core bug and
            // must not read as a pass.
            Err(_) => Output::Error("internal_non_utf8_output".into()),
        },
        Err(e) => Output::Error(e.code().into()),
    }
}

#[cfg(test)]
mod tests {
    use super::handle;
    use dos_conformance::json::{Json, parse};
    use dos_conformance::protocol::Output;

    fn run(s: &str) -> Output {
        handle(&parse(s).unwrap_or(Json::Null))
    }

    #[test]
    fn canonicalizes_and_refuses() {
        assert_eq!(
            run(r#"{"text":"{\"b\":1,\"a\":2}"}"#),
            Output::Ok(Json::str(r#"{"a":2,"b":1}"#))
        );
        assert_eq!(run(r#"{"bytes_hex":"7b7d"}"#), Output::Ok(Json::str("{}")));
        assert_eq!(run(r#"{"text":"﻿{}"}"#), Output::Error("leading_bom".into()));
        assert_eq!(
            run(r#"{"bytes_hex":"22f490808022"}"#),
            Output::Error("invalid_utf8".into())
        );
    }

    #[test]
    fn wrong_shape_is_invalid_input() {
        for bad in [
            r#"{}"#,
            r#"{"text":"{}","bytes_hex":"7b7d"}"#,
            r#"{"text":1}"#,
            r#"{"bytes_hex":"7b7"}"#,
            r#"{"bytes_hex":"zz"}"#,
            r#"{"text":"{}","x":1}"#,
        ] {
            assert_eq!(run(bad), Output::Error("invalid_input".into()), "{bad}");
        }
    }
}
