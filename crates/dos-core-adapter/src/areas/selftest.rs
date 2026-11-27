//! The `selftest` area (spec/CONFORMANCE-notes.md): proves the pipe, not the core.
//!
//! - `{"op": "echo", "value": v}` -> `{"ok": v}`
//! - `{"op": "error", "code": c}` -> `{"error": c}` (c a non-empty string)
//! - any other op -> `{"error": "unknown_op"}`; wrong fields -> `{"error": "invalid_input"}`

use dos_conformance::json::Json;
use dos_conformance::protocol::{Output, exact_keys};

pub fn handle(input: &Json) -> Output {
    let invalid = || Output::Error("invalid_input".into());
    match input.get("op").and_then(Json::as_string).as_deref() {
        Some("echo") if exact_keys(input, &["op", "value"]).is_ok() => match input.get("value") {
            Some(v) => Output::Ok(v.clone()),
            None => invalid(),
        },
        Some("error") if exact_keys(input, &["op", "code"]).is_ok() => {
            match input.get("code").and_then(Json::as_string) {
                Some(c) if !c.is_empty() => Output::Error(c),
                _ => invalid(),
            }
        }
        Some("echo" | "error") | None => invalid(),
        Some(_) => Output::Error("unknown_op".into()),
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
    fn ops() {
        assert_eq!(
            run(r#"{"op":"echo","value":[1,"\ud800"]}"#),
            Output::Ok(parse(r#"[1,"\ud800"]"#).unwrap_or(Json::Null))
        );
        assert_eq!(
            run(r#"{"op":"error","code":"x"}"#),
            Output::Error("x".into())
        );
        assert_eq!(run(r#"{"op":"nope"}"#), Output::Error("unknown_op".into()));
        for bad in [
            r#"{"op":"echo"}"#,
            r#"{"op":"echo","value":1,"x":1}"#,
            r#"{"op":"error","code":""}"#,
            r#"{"op":1}"#,
            r#"{}"#,
        ] {
            assert_eq!(run(bad), Output::Error("invalid_input".into()), "{bad}");
        }
    }
}
