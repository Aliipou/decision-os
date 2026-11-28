//! The `meet` area (spec/verdict.md): the verdict lattice.
//!
//! - `{"op":"parse","s":str}` -> the normalized verdict (unknown strings fail closed)
//! - `{"op":"meet","a":str,"b":str}` -> the lattice meet of the two parsed verdicts
//! - `{"op":"compose","verdicts":[str,...]}` -> the compose of the parsed verdicts

use dos_conformance::json::Json;
use dos_conformance::protocol::{Output, exact_keys};
use dos_core::verdict::{Verdict, compose, meet, parse};

fn invalid() -> Output {
    Output::Error("invalid_input".into())
}

fn text(input: &Json, key: &str) -> Option<String> {
    input.get(key).and_then(Json::as_string)
}

fn ok(v: Verdict) -> Output {
    Output::Ok(Json::str(v.as_str()))
}

pub fn handle(input: &Json) -> Output {
    match text(input, "op").as_deref() {
        Some("parse") if exact_keys(input, &["op", "s"]).is_ok() => match text(input, "s") {
            Some(s) => ok(parse(&s)),
            None => invalid(),
        },
        Some("meet") if exact_keys(input, &["op", "a", "b"]).is_ok() => {
            match (text(input, "a"), text(input, "b")) {
                (Some(a), Some(b)) => ok(meet(parse(&a), parse(&b))),
                _ => invalid(),
            }
        }
        Some("compose") if exact_keys(input, &["op", "verdicts"]).is_ok() => {
            let Some(list) = input.get("verdicts").and_then(Json::as_array) else {
                return invalid();
            };
            let mut parsed = Vec::with_capacity(list.len());
            for item in list {
                match item.as_string() {
                    Some(s) => parsed.push(parse(&s)),
                    None => return invalid(),
                }
            }
            ok(compose(parsed))
        }
        Some("parse" | "meet" | "compose") | None => invalid(),
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
    fn lattice_ops() {
        assert_eq!(
            run(r#"{"op":"meet","a":"ALLOW","b":"DENY"}"#),
            Output::Ok(Json::str("DENY"))
        );
        assert_eq!(
            run(r#"{"op":"parse","s":"nonsense"}"#),
            Output::Ok(Json::str("DENY"))
        );
        assert_eq!(
            run(r#"{"op":"compose","verdicts":["ALLOW","ALLOW"]}"#),
            Output::Ok(Json::str("ALLOW"))
        );
    }

    #[test]
    fn wrong_shape_is_invalid_input() {
        for bad in [
            r#"{}"#,
            r#"{"op":"meet","a":"ALLOW"}"#,
            r#"{"op":"compose","verdicts":[1]}"#,
            r#"{"op":"parse","s":1}"#,
            r#"{"op":"parse","s":"ALLOW","x":1}"#,
        ] {
            assert_eq!(run(bad), Output::Error("invalid_input".into()), "{bad}");
        }
        assert_eq!(run(r#"{"op":"nope"}"#), Output::Error("unknown_op".into()));
    }
}
