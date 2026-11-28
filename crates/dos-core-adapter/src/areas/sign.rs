//! The `sign` area (spec/sign.md, "Conformance input").
//!
//! - `sign`: `{"op":"sign","domain","payload_hex"}` -> `{"sig","kid"}` under the fixed
//!   RFC 8032 TEST 1 key (a test key, never accepted by a production key store).
//! - `verify`: `{"op":"verify","domain","payload_hex","sig"}` plus optional
//!   `"public_key"` (default: the test key) and `"kid"` (expected kid). Check order:
//!   domain, payload hex, public key, then kid and signature via `verify_wire`.
//! - `kid`: `{"op":"kid","public_key"}` -> the 32-hex kid of the key.

use dos_conformance::json::Json;
use dos_conformance::protocol::Output;
use dos_core::sign::{Domain, SignError, SigningKey, VerifyingKey, hex_decode, hex_decode_array};

const TEST1_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn invalid() -> Output {
    Output::Error("invalid_input".into())
}

fn text(input: &Json, key: &str) -> Option<String> {
    input.get(key).and_then(Json::as_string)
}

fn test_key() -> Result<SigningKey, SignError> {
    Ok(SigningKey::from_bytes(&hex_decode_array::<32>(
        TEST1_SECRET,
    )?))
}

fn err(e: SignError) -> Output {
    Output::Error(e.code().into())
}

fn sign(input: &Json) -> Output {
    let Some(tag) = text(input, "domain") else {
        return invalid();
    };
    let r = test_key().and_then(|key| {
        let domain = Domain::from_tag(&tag)?;
        // An absent payload is the invalid hex "\0", so it reads as `bad_hex`.
        let payload = hex_decode(&text(input, "payload_hex").unwrap_or_else(|| "\u{0}".into()))?;
        let sig = key.sign(domain, &payload);
        Ok(Json::obj([
            ("sig", Json::str(&sig.to_hex())),
            ("kid", Json::str(&key.kid().to_hex())),
        ]))
    });
    match r {
        Ok(v) => Output::Ok(v),
        Err(e) => err(e),
    }
}

fn verify(input: &Json) -> Output {
    let r = (|| {
        let domain = Domain::from_tag(&text(input, "domain").unwrap_or_default())?;
        let payload = hex_decode(&text(input, "payload_hex").unwrap_or_else(|| "\u{0}".into()))?;
        let vk = match text(input, "public_key") {
            Some(pk) => VerifyingKey::from_hex(&pk)?,
            None => test_key()?.verifying_key(),
        };
        let kid = text(input, "kid");
        vk.verify_wire(
            domain,
            &payload,
            kid.as_deref(),
            &text(input, "sig").unwrap_or_default(),
        )
    })();
    match r {
        Ok(()) => Output::Ok(Json::Bool(true)),
        Err(e) => err(e),
    }
}

fn kid(input: &Json) -> Output {
    let Some(pk) = text(input, "public_key") else {
        return invalid();
    };
    match VerifyingKey::from_hex(&pk) {
        Ok(vk) => Output::Ok(Json::str(&vk.kid().to_hex())),
        Err(e) => err(e),
    }
}

pub fn handle(input: &Json) -> Output {
    match text(input, "op").as_deref() {
        Some("sign") => sign(input),
        Some("verify") => verify(input),
        Some("kid") => kid(input),
        None => invalid(),
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
    fn test_key_kid_and_roundtrip() {
        assert_eq!(
            run(
                r#"{"op":"kid","public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"}"#
            ),
            Output::Ok(Json::str("b1f1515d964ca23d4f37283c507551d3"))
        );
        let Output::Ok(out) = run(r#"{"op":"sign","domain":"decision","payload_hex":"00ff"}"#)
        else {
            return;
        };
        let sig = out.get("sig").and_then(Json::as_string).unwrap_or_default();
        let req =
            format!(r#"{{"op":"verify","domain":"decision","payload_hex":"00ff","sig":"{sig}"}}"#);
        assert_eq!(run(&req), Output::Ok(Json::Bool(true)));
        // A different payload does not verify.
        let bad = req.replace("00ff", "00fe");
        assert_eq!(run(&bad), Output::Error("bad_signature".into()));
    }

    #[test]
    fn refusals() {
        assert_eq!(run(r#"{}"#), Output::Error("invalid_input".into()));
        assert_eq!(run(r#"{"op":"nope"}"#), Output::Error("unknown_op".into()));
        assert_eq!(
            run(r#"{"op":"sign","domain":"nope","payload_hex":""}"#),
            Output::Error("unknown_domain".into())
        );
    }
}
