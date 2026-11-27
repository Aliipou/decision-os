//! The `audit` area: `{"op":"verify","log":[line,...],"keys":{kid:pubhex},
//! "anchor":{"seq":n,"entry_hash":h}?,"python_compat":bool?,"final_newline":bool?}`
//! -> `{"ok":{"entries":n}}` or `{"error":<VerifyErrorKind code>}`.

use dos_audit::{Head, VerifyOptions, verify_bytes};
use dos_conformance::json::Json;
use dos_conformance::protocol::Output;
use dos_core::sign::hex_decode_array;
use dos_core::store::{KeyStore, StoreError};

struct Keys(Vec<(String, [u8; 32])>);

impl KeyStore for Keys {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(self.0.iter().find(|(k, _)| k == kid).map(|(_, v)| *v))
    }
}

fn parse_keys(j: &Json) -> Option<Keys> {
    let members = j.as_object()?;
    let mut out = Vec::new();
    for (k, v) in members {
        let kid = k.to_string_strict()?;
        let pk = hex_decode_array::<32>(&v.as_string()?).ok()?;
        out.push((kid, pk));
    }
    Some(Keys(out))
}

fn parse_anchor(j: &Json) -> Option<Head> {
    let seq = match j.get("seq")? {
        Json::Number(n) => n.lexeme().parse::<u64>().ok()?,
        _ => return None,
    };
    Some(Head {
        seq,
        entry_hash: j.get("entry_hash")?.as_string()?,
    })
}

pub fn handle(input: &Json) -> Output {
    let invalid = || Output::Error("invalid_input".into());
    match input.get("op").and_then(Json::as_string).as_deref() {
        Some("verify") => {}
        Some(_) => return Output::Error("unknown_op".into()),
        None => return invalid(),
    }
    let Some(lines) = input.get("log").and_then(Json::as_array) else {
        return invalid();
    };
    let Some(keys) = input.get("keys").and_then(parse_keys) else {
        return invalid();
    };
    let anchor = match input.get("anchor") {
        None => None,
        Some(a) => match parse_anchor(a) {
            Some(h) => Some(h),
            None => return invalid(),
        },
    };
    let flag = |name: &str, default: bool| match input.get(name) {
        None => Some(default),
        Some(v) => v.as_bool(),
    };
    let (Some(python_compat), Some(final_newline)) =
        (flag("python_compat", false), flag("final_newline", true))
    else {
        return invalid();
    };
    let mut bytes = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let Some(s) = l.as_string() else {
            return invalid();
        };
        if i > 0 {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(s.as_bytes());
    }
    if !bytes.is_empty() && final_newline {
        bytes.push(b'\n');
    }
    let opts = VerifyOptions {
        keys: &keys,
        now_unix_ms: 0,
        python_compat,
        anchor,
    };
    match verify_bytes(&bytes, &opts) {
        Ok(v) => Output::Ok(Json::obj([("entries", Json::uint(v.entries))])),
        Err(e) => Output::Error(e.kind.code().into()),
    }
}
