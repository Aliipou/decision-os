//! The adapter protocol of `spec/CONFORMANCE.md`: request and response lines, and a
//! [`serve`] loop that any Rust adapter can use with a table of area handlers.

use crate::json::{self, Json};
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

/// What an implementation answered for one case (also the shape of `expected`).
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    Ok(Json),
    Error(String),
    Unsupported,
}

impl Output {
    pub fn to_json(&self) -> Json {
        match self {
            Output::Ok(v) => Json::obj([("ok", v.clone())]),
            Output::Error(c) => Json::obj([("error", Json::str(c))]),
            Output::Unsupported => Json::obj([("unsupported", Json::Bool(true))]),
        }
    }

    /// Parse `{"ok": v}`, `{"error": "<non-empty>"}` or, if `allow_unsupported`,
    /// `{"unsupported": true}`. Anything else (extra keys, wrong types) is refused.
    pub fn from_json(j: &Json, allow_unsupported: bool) -> Result<Output, String> {
        let m = j.as_object().ok_or("output must be an object")?;
        let [(k, v)] = m else {
            return Err(format!(
                "output must have exactly one key, has {:?}",
                j.keys()
            ));
        };
        if k.is("ok") {
            Ok(Output::Ok(v.clone()))
        } else if k.is("error") {
            match v.as_string() {
                Some(c) if !c.is_empty() => Ok(Output::Error(c)),
                _ => Err("error must be a non-empty string".into()),
            }
        } else if k.is("unsupported") && allow_unsupported {
            match v {
                Json::Bool(true) => Ok(Output::Unsupported),
                _ => Err("unsupported must be true".into()),
            }
        } else {
            Err(format!(
                "unknown output key {:?}",
                String::from_utf16_lossy(k.units())
            ))
        }
    }
}

/// One request line (without the newline).
pub fn request_line(area: &str, name: &str, input: &Json) -> String {
    // Fixed member order: area, name, input.
    json::write(&Json::obj([
        ("area", Json::str(area)),
        ("name", Json::str(name)),
        ("input", input.clone()),
    ]))
}

/// One response line (without the newline).
pub fn response_line(name: &str, output: &Output) -> String {
    json::write(&Json::obj([
        ("name", Json::str(name)),
        ("output", output.to_json()),
    ]))
}

/// Check that `obj` has exactly the keys `want` (any order).
pub fn exact_keys(obj: &Json, want: &[&str]) -> Result<(), String> {
    let keys = obj.keys();
    let mut sorted_have = keys.clone();
    sorted_have.sort();
    let mut sorted_want: Vec<String> = want.iter().map(|s| (*s).to_owned()).collect();
    sorted_want.sort();
    if obj.as_object().is_none() {
        return Err("expected an object".into());
    }
    if sorted_have != sorted_want {
        return Err(format!("keys must be exactly {want:?}, found {keys:?}"));
    }
    Ok(())
}

/// Parse a response line (newline already removed) into (name, output).
pub fn parse_response(line: &str) -> Result<(String, Output), String> {
    let j = json::parse(line).map_err(|e| format!("invalid JSON: {e}"))?;
    exact_keys(&j, &["name", "output"])?;
    let name = j
        .get("name")
        .and_then(Json::as_string)
        .ok_or("name must be a string")?;
    let out = j.get("output").ok_or("no output")?;
    Ok((name, Output::from_json(out, true)?))
}

/// Parse a request line into (area, name, input).
pub fn parse_request(line: &str) -> Result<(String, String, Json), String> {
    let j = json::parse(line).map_err(|e| format!("invalid JSON: {e}"))?;
    exact_keys(&j, &["area", "name", "input"])?;
    let area = j
        .get("area")
        .and_then(Json::as_string)
        .ok_or("area must be a string")?;
    let name = j
        .get("name")
        .and_then(Json::as_string)
        .ok_or("name must be a string")?;
    let input = j.get("input").ok_or("no input")?.clone();
    Ok((area, name, input))
}

/// An area handler: the vector's `input` to the implementation's output.
pub type Handler = fn(&Json) -> Output;

/// Adapter main loop: answer every request line on stdin with one line on stdout, in
/// order, using `areas` (unknown areas answer `unsupported`). A malformed request is a
/// runner bug or an attack: report it on stderr and exit 2 without answering.
pub fn serve(areas: &[(&str, Handler)]) -> ExitCode {
    match serve_io(areas, io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("adapter: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn serve_io(
    areas: &[(&str, Handler)],
    mut input: impl BufRead,
    mut out: impl Write,
) -> Result<(), String> {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = input
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Ok(());
        }
        if buf.pop() != Some(b'\n') {
            return Err("request line without newline".into());
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        let line = std::str::from_utf8(&buf).map_err(|_| "request is not UTF-8".to_owned())?;
        let (area, name, input_value) = parse_request(line)?;
        let output = match areas.iter().find(|(a, _)| *a == area) {
            Some((_, handler)) => handler(&input_value),
            None => Output::Unsupported,
        };
        writeln!(out, "{}", response_line(&name, &output)).map_err(|e| format!("write: {e}"))?;
        out.flush().map_err(|e| format!("flush: {e}"))?;
    }
}
