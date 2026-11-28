//! Replays every vector in `conformance/vectors/meet/` through the Rust lattice.
//! The vectors were generated from the frozen oracle (conformance/gen/verdict_from_oracle.py).
//! Rust is checked against `expected`, never against `oracle_expected`.

use std::path::{Path, PathBuf};

use dos_core::verdict::{Verdict, compose, meet, parse};
use serde_json::Value;

/// The suite must not pass by being empty or truncated.
const MIN_VECTORS: usize = 80;

fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/meet")
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}"))
}

fn run(input: &Value) -> Result<Verdict, String> {
    match str_field(input, "op")? {
        "meet" => Ok(meet(
            parse(str_field(input, "a")?),
            parse(str_field(input, "b")?),
        )),
        "parse" => Ok(parse(str_field(input, "s")?)),
        "compose" => {
            let list = input
                .get("verdicts")
                .and_then(Value::as_array)
                .ok_or("missing verdicts array")?;
            let mut parsed = Vec::new();
            for item in list {
                parsed.push(parse(item.as_str().ok_or("non-string verdict in vector")?));
            }
            Ok(compose(parsed))
        }
        other => Err(format!("unknown op {other}")),
    }
}

fn check(path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let case: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("bad file name")?;
    if case.get("v").and_then(Value::as_u64) != Some(1) {
        return Err("v must be 1".into());
    }
    if str_field(&case, "area")? != "meet" {
        return Err("area must be meet".into());
    }
    if str_field(&case, "name")? != stem {
        return Err("name must equal the file name".into());
    }
    let input = case.get("input").ok_or("missing input")?;
    let want = case
        .get("expected")
        .and_then(|e| e.get("ok"))
        .and_then(Value::as_str)
        .ok_or("expected must be {\"ok\": <verdict string>}")?;
    let got = run(input)?.as_str();
    if got != want {
        return Err(format!("got {got}, expected {want}"));
    }
    Ok(())
}

#[test]
fn every_meet_vector_passes() -> Result<(), String> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(vector_dir())
        .map_err(|e| format!("{}: {e}", vector_dir().display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    let mut failures = Vec::new();
    for p in &paths {
        if let Err(e) = check(p) {
            failures.push(format!("{}: {e}", p.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "failing vectors:\n{}",
        failures.join("\n")
    );
    assert!(
        paths.len() >= MIN_VECTORS,
        "only {} vectors found, expected at least {MIN_VECTORS}",
        paths.len()
    );
    Ok(())
}
