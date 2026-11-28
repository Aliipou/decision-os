//! Runs every conformance/vectors/jcs/*.json case through `canonicalize`.
//! Vector format: spec/CONFORMANCE.md; jcs inputs: spec/canon.md.

use dos_core::canon::{self, Value};
use std::path::PathBuf;

fn member<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn string<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    match member(v, key) {
        Some(Value::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

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

fn run_case(path: &PathBuf) -> Result<(), String> {
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    let case = canon::parse_strict(&raw).map_err(|e| format!("vector file: {}", e.code()))?;
    let name = string(&case, "name").ok_or("no name")?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("bad file name")?;
    if name != stem || string(&case, "area") != Some("jcs") {
        return Err(format!("name {name:?} or area does not match file"));
    }
    let input = member(&case, "input").ok_or("no input")?;
    let bytes = match (string(input, "text"), string(input, "bytes_hex")) {
        (Some(t), None) => t.as_bytes().to_vec(),
        (None, Some(h)) => from_hex(h).ok_or("bad bytes_hex")?,
        _ => return Err("input needs exactly one of text, bytes_hex".into()),
    };
    let expected = member(&case, "expected").ok_or("no expected")?;
    let got = canon::canonicalize(&bytes);
    match (string(expected, "ok"), string(expected, "error"), got) {
        (Some(want), None, Ok(out)) if out == want.as_bytes() => Ok(()),
        (None, Some(code), Err(e)) if e.code() == code => Ok(()),
        (w, c, g) => Err(format!(
            "expected ok={w:?} error={c:?}, got {:?}",
            g.map(|o| String::from_utf8_lossy(&o).into_owned())
                .map_err(|e| e.code())
        )),
    }
}

#[test]
fn jcs_vectors() -> Result<(), String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/jcs");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    let mut failures = Vec::new();
    for p in &paths {
        if let Err(e) = run_case(p) {
            failures.push(format!("{}: {e}", p.display()));
        }
    }
    assert!(paths.len() >= 60, "only {} jcs vectors", paths.len());
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    Ok(())
}
