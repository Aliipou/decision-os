//! Loading and validating `conformance/vectors/<area>/<name>.json` (spec/CONFORMANCE.md).
//!
//! Every deviation from the format is a hard error, collected for the whole tree, so a
//! typo can never turn a case into a silently skipped or silently passing one.

use crate::json::{self, Json};
use crate::protocol::Output;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Largest vector file accepted.
pub const MAX_VECTOR_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Vector {
    pub area: String,
    pub name: String,
    pub input: Json,
    pub expected: Output,
    pub oracle_expected: Option<Output>,
    pub gap: Option<String>,
    pub source: String,
    pub path: PathBuf,
}

impl Vector {
    /// What `adapter` must answer: `oracle_expected` for the oracle when present.
    pub fn want(&self, oracle: bool) -> &Output {
        match (&self.oracle_expected, oracle) {
            (Some(o), true) => o,
            _ => &self.expected,
        }
    }
}

/// Areas and names: `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 128 bytes. Keeps file names
/// portable and every output line unambiguous.
pub fn valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && s.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// All areas under `root`, each with its vectors sorted by name. An area directory with
/// no vectors maps to an empty list (the runner refuses it if selected).
pub fn load_all(root: &Path) -> Result<BTreeMap<String, Vec<Vector>>, Vec<String>> {
    let mut errors = Vec::new();
    let mut areas = BTreeMap::new();
    let entries = match sorted_entries(root) {
        Ok(e) => e,
        Err(e) => return Err(vec![e]),
    };
    let mut folded: BTreeMap<String, String> = BTreeMap::new();
    for (name, path) in entries {
        let is_dir = fs::symlink_metadata(&path)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if !is_dir {
            errors.push(format!(
                "{}: only area directories may be in the vectors directory",
                path.display()
            ));
            continue;
        }
        if !valid_ident(&name) {
            errors.push(format!("{}: invalid area name", path.display()));
            continue;
        }
        if let Some(prev) = folded.insert(name.to_ascii_lowercase(), name.clone()) {
            errors.push(format!(
                "{}: area name collides with {prev:?} on case-insensitive filesystems",
                path.display()
            ));
            continue;
        }
        match load_area(&name, &path) {
            Ok(v) => {
                areas.insert(name, v);
            }
            Err(mut e) => errors.append(&mut e),
        }
    }
    if errors.is_empty() {
        Ok(areas)
    } else {
        Err(errors)
    }
}

fn sorted_entries(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let rd = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{}: file name is not UTF-8", path.display()))?;
        out.push((name, path));
    }
    out.sort();
    Ok(out)
}

fn load_area(area: &str, dir: &Path) -> Result<Vec<Vector>, Vec<String>> {
    let mut errors = Vec::new();
    let mut out = Vec::new();
    let entries = sorted_entries(dir).map_err(|e| vec![e])?;
    let mut folded: BTreeMap<String, String> = BTreeMap::new();
    for (file, path) in entries {
        let regular = fs::symlink_metadata(&path)
            .map(|m| m.is_file())
            .unwrap_or(false);
        let Some(stem) = file.strip_suffix(".json").filter(|_| regular) else {
            errors.push(format!(
                "{}: only regular <name>.json files may be in an area directory",
                path.display()
            ));
            continue;
        };
        if let Some(prev) = folded.insert(stem.to_ascii_lowercase(), stem.to_owned()) {
            errors.push(format!(
                "{}: name collides with {prev:?} on case-insensitive filesystems",
                path.display()
            ));
            continue;
        }
        match load_one(area, stem, &path) {
            Ok(v) => out.push(v),
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

const REQUIRED: [&str; 6] = ["v", "area", "name", "input", "expected", "source"];
const OPTIONAL: [&str; 3] = ["oracle_expected", "gap", "divergence"];

fn load_one(area: &str, stem: &str, path: &Path) -> Result<Vector, String> {
    let size = fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > MAX_VECTOR_BYTES {
        return Err(format!("larger than {MAX_VECTOR_BYTES} bytes"));
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let text = String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned())?;
    if text.starts_with('\u{feff}') {
        return Err("starts with a byte order mark".into());
    }
    if text.contains('\r') {
        return Err("contains CR; vector files are LF only".into());
    }
    let j = json::parse(&text).map_err(|e| format!("invalid JSON: {e}"))?;
    let keys = j.keys();
    if j.as_object().is_none() {
        return Err("a vector must be a JSON object".into());
    }
    for k in &keys {
        if !REQUIRED.contains(&k.as_str()) && !OPTIONAL.contains(&k.as_str()) {
            return Err(format!("unknown field {k:?}"));
        }
    }
    for k in REQUIRED {
        if j.get(k).is_none() {
            return Err(format!("missing field {k:?}"));
        }
    }
    if j.get("v") != Some(&Json::uint(1)) {
        return Err("\"v\" must be the number 1".into());
    }
    let field_str = |k: &str| -> Result<Option<String>, String> {
        match j.get(k) {
            None => Ok(None),
            Some(v) => match v.as_string() {
                Some(s) if !s.is_empty() => Ok(Some(s)),
                _ => Err(format!("{k:?} must be a non-empty string")),
            },
        }
    };
    let v_area = field_str("area")?.unwrap_or_default();
    let v_name = field_str("name")?.unwrap_or_default();
    let source = field_str("source")?.unwrap_or_default();
    let gap = field_str("gap")?;
    if v_area != area {
        return Err(format!(
            "area {v_area:?} does not match its directory {area:?}"
        ));
    }
    if v_name != stem {
        return Err(format!(
            "name {v_name:?} does not match its file name {stem:?}"
        ));
    }
    if !valid_ident(stem) {
        return Err("invalid name (allowed: [A-Za-z0-9][A-Za-z0-9._-]*, at most 128 bytes)".into());
    }
    let input = j.get("input").cloned().unwrap_or(Json::Null);
    if input.as_object().is_none() {
        return Err("\"input\" must be an object".into());
    }
    let parse_expected = |k: &str| -> Result<Option<Output>, String> {
        match j.get(k) {
            None => Ok(None),
            Some(v) => Output::from_json(v, false)
                .map(Some)
                .map_err(|e| format!("{k:?}: {e}")),
        }
    };
    let expected = parse_expected("expected")?.ok_or("missing field \"expected\"")?;
    let oracle_expected = parse_expected("oracle_expected")?;
    Ok(Vector {
        area: area.to_owned(),
        name: stem.to_owned(),
        input,
        expected,
        oracle_expected,
        gap,
        source,
        path: path.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::valid_ident;

    #[test]
    fn idents() {
        for ok in ["a", "rfc8785-3.2.2-numbers", "A_b.c-1", "0"] {
            assert!(valid_ident(ok), "{ok}");
        }
        let long = "a".repeat(129);
        for bad in [
            "",
            ".a",
            "-a",
            "_a",
            "a b",
            "a/b",
            "a\\b",
            "é",
            "a:b",
            long.as_str(),
        ] {
            assert!(!valid_ident(bad), "{bad}");
        }
    }
}
