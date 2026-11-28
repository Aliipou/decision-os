//! Adapter manifests: `conformance/adapters/<name>/manifest.json`.
//!
//! ```json
//! {"v": 1, "command": ["./adapter"], "required": ["selftest"], "oracle": false}
//! ```
//!
//! `v`, `command`, `required` and `oracle` are required; `unsupported_ok` is optional
//! (default empty) and no other field is allowed. `command` is an argv
//! (never split by a shell); a first element starting with `./` is resolved against the
//! manifest's directory, which is also the adapter's working directory. `required`
//! lists areas the adapter must fully support whenever they are selected.
//! `unsupported_ok` lists the only areas where `unsupported` answers are tolerated; an
//! `unsupported` answer in any other area fails the run. `oracle`
//! selects `oracle_expected` when a vector has one.

use crate::json::{self, Json};
use crate::protocol::exact_keys;
use crate::vector::valid_ident;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Manifest {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub dir: PathBuf,
    pub required: Vec<String>,
    /// Areas whose `unsupported` answers are tolerated (the adapter does not implement
    /// them yet). With a manifest, an `unsupported` answer in any other area fails the
    /// run, so a dropped handler cannot pass silently.
    pub unsupported_ok: Vec<String>,
    pub oracle: bool,
}

pub fn load(path: &Path) -> Result<Manifest, String> {
    let at = |e: String| format!("{}: {e}", path.display());
    let text = std::fs::read_to_string(path).map_err(|e| at(e.to_string()))?;
    let j = json::parse(&text).map_err(|e| at(format!("invalid JSON: {e}")))?;
    // `unsupported_ok` is optional; every other member is required.
    let keys: &[&str] = if j.get("unsupported_ok").is_some() {
        &["v", "command", "required", "unsupported_ok", "oracle"]
    } else {
        &["v", "command", "required", "oracle"]
    };
    exact_keys(&j, keys).map_err(at)?;
    if j.get("v") != Some(&Json::uint(1)) {
        return Err(at("\"v\" must be the number 1".into()));
    }
    let strings = |k: &str| -> Result<Vec<String>, String> {
        let arr = j
            .get(k)
            .and_then(Json::as_array)
            .ok_or_else(|| at(format!("{k:?} must be an array")))?;
        arr.iter()
            .map(|v| {
                v.as_string()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| at(format!("{k:?} must hold non-empty strings")))
            })
            .collect()
    };
    let command = strings("command")?;
    let required = strings("required")?;
    let unsupported_ok = if j.get("unsupported_ok").is_some() {
        strings("unsupported_ok")?
    } else {
        Vec::new()
    };
    let oracle = j
        .get("oracle")
        .and_then(Json::as_bool)
        .ok_or_else(|| at("\"oracle\" must be a boolean".into()))?;
    let Some((first, rest)) = command.split_first() else {
        return Err(at("\"command\" must not be empty".into()));
    };
    for (i, a) in required.iter().enumerate() {
        if !valid_ident(a) {
            return Err(at(format!("invalid area {a:?} in \"required\"")));
        }
        if required.iter().take(i).any(|b| b == a) {
            return Err(at(format!("area {a:?} listed twice in \"required\"")));
        }
    }
    for (i, a) in unsupported_ok.iter().enumerate() {
        if !valid_ident(a) {
            return Err(at(format!("invalid area {a:?} in \"unsupported_ok\"")));
        }
        if unsupported_ok.iter().take(i).any(|b| b == a) {
            return Err(at(format!("area {a:?} listed twice in \"unsupported_ok\"")));
        }
        if required.contains(a) {
            return Err(at(format!(
                "area {a:?} is both \"required\" and \"unsupported_ok\""
            )));
        }
    }
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let dir = if dir.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        dir
    };
    // Absolute, because a relative program path combined with a working directory is
    // resolved differently per platform by std::process.
    let dir = std::fs::canonicalize(&dir).map_err(|e| at(format!("{}: {e}", dir.display())))?;
    let program = match first.strip_prefix("./") {
        Some(rel) => dir.join(rel),
        None => PathBuf::from(first),
    };
    Ok(Manifest {
        program,
        args: rest.to_vec(),
        dir,
        required,
        unsupported_ok,
        oracle,
    })
}
