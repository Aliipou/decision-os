//! `state.json`: the original of every wrapped entry and, per file, the backup that is
//! eligible for a byte-exact restore. Same format as the oracle, so a Rust uninstall
//! restores what the Python gateway installed.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::InstallError;
use crate::fsio;
use crate::pyjson::{self, Indent};

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone, Debug)]
pub(crate) struct State {
    path: PathBuf,
    /// every other top-level key, kept as read (version, python, updated, ...)
    rest: Map<String, Value>,
    entries: Map<String, Value>,
    files: Map<String, Value>,
}

/// Python `json.dumps([str(path), list(pointer), name])`: the entry key.
pub(crate) fn key(path: &str, pointer: &[String], name: &str) -> String {
    // strings only: formatting cannot fail
    pyjson::dumps_compact_ascii(&json!([path, pointer, name])).unwrap_or_default()
}

fn take_map(data: &mut Map<String, Value>, k: &str, path: &Path) -> Result<Map<String, Value>, InstallError> {
    match data.shift_remove(k) {
        None => Ok(Map::new()),
        Some(Value::Object(m)) => Ok(m),
        Some(_) => Err(InstallError::StateCorrupt(path.to_path_buf())),
    }
}

impl State {
    /// Read the state. A state file that is not a JSON object is refused: starting
    /// over (as the oracle does) would lose every backup pointer.
    pub(crate) fn load(home: &Path) -> Result<State, InstallError> {
        let path = home.join("state.json");
        let mut data = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(Value::Object(m)) => m,
                _ => return Err(InstallError::StateCorrupt(path)),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Map::new(),
            Err(e) => return Err(InstallError::Io(path, e)),
        };
        if !data.contains_key("version") {
            data.insert("version".into(), json!(1));
        }
        let entries = take_map(&mut data, "entries", &path)?;
        let files = take_map(&mut data, "files", &path)?;
        Ok(State {
            path,
            rest: data,
            entries,
            files,
        })
    }

    pub(crate) fn remember(
        &mut self,
        path: &str,
        pointer: &[String],
        name: &str,
        client: &str,
        original: Value,
    ) {
        self.entries.insert(
            key(path, pointer, name),
            json!({"client": client, "original": original}),
        );
    }

    pub(crate) fn original(
        &self,
        path: &str,
        pointer: &[String],
        name: &str,
    ) -> Option<&Map<String, Value>> {
        self.entries
            .get(&key(path, pointer, name))?
            .get("original")?
            .as_object()
    }

    pub(crate) fn forget(&mut self, path: &str, pointer: &[String], name: &str) {
        self.entries.shift_remove(&key(path, pointer, name));
    }

    /// Record a write (oracle `State.wrote`): the backup stays eligible for a
    /// byte-exact restore only while nobody else touched the file between our writes.
    pub(crate) fn wrote(&mut self, path: &str, text: &[u8], backup: &Path, prior_sha256: &str) {
        let mut rec = match self.files.get(path).and_then(Value::as_object) {
            None => {
                let mut m = Map::new();
                m.insert("backup".into(), json!(backup.to_string_lossy()));
                m
            }
            Some(old) => {
                let mut m = old.clone();
                if m.get("written_sha256").and_then(Value::as_str) != Some(prior_sha256) {
                    m.insert("backup".into(), Value::Null);
                }
                m
            }
        };
        rec.insert("written_sha256".into(), json!(sha256_hex(text)));
        self.files.insert(path.to_string(), Value::Object(rec));
    }

    /// (backup path, sha256 of what we last wrote) when an exact restore is possible.
    pub(crate) fn exact_record(&self, path: &str) -> Option<(PathBuf, String)> {
        let rec = self.files.get(path)?;
        let backup = rec.get("backup")?.as_str().filter(|s| !s.is_empty())?;
        let sha = rec
            .get("written_sha256")?
            .as_str()
            .filter(|s| !s.is_empty())?;
        Some((PathBuf::from(backup), sha.to_string()))
    }

    pub(crate) fn drop_file_record(&mut self, path: &str) {
        self.files.shift_remove(path);
    }

    /// Forget the file and every entry recorded for it.
    pub(crate) fn drop_file(&mut self, path: &str) {
        self.drop_file_record(path);
        self.entries.retain(|k, _| {
            serde_json::from_str::<Value>(k)
                .ok()
                .and_then(|v| v.get(0).and_then(Value::as_str).map(|p| p != path))
                .unwrap_or(true)
        });
    }

    pub(crate) fn save(&mut self, binary: &str, updated: &str) -> Result<(), InstallError> {
        let mut data = self.rest.clone();
        data.insert("entries".into(), Value::Object(self.entries.clone()));
        data.insert("files".into(), Value::Object(self.files.clone()));
        data.insert("binary".into(), json!(binary));
        data.insert("updated".into(), json!(updated));
        let text = pyjson::dumps(&Value::Object(data), &Indent::Spaces(2), true)
            .map_err(|_| InstallError::StateCorrupt(self.path.clone()))?;
        fsio::atomic_write(&self.path, text.as_bytes(), None, true)
            .map_err(|e| InstallError::Io(self.path.clone(), e.into_io()))
    }
}
