//! "Always allow" and "always deny": `<home>/learned.json`, `{"choices": {"*|server|tool": "allow"}}`.
//! The key is the policy engine's `learned_key("*", server, tool)`: it applies to every client
//! and to every argument of that tool. A matching deny rule in the policy still wins, as in
//! the oracle. An unreadable file means no learned choices (never more permissive).

use std::path::Path;

use serde_json::{Value, json};

/// The recorded choices as `(key, "allow" | "deny")`.
pub fn load(path: &Path) -> Vec<(String, String)> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    v.get("choices")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, d)| Some((k.clone(), d.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// Records `choice` ("allow" or "deny") for `server/tool`, replacing an earlier choice.
pub fn record(path: &Path, server: &str, tool: &str, choice: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut choices: serde_json::Map<String, Value> = load(path)
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();
    choices.insert(
        dos_decision::learned_key("*", server, tool),
        Value::String(choice.to_owned()),
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(json!({ "choices": choices }).to_string().as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}
