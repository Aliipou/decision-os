//! The gateway home (`~/.decision-os`): policy, audit log, audit key, locks.
//! The layout is the Python gateway's, so both can share one home:
//! `policy.toml`, `audit.jsonl`, `locks/audit.lock`, plus `keys/audit.key` (new).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use dos_core::sign::{hex_decode_array, hex_encode};

pub struct Home(pub PathBuf);

impl Home {
    pub fn policy(&self) -> PathBuf {
        self.0.join("policy.toml")
    }
    pub fn audit(&self) -> PathBuf {
        self.0.join("audit.jsonl")
    }
    pub fn approvals(&self) -> PathBuf {
        self.0.join("approvals")
    }
    pub fn lock(&self) -> PathBuf {
        self.0.join("locks").join("audit.lock")
    }
    pub fn key(&self) -> PathBuf {
        self.0.join("keys").join("audit.key")
    }
}

/// `$HOME/.decision-os`, or `%USERPROFILE%\.decision-os`.
pub fn default_home() -> Option<PathBuf> {
    let base = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()))?;
    Some(PathBuf::from(base).join(".decision-os"))
}

/// A new random 32-byte key as hex.
pub fn new_secret_hex() -> Result<String, String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| format!("no randomness: {e}"))?;
    Ok(hex_encode(&secret))
}

/// Creates `path` with `contents` only if it does not exist (never overwrites), atomically:
/// the file is written under a temporary name and hard-linked into place, so a concurrent
/// reader never sees a half-written key. `Ok(false)` if it already existed.
pub fn create_new_file(path: &Path, contents: &str) -> std::io::Result<bool> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(contents.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if path.exists() && e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn read_key(path: &Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read key file {}: {e}", path.display()))?;
    hex_decode_array::<32>(text.trim())
        .map_err(|e| format!("key file {} is not 32 bytes of hex: {e}", path.display()))
}

/// The audit key of a home, created on first use.
pub fn ensure_key(home: &Home) -> Result<[u8; 32], String> {
    let path = home.key();
    if !path.exists() {
        let hex = new_secret_hex()?;
        create_new_file(&path, &hex)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    }
    read_key(&path)
}
