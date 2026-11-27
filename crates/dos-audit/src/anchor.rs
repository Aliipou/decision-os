//! Out-of-band chain head ("anchor"). Without one, deleting the last N entries leaves a
//! shorter chain that still verifies (HB-2). `FileSink` always has an anchor.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use dos_core::canon::{self, Value};
use dos_core::sign::{Domain, Kid, Signature, SigningKey, VerifyingKey, hex_encode};
use dos_core::store::{KeyStore, StoreError};

use crate::entry::{seq_field, seq_value, str_field};
use crate::verify::{VerifyError, VerifyErrorKind};

/// A chain head: the last entry's position and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub entry_hash: String,
}

/// Receives each new head after the entry is durable. An error propagates to the
/// caller of `append` (fail closed). Publish to something the log's writer cannot
/// rewrite (a WORM bucket, another host) for real tamper-evidence.
pub trait Anchor: Send + Sync {
    fn publish(&self, head: &Head) -> Result<(), StoreError>;

    /// The latest published head, `Ok(None)` if none was ever published. The sink checks
    /// the log against it before every append, so a log that was truncated, wiped or
    /// replaced is never silently continued. An anchor that cannot answer returns
    /// `Ok(None)` (the default): then the sink cannot detect truncation itself.
    fn latest(&self) -> Result<Option<Head>, StoreError> {
        Ok(None)
    }
}

/// Latest head as a signed one-line JSON file, replaced atomically (temp file + rename).
/// The signature stops forging a head; it does not stop deleting or rolling back the
/// file, which is why the anchor should live elsewhere in production.
pub struct FileAnchor {
    path: PathBuf,
    key: SigningKey,
}

impl FileAnchor {
    pub fn new(path: impl Into<PathBuf>, key: SigningKey) -> FileAnchor {
        FileAnchor {
            path: path.into(),
            key,
        }
    }
}

/// Signed bytes of a head: JCS of `{entry_hash, kid, seq}` under `Domain::AuditHead`.
fn head_payload(kid: &str, head: &Head) -> Result<Vec<u8>, canon::CanonError> {
    canon::to_jcs(&Value::Object(vec![
        ("entry_hash".into(), Value::String(head.entry_hash.clone())),
        ("kid".into(), Value::String(kid.into())),
        ("seq".into(), seq_value(head.seq)?),
    ]))
}

struct OneKey(String, [u8; 32]);

impl KeyStore for OneKey {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok((kid == self.0).then_some(self.1))
    }
}

impl Anchor for FileAnchor {
    fn latest(&self) -> Result<Option<Head>, StoreError> {
        let vk = self.key.verifying_key();
        let keys = OneKey(self.key.kid().to_hex(), vk.to_bytes());
        // A present but unreadable, unsigned or foreign anchor is an error, not "none".
        read_anchor_file(&self.path, &keys, 0).map_err(|_| StoreError::Unavailable)
    }

    fn publish(&self, head: &Head) -> Result<(), StoreError> {
        let kid = self.key.kid().to_hex();
        let payload = head_payload(&kid, head).map_err(|_| StoreError::InvalidInput)?;
        let sig = self.key.sign(Domain::AuditHead, &payload);
        let line = canon::to_jcs(&Value::Object(vec![
            ("entry_hash".into(), Value::String(head.entry_hash.clone())),
            ("kid".into(), Value::String(kid)),
            (
                "seq".into(),
                seq_value(head.seq).map_err(|_| StoreError::InvalidInput)?,
            ),
            ("sig".into(), Value::String(hex_encode(&sig.to_bytes()))),
        ]))
        .map_err(|_| StoreError::InvalidInput)?;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&line)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)
        };
        write().map_err(|_| StoreError::Unavailable)
    }
}

fn anchor_err(kind: VerifyErrorKind) -> VerifyError {
    VerifyError { line: None, kind }
}

/// Reads and verifies a `FileAnchor` file. `Ok(None)` if the file does not exist.
pub fn read_anchor_file(
    path: &Path,
    keys: &dyn KeyStore,
    now_unix_ms: i64,
) -> Result<Option<Head>, VerifyError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(anchor_err(VerifyErrorKind::Io)),
    };
    let bad = || anchor_err(VerifyErrorKind::AnchorInvalid);
    let text = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let Value::Object(m) = canon::parse_strict(text).map_err(|_| bad())? else {
        return Err(bad());
    };
    if m.len() != 4 {
        return Err(bad());
    }
    let head = Head {
        seq: seq_field(&m).ok_or_else(bad)?,
        entry_hash: str_field(&m, "entry_hash").ok_or_else(bad)?.to_string(),
    };
    let kid_hex = str_field(&m, "kid").ok_or_else(bad)?;
    let sig = Signature::from_hex(str_field(&m, "sig").ok_or_else(bad)?).map_err(|_| bad())?;
    let key = keys
        .verifying_key(kid_hex, now_unix_ms)
        .map_err(|_| anchor_err(VerifyErrorKind::Io))?
        .ok_or_else(|| anchor_err(VerifyErrorKind::UnknownKey))?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| bad())?;
    let kid = Kid::from_hex(kid_hex).map_err(|_| bad())?;
    let payload = head_payload(kid_hex, &head).map_err(|_| bad())?;
    key.verify_with_kid(Domain::AuditHead, &payload, &sig, &kid)
        .map_err(|_| anchor_err(VerifyErrorKind::BadSignature))?;
    Ok(Some(head))
}
