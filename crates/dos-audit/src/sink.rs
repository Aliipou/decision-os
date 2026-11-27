//! `FileSink`: the `AuditSink` implementation.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use dos_core::canon::{self, Value};
use dos_core::sign::{Domain, SigningKey, hex_encode};
use dos_core::store::{AuditReceipt, AuditSink, StoreError};

use crate::anchor::{Anchor, FileAnchor, Head};
use crate::entry::{
    GENESIS, RESERVED, field, hash_of, seq_field, seq_value, signing_bytes, str_field,
};

#[derive(Clone)]
struct State {
    /// Log length in bytes the cached head describes.
    len: u64,
    next_seq: u64,
    last_hash: String,
}

/// Append-only signed hash-chained log in one file, safe across threads and processes.
pub struct FileSink {
    path: PathBuf,
    lock_path: PathBuf,
    key: SigningKey,
    anchor: Option<Box<dyn Anchor>>,
    state: Mutex<Option<State>>,
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

impl FileSink {
    /// Opens (creating if needed) the log at `path` with the default anchor: a signed
    /// head file at `<path>.anchor`, written with the same key.
    pub fn open(path: impl Into<PathBuf>, secret: &[u8; 32]) -> Result<FileSink, StoreError> {
        let path = path.into();
        let anchor = FileAnchor::new(with_suffix(&path, ".anchor"), SigningKey::from_bytes(secret));
        FileSink::open_with_anchor(path, secret, Some(Box::new(anchor)))
    }

    /// Like `open` with a caller-chosen anchor. `None` disables anchoring: tail
    /// truncation is then undetectable, so this is for tests and explicit opt-out.
    pub fn open_with_anchor(
        path: impl Into<PathBuf>,
        secret: &[u8; 32],
        anchor: Option<Box<dyn Anchor>>,
    ) -> Result<FileSink, StoreError> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir).map_err(|_| StoreError::Unavailable)?;
            }
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(FileSink {
            lock_path: with_suffix(&path, ".lock"),
            path,
            key: SigningKey::from_bytes(secret),
            anchor,
            state: Mutex::new(None),
        })
    }

    /// Current head from disk, `None` for an empty log. Errors if the tail is corrupt.
    pub fn head(&self) -> Result<Option<Head>, StoreError> {
        let bytes = fs::read(&self.path).map_err(|_| StoreError::Unavailable)?;
        let st = scan_tail(&bytes, bytes.len() as u64)?;
        Ok(st.next_seq.checked_sub(1).map(|seq| Head {
            seq,
            entry_hash: st.last_hash,
        }))
    }
}

/// Finds the head of the log bytes. Fails closed on anything but a clean tail.
fn scan_tail(bytes: &[u8], len: u64) -> Result<State, StoreError> {
    if bytes.is_empty() {
        return Ok(State {
            len,
            next_seq: 0,
            last_hash: GENESIS.into(),
        });
    }
    let body = bytes.strip_suffix(b"\n").ok_or(StoreError::Unavailable)?;
    let start = body.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let line = body.get(start..).ok_or(StoreError::Unavailable)?;
    let Value::Object(m) = canon::parse_strict(line).map_err(|_| StoreError::Unavailable)? else {
        return Err(StoreError::Unavailable);
    };
    let seq = seq_field(&m).ok_or(StoreError::Unavailable)?;
    let hash = str_field(&m, "entry_hash").ok_or(StoreError::Unavailable)?;
    if hash_of(&m).map_err(|_| StoreError::Unavailable)? != hash {
        return Err(StoreError::Unavailable);
    }
    Ok(State {
        len,
        next_seq: seq.checked_add(1).ok_or(StoreError::Unavailable)?,
        last_hash: hash.to_string(),
    })
}

impl FileSink {
    fn build_line(&self, entry_jcs: &[u8], st: &State) -> Result<(Vec<u8>, String), StoreError> {
        let Value::Object(mut m) =
            canon::parse_strict(entry_jcs).map_err(|_| StoreError::InvalidInput)?
        else {
            return Err(StoreError::InvalidInput);
        };
        if RESERVED.iter().any(|k| field(&m, k).is_some()) {
            return Err(StoreError::InvalidInput);
        }
        m.push(("seq".into(), seq_value(st.next_seq).map_err(|_| StoreError::InvalidInput)?));
        m.push(("prev_hash".into(), Value::String(st.last_hash.clone())));
        m.push(("kid".into(), Value::String(self.key.kid().to_hex())));
        let sig = self
            .key
            .sign(Domain::AuditHead, &signing_bytes(&m).map_err(|_| StoreError::InvalidInput)?);
        m.push(("sig".into(), Value::String(hex_encode(&sig.to_bytes()))));
        let hash = hash_of(&m).map_err(|_| StoreError::InvalidInput)?;
        m.push(("entry_hash".into(), Value::String(hash.clone())));
        let mut line = canon::to_jcs(&Value::Object(m)).map_err(|_| StoreError::InvalidInput)?;
        line.push(b'\n');
        Ok((line, hash))
    }

    fn append_locked(&self, entry_jcs: &[u8]) -> Result<AuditReceipt, StoreError> {
        let mut guard = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        let lock = File::options()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(|_| StoreError::Unavailable)?;
        lock.lock().map_err(|_| StoreError::Unavailable)?;
        let result = (|| {
            let mut f = OpenOptions::new()
                .append(true)
                .read(true)
                .open(&self.path)
                .map_err(|_| StoreError::Unavailable)?;
            let len = f.metadata().map_err(|_| StoreError::Unavailable)?.len();
            let st = match guard.as_ref() {
                Some(s) if s.len == len => s.clone(),
                _ => {
                    *guard = None;
                    {
                        let tail = read_tail(&mut f, len).map_err(|_| StoreError::Unavailable)?;
                        scan_tail(&tail, len)?
                    }
                }
            };
            let (line, hash) = self.build_line(entry_jcs, &st)?;
            f.write_all(&line).map_err(|_| StoreError::Unavailable)?;
            f.sync_all().map_err(|_| StoreError::Unavailable)?;
            *guard = Some(State {
                len: st.len + line.len() as u64,
                next_seq: st.next_seq + 1,
                last_hash: hash.clone(),
            });
            Ok(AuditReceipt {
                seq: st.next_seq,
                entry_hash: hash,
            })
        })();
        // Publish under the lock so heads reach the anchor in order.
        let result = result.and_then(|receipt| {
            if let Some(a) = &self.anchor {
                a.publish(&Head {
                    seq: receipt.seq,
                    entry_hash: receipt.entry_hash.clone(),
                })?;
            }
            Ok(receipt)
        });
        let _ = lock.unlock();
        result
    }
}

impl AuditSink for FileSink {
    fn append(&self, entry_jcs: &[u8]) -> Result<AuditReceipt, StoreError> {
        self.append_locked(entry_jcs)
    }
}

/// Reads from the start of the last line to the end of the file, without reading the
/// whole log: walks back in 8 KiB steps until a newline precedes the final line.
fn read_tail(f: &mut File, len: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    const STEP: u64 = 8192;
    let mut start = len;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let from = start.saturating_sub(STEP);
        let mut chunk = vec![0u8; (start - from) as usize];
        f.seek(SeekFrom::Start(from))?;
        f.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;
        start = from;
        // A newline before the final byte marks where the last line begins.
        let body = buf.strip_suffix(b"\n").unwrap_or(&buf);
        if start == 0 || body.contains(&b'\n') {
            return Ok(buf);
        }
    }
}
