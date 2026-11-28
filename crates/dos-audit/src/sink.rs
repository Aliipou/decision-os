//! `FileSink`: the `AuditSink` implementation.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use dos_core::canon::{self, Value};
use dos_core::sign::{Domain, SigningKey, hex_encode};
use dos_core::store::{AuditReceipt, AuditSink, KeyStore, StoreError};

use crate::anchor::{Anchor, FileAnchor, Head};
use crate::entry::{
    GENESIS, RESERVED, field, hash_of, legacy_hash_of, seq_field, seq_value, signing_bytes,
    str_field,
};
use crate::verify::{VerifyOptions, verify_bytes};

/// Largest entry the sink accepts (bytes of input JCS); keeps the tail read bounded.
pub const MAX_ENTRY_BYTES: usize = 1 << 20;

/// The head of the log as read from disk.
struct State {
    next_seq: u64,
    last_hash: String,
}

/// Append-only signed hash-chained log in one file, safe across threads and processes.
pub struct FileSink {
    path: PathBuf,
    lock_path: PathBuf,
    key: SigningKey,
    anchor: Option<Box<dyn Anchor>>,
    /// Allow the first append to a non-empty log that has no anchor yet (an oracle log).
    adopt_unanchored: bool,
    /// Serializes appends within the process; the file lock does it across processes.
    state: Mutex<()>,
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
        let anchor = FileAnchor::new(
            with_suffix(&path, ".anchor"),
            SigningKey::from_bytes(secret),
        );
        FileSink::open_with_anchor(path, secret, Some(Box::new(anchor)))
    }

    /// Uses `lock_path` for the cross-process lock instead of the default (the log path with
    /// extension `lock`, as Python's `LockedHashLog` does). Every writer of
    /// one log must use the same lock file, including the Python gateway, which locks
    /// `<home>/locks/audit.lock` (flock on Unix, byte 0 on Windows).
    pub fn with_lock_path(mut self, lock_path: impl Into<PathBuf>) -> FileSink {
        self.lock_path = lock_path.into();
        self
    }

    /// Lets the first append continue a non-empty log that has no anchor (a log written by
    /// the Python oracle). Off by default: a non-empty log without an anchor is refused, so
    /// a deleted anchor or a forged history cannot be signed over.
    pub fn adopt_unanchored(mut self, yes: bool) -> FileSink {
        self.adopt_unanchored = yes;
        self
    }

    /// Like `open` with a caller-chosen anchor. `None` disables anchoring: tail
    /// truncation is then undetectable, so this is for tests and explicit opt-out.
    pub fn open_with_anchor(
        path: impl Into<PathBuf>,
        secret: &[u8; 32],
        anchor: Option<Box<dyn Anchor>>,
    ) -> Result<FileSink, StoreError> {
        let path = path.into();
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(|_| StoreError::Unavailable)?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(FileSink {
            lock_path: path.with_extension("lock"),
            path,
            key: SigningKey::from_bytes(secret),
            anchor,
            adopt_unanchored: false,
            state: Mutex::new(()),
        })
    }

    /// Recovers from a crash in the middle of a write (kill -9, power loss): removes a last
    /// line that has no newline and so was never complete, never anchored and never
    /// acknowledged to a caller. Returns the number of bytes removed. Any other damage is
    /// left alone, and appends keep refusing it.
    pub fn repair_torn_tail(&self) -> Result<u64, StoreError> {
        self.locked(|| {
            let bytes = fs::read(&self.path).map_err(|_| StoreError::Unavailable)?;
            if bytes.is_empty() || bytes.last() == Some(&b'\n') {
                return Ok(0);
            }
            let keep = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            let f = OpenOptions::new()
                .write(true)
                .open(&self.path)
                .map_err(|_| StoreError::Unavailable)?;
            f.set_len(keep as u64)
                .map_err(|_| StoreError::Unavailable)?;
            f.sync_all().map_err(|_| StoreError::Unavailable)?;
            Ok((bytes.len() - keep) as u64)
        })
    }

    /// Current head from disk, `None` for an empty log. Errors if the tail is corrupt.
    pub fn head(&self) -> Result<Option<Head>, StoreError> {
        // Under the lock, so a concurrent append is never seen half written.
        self.locked(|| {
            let mut f = File::open(&self.path).map_err(|_| StoreError::Unavailable)?;
            let len = f.metadata().map_err(|_| StoreError::Unavailable)?.len();
            let tail = read_tail(&mut f, len).map_err(|_| StoreError::Unavailable)?;
            let st = scan_tail(&tail)?;
            Ok(st.next_seq.checked_sub(1).map(|seq| Head {
                seq,
                entry_hash: st.last_hash,
            }))
        })
    }
}

/// Finds the head of the log bytes. Fails closed on anything but a clean tail.
fn scan_tail(bytes: &[u8]) -> Result<State, StoreError> {
    if bytes.is_empty() {
        return Ok(State {
            next_seq: 0,
            last_hash: GENESIS.into(),
        });
    }
    let body = bytes.strip_suffix(b"\n").ok_or(StoreError::Unavailable)?;
    let split = body.iter().rposition(|b| *b == b'\n');
    let line = body
        .get(split.map_or(0, |i| i + 1)..)
        .ok_or(StoreError::Unavailable)?;
    let (seq, prev_hash, hash) = parse_tail_line(line)?;
    // The line before the last one must be the one the last one chains to: this refuses
    // a duplicated or spliced tail that a lone last-line check would accept.
    match split {
        None => {
            if seq != 0 || prev_hash != GENESIS {
                return Err(StoreError::Unavailable);
            }
        }
        Some(i) => {
            let before = body.get(..i).ok_or(StoreError::Unavailable)?;
            let pstart = before
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |j| j + 1);
            let pline = before.get(pstart..).ok_or(StoreError::Unavailable)?;
            let (pseq, _, phash) = parse_tail_line(pline)?;
            if pseq.checked_add(1) != Some(seq) || phash != prev_hash {
                return Err(StoreError::Unavailable);
            }
        }
    }
    Ok(State {
        next_seq: seq.checked_add(1).ok_or(StoreError::Unavailable)?,
        last_hash: hash,
    })
}

/// `(seq, prev_hash, entry_hash)` of one log line, after checking its own hash.
fn parse_tail_line(line: &[u8]) -> Result<(u64, String, String), StoreError> {
    let Value::Object(m) = canon::parse_strict(line).map_err(|_| StoreError::Unavailable)? else {
        return Err(StoreError::Unavailable);
    };
    let seq = seq_field(&m).ok_or(StoreError::Unavailable)?;
    let prev = str_field(&m, "prev_hash").ok_or(StoreError::Unavailable)?;
    let hash = str_field(&m, "entry_hash").ok_or(StoreError::Unavailable)?;
    // The oracle (Python) writes the same chain with an ASCII-escaped hash; accept its
    // tail so Rust can continue a Python-written log.
    let jcs_ok = hash_of(&m).map_err(|_| StoreError::Unavailable)? == hash;
    if !jcs_ok && legacy_hash_of(&m).as_deref() != Some(hash) {
        return Err(StoreError::Unavailable);
    }
    Ok((seq, prev.to_string(), hash.to_string()))
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
        m.push((
            "seq".into(),
            seq_value(st.next_seq).map_err(|_| StoreError::InvalidInput)?,
        ));
        m.push(("prev_hash".into(), Value::String(st.last_hash.clone())));
        m.push(("kid".into(), Value::String(self.key.kid().to_hex())));
        let sig = self.key.sign(
            Domain::AuditHead,
            &signing_bytes(&m).map_err(|_| StoreError::InvalidInput)?,
        );
        m.push(("sig".into(), Value::String(hex_encode(&sig.to_bytes()))));
        let hash = hash_of(&m).map_err(|_| StoreError::InvalidInput)?;
        m.push(("entry_hash".into(), Value::String(hash.clone())));
        let mut line = canon::to_jcs(&Value::Object(m)).map_err(|_| StoreError::InvalidInput)?;
        if has_python_line_break(&line) {
            return Err(StoreError::InvalidInput);
        }
        line.push(b'\n');
        Ok((line, hash))
    }

    /// Runs `f` holding the in-process mutex and the cross-process file lock.
    fn locked<T>(&self, f: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        let _guard = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        if let Some(dir) = self
            .lock_path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
        {
            fs::create_dir_all(dir).map_err(|_| StoreError::Unavailable)?;
        }
        let lock = File::options()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(|_| StoreError::Unavailable)?;
        lock.lock().map_err(|_| StoreError::Unavailable)?;
        let result = f();
        let _ = lock.unlock();
        result
    }

    /// Refuses to continue a log that does not match the anchor: truncated (fewer entries
    /// than the anchored head), wiped, or replaced by another log. A log that is longer than
    /// the anchor (an anchor write failed earlier) must verify in full: strict, signed by
    /// this key, with the anchored entry in place.
    fn check_against_anchor(&self, st: &State) -> Result<(), StoreError> {
        let Some(anchor) = &self.anchor else {
            return Ok(());
        };
        let head_seq = st.next_seq.checked_sub(1);
        match anchor.latest()? {
            None => {
                // A non-empty log with no anchor was never ours (or its anchor was deleted).
                if head_seq.is_some() && !self.adopt_unanchored {
                    return Err(StoreError::Unavailable);
                }
                Ok(())
            }
            Some(a) => match head_seq {
                Some(h) if h == a.seq && st.last_hash == a.entry_hash => Ok(()),
                Some(h) if h > a.seq => {
                    let bytes = fs::read(&self.path).map_err(|_| StoreError::Unavailable)?;
                    let keys = OwnKey(self.key.kid().to_hex(), self.key.verifying_key().to_bytes());
                    let opts = VerifyOptions {
                        keys: &keys,
                        now_unix_ms: 0,
                        python_compat: false,
                        anchor: Some(a),
                    };
                    verify_bytes(&bytes, &opts)
                        .map(|_| ())
                        .map_err(|_| StoreError::Unavailable)
                }
                _ => Err(StoreError::Unavailable),
            },
        }
    }

    fn append_locked(&self, entry_jcs: &[u8]) -> Result<AuditReceipt, StoreError> {
        if entry_jcs.len() > MAX_ENTRY_BYTES {
            return Err(StoreError::InvalidInput);
        }
        self.locked(|| {
            use std::io::{Seek as _, SeekFrom};
            // Not opened in append mode: a failed append is rolled back with `set_len`.
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)
                .map_err(|_| StoreError::Unavailable)?;
            let len = f.metadata().map_err(|_| StoreError::Unavailable)?.len();
            // Always re-read the tail: a cached head could be stale, or the file swapped
            // for another of the same length.
            let tail = read_tail(&mut f, len).map_err(|_| StoreError::Unavailable)?;
            let st = scan_tail(&tail)?;
            self.check_against_anchor(&st)?;
            let (line, hash) = self.build_line(entry_jcs, &st)?;
            let receipt = AuditReceipt {
                seq: st.next_seq,
                entry_hash: hash,
            };
            let written = (|| -> Result<(), StoreError> {
                f.seek(SeekFrom::Start(len))
                    .map_err(|_| StoreError::Unavailable)?;
                f.write_all(&line).map_err(|_| StoreError::Unavailable)?;
                f.sync_all().map_err(|_| StoreError::Unavailable)?;
                // Publish under the lock so heads reach the anchor in order.
                if let Some(a) = &self.anchor {
                    a.publish(&Head {
                        seq: receipt.seq,
                        entry_hash: receipt.entry_hash.clone(),
                    })?;
                }
                Ok(())
            })();
            if let Err(e) = written {
                // Err must mean "no entry": take back what was written (best effort).
                let _ = f.set_len(len);
                let _ = f.sync_all();
                return Err(e);
            }
            Ok(receipt)
        })
    }
}

impl AuditSink for FileSink {
    fn append(&self, entry_jcs: &[u8]) -> Result<AuditReceipt, StoreError> {
        self.append_locked(entry_jcs)
    }
}

/// Longest last line the sink will read: an entry is at most `MAX_ENTRY_BYTES` of input
/// and gains well under 1 KiB of fields per entry, so a longer tail is not ours.
const MAX_TAIL_BYTES: usize = 4 << 20;

/// Reads from the start of the last line to the end of the file, without reading the
/// whole log: walks back in 64 KiB steps until a newline precedes the final line. Fails
/// (does not read on) when the last line is longer than `MAX_TAIL_BYTES`.
fn read_tail(f: &mut File, len: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    const STEP: u64 = 64 * 1024;
    let mut start = len;
    let mut chunks: Vec<Vec<u8>> = Vec::new(); // newest (closest to the end) first
    let mut total = 0usize;
    let mut newlines = 0usize;
    loop {
        let from = start.saturating_sub(STEP);
        let mut chunk = vec![0u8; (start - from) as usize];
        f.seek(SeekFrom::Start(from))?;
        f.read_exact(&mut chunk)?;
        // The final byte of the file is the line's own newline; a newline before it
        // marks where the last line begins.
        let probe_end = if chunks.is_empty() {
            chunk.len().saturating_sub(1)
        } else {
            chunk.len()
        };
        // Two newlines before the final byte: the start of the previous line is in hand,
        // so the tail check can chain the last line to its predecessor.
        newlines += chunk
            .get(..probe_end)
            .map_or(0, |p| p.iter().filter(|b| **b == b'\n').count());
        total += chunk.len();
        chunks.push(chunk);
        start = from;
        if start == 0 || newlines >= 2 {
            let mut out = Vec::with_capacity(total);
            for c in chunks.iter().rev() {
                out.extend_from_slice(c);
            }
            return Ok(out);
        }
        if total > MAX_TAIL_BYTES {
            return Err(std::io::Error::other("last line too long"));
        }
    }
}

/// A key store that trusts exactly the sink's own key (to re-verify its own log).
struct OwnKey(String, [u8; 32]);

impl KeyStore for OwnKey {
    fn verifying_key(&self, kid: &str, _now: i64) -> Result<Option<[u8; 32]>, StoreError> {
        Ok((kid == self.0).then_some(self.1))
    }
}

/// Characters Python's `str.splitlines()` treats as line breaks but JCS writes raw. A
/// Rust log containing one would be unreadable for the Python gateway's `HashLog`.
fn has_python_line_break(line: &[u8]) -> bool {
    line.windows(2).any(|w| w == [0xC2, 0x85])
        || line
            .windows(3)
            .any(|w| w == [0xE2, 0x80, 0xA8] || w == [0xE2, 0x80, 0xA9])
}
