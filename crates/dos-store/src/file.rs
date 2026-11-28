//! One `O_EXCL` marker file per token in a directory. See design/store.md.
//!
//! Marker name: lowercase hex SHA-256 of `"dos-store/spent-file/v1\0" || token_id`.
//! Marker content: exactly `dos-spent-v1 <expiry>\n`; no proper prefix parses.
//! A plain first spend takes no lock (the kernel's create-exclusive is the
//! compare-and-set). Expiry extension and purge take the store-wide lock file.

use crate::fsutil::{self, FsId};
use crate::{Spend, SpentStore, StoreError, StoreOptions, validate_token_id};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const U: StoreError = StoreError::Unavailable;
const DOMAIN_TAG: &[u8] = b"dos-store/spent-file/v1\0";
const CONTENT_PREFIX: &str = "dos-spent-v1 ";
const TMP_PREFIX: &str = ".tmp-";

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct FileSpentStore {
    dir: PathBuf,
    dir_id: FsId,
    lock_id: FsId,
    options: StoreOptions,
}

/// What a read of an existing marker found.
enum Marker {
    Missing,
    Expiry(i64),
    /// Empty, partial (a first spender mid-write) or foreign content: spent forever.
    Unparsable,
}

impl FileSpentStore {
    pub const LOCK_FILE_NAME: &'static str = ".dos-spent.lock";

    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with(dir, StoreOptions::default())
    }

    /// Create (mode 0700 on Unix) and check the directory, and create the lock file.
    pub fn open_with(dir: impl AsRef<Path>, options: StoreOptions) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        let dir_id = fsutil::prepare_dir(&dir)?;
        let lock_path = dir.join(Self::LOCK_FILE_NAME);
        drop(fsutil::open_lock_file(&lock_path)?);
        fsutil::sync_dir(&dir)?;
        let lock_id = fsutil::file_id(&lock_path)?;
        let store = FileSpentStore {
            dir,
            dir_id,
            lock_id,
            options,
        };
        store.check_identity()?;
        Ok(store)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The marker file name for `token_id` (64 lowercase hex chars, never the raw id).
    pub fn marker_file_name(token_id: &str) -> Result<String, StoreError> {
        validate_token_id(token_id)?;
        let mut h = Sha256::new();
        h.update(DOMAIN_TAG);
        h.update(token_id.as_bytes());
        let digest = h.finalize();
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push(hex_digit(b >> 4));
            out.push(hex_digit(b & 0x0f));
        }
        Ok(out)
    }

    /// Remove markers whose stored expiry is strictly before `now_unix_ms`, and orphan
    /// temp files. Unparsable markers are kept. Holds the store lock throughout.
    pub fn purge_expired(&self, now_unix_ms: i64) -> Result<u64, StoreError> {
        let _lock = fsutil::lock_exclusive(&self.lock_path(), self.options.lock_timeout)?;
        self.check_identity()?;
        let mut removed = 0u64;
        let mut changed = false;
        for entry in fs::read_dir(&self.dir).map_err(|_| U)? {
            let entry = entry.map_err(|_| U)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let path = self.dir.join(name);
            if name.starts_with(TMP_PREFIX) {
                // No extender can be active: they all hold the lock we hold.
                remove_if_present(&path)?;
                changed = true;
            } else if is_marker_name(name)
                && let Marker::Expiry(exp) = read_marker(&path)
                && exp < now_unix_ms
            {
                remove_if_present(&path)?;
                removed = removed.saturating_add(1);
                changed = true;
            }
        }
        if changed {
            fsutil::sync_dir(&self.dir)?;
        }
        Ok(removed)
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(Self::LOCK_FILE_NAME)
    }

    /// The directory is still the one opened (not removed, re-created or swapped), and
    /// still holds our lock file (a re-created directory does not; on Windows the
    /// creation-time identity alone can be preserved by NTFS name tunneling).
    fn check_identity(&self) -> Result<(), StoreError> {
        if fsutil::check_dir(&self.dir)? != self.dir_id {
            return Err(U);
        }
        if fsutil::file_id(&self.lock_path())? != self.lock_id {
            return Err(U);
        }
        Ok(())
    }

    /// Write the content of a marker we just created exclusively, make it durable.
    fn finish_first(&self, mut f: File, expires_at_unix_ms: i64) -> Result<Spend, StoreError> {
        f.write_all(content(expires_at_unix_ms).as_bytes())
            .map_err(|_| U)?;
        f.sync_all().map_err(|_| U)?;
        drop(f);
        fsutil::sync_dir(&self.dir)?;
        self.check_identity()?;
        Ok(Spend::First)
    }

    /// Replace the marker's content with a later expiry. Caller holds the lock.
    fn extend(&self, marker: &Path, name: &str, expires_at_unix_ms: i64) -> Result<(), StoreError> {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!("{TMP_PREFIX}{name}-{}-{n}", std::process::id()));
        let result = (|| {
            let mut f = create_exclusive(&tmp).map_err(|_| U)?;
            f.write_all(content(expires_at_unix_ms).as_bytes())
                .map_err(|_| U)?;
            f.sync_all().map_err(|_| U)?;
            drop(f);
            fs::rename(&tmp, marker).map_err(|_| U)?;
            fsutil::sync_dir(&self.dir)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    /// Replay path, under the lock: extend if needed. `Ok(None)` means the marker
    /// vanished (purged) and the caller should retry the exclusive create.
    fn replay_locked(
        &self,
        marker: &Path,
        name: &str,
        expires_at_unix_ms: i64,
        deadline: Instant,
    ) -> Result<Option<Spend>, StoreError> {
        let _lock = fsutil::lock_exclusive(&self.lock_path(), self.options.lock_timeout)?;
        self.check_identity()?;
        let mut wait = Duration::from_millis(1);
        loop {
            match read_marker(marker) {
                Marker::Missing => return Ok(None),
                Marker::Expiry(stored) if stored >= expires_at_unix_ms => {
                    return Ok(Some(Spend::AlreadySpent));
                }
                Marker::Expiry(_) => {
                    self.extend(marker, name, expires_at_unix_ms)?;
                    self.check_identity()?;
                    return Ok(Some(Spend::AlreadySpent));
                }
                Marker::Unparsable => {
                    // Maybe a first spender mid-write: poll. On timeout, refuse the
                    // replay without extending; an unparsable marker is never purged.
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(Some(Spend::AlreadySpent));
                    }
                    std::thread::sleep(wait.min(deadline - now));
                    wait = (wait * 2).min(Duration::from_millis(20));
                }
            }
        }
    }
}

impl SpentStore for FileSpentStore {
    fn try_spend(&self, token_id: &str, expires_at_unix_ms: i64) -> Result<Spend, StoreError> {
        let name = Self::marker_file_name(token_id)?;
        let marker = self.dir.join(&name);
        self.check_identity()?;
        let deadline = Instant::now() + self.options.lock_timeout;
        let mut wait = Duration::from_millis(1);
        loop {
            match create_exclusive(&marker) {
                Ok(f) => return self.finish_first(f, expires_at_unix_ms),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    match read_marker(&marker) {
                        // Purged between create and read: try to create again.
                        Marker::Missing => {}
                        Marker::Expiry(stored) if stored >= expires_at_unix_ms => {
                            return Ok(Spend::AlreadySpent);
                        }
                        Marker::Expiry(_) | Marker::Unparsable => {
                            if let Some(s) =
                                self.replay_locked(&marker, &name, expires_at_unix_ms, deadline)?
                            {
                                return Ok(s);
                            }
                        }
                    }
                }
                // Windows: a marker being deleted by a purger is briefly "delete
                // pending" and refuses opens with access denied. Retry until the
                // deadline, then fail closed.
                Err(e) if cfg!(windows) && e.kind() == ErrorKind::PermissionDenied => {}
                Err(_) => return Err(U),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(U);
            }
            std::thread::sleep(wait.min(deadline - now));
            wait = (wait * 2).min(Duration::from_millis(20));
        }
    }
}

fn hex_digit(n: u8) -> char {
    char::from(
        b"0123456789abcdef"
            .get(usize::from(n))
            .copied()
            .unwrap_or(b'0'),
    )
}

fn is_marker_name(n: &str) -> bool {
    n.len() == 64
        && n.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn content(expires_at_unix_ms: i64) -> String {
    format!("{CONTENT_PREFIX}{expires_at_unix_ms}\n")
}

/// Parse `dos-spent-v1 <expiry>\n` exactly (canonical decimal only).
pub(crate) fn parse_content(bytes: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(bytes).ok()?;
    let num = s.strip_prefix(CONTENT_PREFIX)?.strip_suffix('\n')?;
    let v: i64 = num.parse().ok()?;
    (v.to_string() == num).then_some(v)
}

fn create_exclusive(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

fn read_marker(path: &Path) -> Marker {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Marker::Missing,
        Err(_) => return Marker::Unparsable,
    };
    let mut buf = Vec::with_capacity(64);
    // Bounded read: a valid marker is at most 34 bytes.
    if (&mut f).take(128).read_to_end(&mut buf).is_err() {
        return Marker::Unparsable;
    }
    parse_content(&buf).map_or(Marker::Unparsable, Marker::Expiry)
}

fn remove_if_present(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(U),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_round_trips_and_no_proper_prefix_parses() {
        for v in [i64::MIN, -1, 0, 1, 1_000, i64::MAX] {
            let c = content(v);
            assert_eq!(parse_content(c.as_bytes()), Some(v));
            for cut in 0..c.len() {
                assert_eq!(
                    parse_content(c.as_bytes().get(..cut).unwrap_or(b"")),
                    None,
                    "{c:?} {cut}"
                );
            }
        }
    }

    #[test]
    fn non_canonical_content_refused() {
        for bad in [
            &b"dos-spent-v1 +5\n"[..],
            b"dos-spent-v1 05\n",
            b"dos-spent-v1 5\n\n",
            b"dos-spent-v1  5\n",
            b"dos-spent-v1 5",
            b"dos-spent-v2 5\n",
            b"dos-spent-v1 -0\n",
            b"\xff",
        ] {
            assert_eq!(parse_content(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn marker_name_shape() -> Result<(), StoreError> {
        let n = FileSpentStore::marker_file_name("tok")?;
        assert!(is_marker_name(&n));
        assert_eq!(
            FileSpentStore::marker_file_name(""),
            Err(StoreError::InvalidInput)
        );
        Ok(())
    }
}
