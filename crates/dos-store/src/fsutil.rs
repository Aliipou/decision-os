//! Directory checks, file identity, directory fsync and the timed cross-process lock.
//! Every failure is `StoreError::Unavailable`.

use crate::StoreError;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, Instant};

const U: StoreError = StoreError::Unavailable;

/// Identity of a file or directory, compared to detect a store that was removed,
/// re-created or swapped while in use. Unix: (dev, ino). Windows: creation time
/// (100 ns resolution; weaker, see design/store.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FsId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    created: u64,
}

pub(crate) fn fs_id(md: &Metadata) -> FsId {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FsId {
            dev: md.dev(),
            ino: md.ino(),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        FsId {
            created: md.creation_time(),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = md;
        FsId {}
    }
}

/// Identity of the regular file at `path` (not following a symlink).
pub(crate) fn file_id(path: &Path) -> Result<FsId, StoreError> {
    let md = fs::symlink_metadata(path).map_err(|_| U)?;
    if !md.file_type().is_file() {
        return Err(U);
    }
    Ok(fs_id(&md))
}

/// Create `dir` (and missing parents, mode 0700 on Unix) if it does not exist, then
/// check it. Returns its identity.
pub(crate) fn prepare_dir(dir: &Path) -> Result<FsId, StoreError> {
    if dir.as_os_str().is_empty() {
        return Err(U);
    }
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            b.create(dir).map_err(|_| U)?;
        }
        Err(_) => return Err(U),
    }
    check_dir(dir)
}

/// The store directory must be a real directory (not a symlink or junction). On Unix it
/// must also be owned by the effective uid and have no group or other write bit: anyone
/// else who can write it can delete records and double spend.
pub(crate) fn check_dir(dir: &Path) -> Result<FsId, StoreError> {
    let md = fs::symlink_metadata(dir).map_err(|_| U)?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(U);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.uid() != rustix::process::geteuid().as_raw() || md.mode() & 0o022 != 0 {
            return Err(U);
        }
    }
    Ok(fs_id(&md))
}

/// Make a new or removed directory entry in `dir` durable. Windows: no-op (NTFS journals
/// metadata, and std cannot open a directory handle there).
pub(crate) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        File::open(dir).and_then(|d| d.sync_all()).map_err(|_| U)?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Open (creating, mode 0600) a lock file. A fresh handle per use: `flock` is per open
/// file description, so threads sharing one handle would not exclude each other.
pub(crate) fn open_lock_file(path: &Path) -> Result<File, StoreError> {
    if let Ok(md) = fs::symlink_metadata(path)
        && !md.file_type().is_file()
    {
        return Err(U);
    }
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).map_err(|_| U)
}

/// An exclusive lock held until drop.
pub(crate) struct Exclusive(File);

impl Drop for Exclusive {
    fn drop(&mut self) {
        // Closing the handle releases the lock even if unlock fails.
        let _ = self.0.unlock();
    }
}

/// Take an exclusive lock on `path`, polling until `timeout`; then `Unavailable`.
pub(crate) fn lock_exclusive(path: &Path, timeout: Duration) -> Result<Exclusive, StoreError> {
    let file = open_lock_file(path)?;
    let deadline = Instant::now() + timeout;
    let mut wait = Duration::from_millis(1);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Exclusive(file)),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(_)) => return Err(U),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(U);
        }
        std::thread::sleep(wait.min(deadline - now));
        wait = (wait * 2).min(Duration::from_millis(50));
    }
}
