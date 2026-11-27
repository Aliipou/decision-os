//! Atomic writes, backups, the install lock and the home directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Why a write was refused or failed. The target is untouched in every case.
#[derive(Debug)]
pub(crate) enum WriteError {
    /// The file no longer holds the bytes we read: someone else wrote it.
    Changed,
    Io(io::Error),
}

impl WriteError {
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            WriteError::Changed => io::Error::other("file changed while it was being written"),
            WriteError::Io(e) => e,
        }
    }
}

impl From<io::Error> for WriteError {
    fn from(e: io::Error) -> Self {
        WriteError::Io(e)
    }
}

/// The file to write for `path`: a symlink is followed (the link itself is kept), so
/// dotfile setups keep working. The oracle replaced the link with a regular file.
pub(crate) fn resolve(path: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

fn create_new(path: &Path, private: bool) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if private {
            o.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    o.open(path)
}

fn temp_beside(target: &Path) -> io::Result<(PathBuf, File)> {
    let dir = target.parent().unwrap_or(Path::new("."));
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    loop {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{name}.dos-{}-{n}.tmp", std::process::id()));
        match create_new(&tmp, true) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    // Best effort: the rename is already atomic; this makes it durable.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

/// Write `data` to `path` atomically: a temp file in the same directory (owner-only),
/// fsync, the original permissions copied (0600 when `private` or new), a last check
/// that the file still holds `expect` (when given), rename, fsync of the directory.
pub(crate) fn atomic_write(
    path: &Path,
    data: &[u8],
    expect: Option<&[u8]>,
    private: bool,
) -> Result<(), WriteError> {
    let target = resolve(path)?;
    let perms = fs::metadata(&target).ok().map(|m| m.permissions());
    let (tmp, mut f) = temp_beside(&target)?;
    let result = (|| -> Result<(), WriteError> {
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        if let (Some(p), false) = (&perms, private) {
            fs::set_permissions(&tmp, p.clone())?;
        }
        if let Some(exp) = expect {
            if fs::read(&target)? != exp {
                return Err(WriteError::Changed);
            }
        }
        fs::rename(&tmp, &target)?;
        if let Some(dir) = target.parent() {
            sync_dir(dir);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// `[^A-Za-z0-9._-]+` -> `_` on the path with `/` and `\` stripped from both ends
/// (oracle `_backup`).
pub(crate) fn safe_name(path: &str) -> String {
    let trimmed = path.trim_matches(|c| c == '/' || c == '\\');
    let mut out = String::new();
    let mut in_run = false;
    for c in trimmed.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// Write a backup that never replaces an existing one: `<dir>/<name>`, else
/// `<name>.1`, `<name>.2`, ... Owner-only, fsynced, read back.
pub(crate) fn write_backup(dir: &Path, name: &str, data: &[u8]) -> io::Result<PathBuf> {
    create_private_dirs(dir)?;
    for i in 0u32.. {
        let p = if i == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{name}.{i}"))
        };
        match create_new(&p, true) {
            Ok(mut f) => {
                f.write_all(data)?;
                f.sync_all()?;
                drop(f);
                if fs::read(&p)? != data {
                    return Err(io::Error::other("backup does not read back"));
                }
                return Ok(p);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("no free backup name"))
}

fn create_private_dirs(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The gateway home with owner-only directories (oracle `Home.ensure`).
pub(crate) fn ensure_home(root: &Path) -> io::Result<()> {
    for d in ["", "approvals", "backups", "locks", "sessions"] {
        let p = if d.is_empty() {
            root.to_path_buf()
        } else {
            root.join(d)
        };
        create_private_dirs(&p)?;
    }
    Ok(())
}

/// Held for the whole run: two installs never interleave their state updates.
pub(crate) struct InstallLock {
    _file: File,
}

pub(crate) fn lock(root: &Path) -> io::Result<InstallLock> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join("locks").join("install.lock"))?;
    f.lock()?;
    Ok(InstallLock { _file: f })
}

/// Seconds since the Unix epoch -> (y, m, d, H, M, S) in UTC.
pub(crate) fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant, days_from_civil inverse
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let t = |v: i64| u32::try_from(v).unwrap_or(0);
    (y, t(m), t(d), t(rem / 3600), t(rem % 3600 / 60), t(rem % 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil(1_795_000_000), (2026, 11, 18, 11, 6, 40));
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
    }

    #[test]
    fn safe_names_match_the_oracle_rule() {
        assert_eq!(
            safe_name("/home/u/.config/Claude/claude_desktop_config.json"),
            "home_u_.config_Claude_claude_desktop_config.json"
        );
        assert_eq!(safe_name("C:\\Users\\a b\\x.json"), "C_Users_a_b_x.json");
        assert_eq!(safe_name("/ü//x/"), "_x");
    }
}
