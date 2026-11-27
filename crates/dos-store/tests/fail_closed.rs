//! Every unavailable, swapped, corrupt or locked store refuses: `Unavailable`, never
//! `First`. Unix-only cases need mode bits, owners or symlinks.
mod common;
use common::*;
use dos_store::{FileSpentStore, Spend, SpentStore, SqliteSpentStore, StoreError, StoreOptions};
use std::fs;
use std::time::{Duration, Instant};

const U: Result<Spend, StoreError> = Err(StoreError::Unavailable);

fn short() -> StoreOptions {
    StoreOptions {
        lock_timeout: Duration::from_millis(300),
    }
}

#[test]
fn file_regular_file_where_dir_should_be() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let p = tmp.path().join("spent");
    fs::write(&p, b"not a dir")?;
    assert_eq!(FileSpentStore::open(&p).err(), Some(StoreError::Unavailable));
    assert_eq!(
        FileSpentStore::open(p.join("below")).err(),
        Some(StoreError::Unavailable),
        "parent is a regular file"
    );
    Ok(())
}

#[test]
fn file_dir_removed_mid_run() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("spent");
    let store = FileSpentStore::open(&dir).map_err(se)?;
    assert_eq!(store.try_spend("a", 10), Ok(Spend::First));
    fs::remove_dir_all(&dir)?;
    assert_eq!(store.try_spend("a", 10), U);
    assert_eq!(store.try_spend("b", 10), U);
    Ok(())
}

#[test]
fn file_dir_removed_and_recreated_mid_run() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("spent");
    let store = FileSpentStore::open(&dir).map_err(se)?;
    assert_eq!(store.try_spend("a", 10), Ok(Spend::First));
    fs::remove_dir_all(&dir)?;
    fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    // A fresh empty directory must not make "a" spendable again.
    assert_eq!(store.try_spend("a", 10), U);
    assert_eq!(store.try_spend("c", 10), U);
    Ok(())
}

#[test]
fn file_lock_held_past_timeout_refuses_purge_and_extension() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("spent");
    let store = FileSpentStore::open_with(&dir, short()).map_err(se)?;
    assert_eq!(store.try_spend("a", 10), Ok(Spend::First));
    let holder = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(FileSpentStore::LOCK_FILE_NAME))?;
    holder.lock()?;
    let t = Instant::now();
    assert_eq!(store.purge_expired(i64::MAX), Err(StoreError::Unavailable));
    assert!(t.elapsed() >= Duration::from_millis(250), "{:?}", t.elapsed());
    // Extending needs the lock too; a replay is still refused.
    assert_eq!(store.try_spend("a", 1_000), U);
    // A plain first spend does not need the lock.
    assert_eq!(store.try_spend("b", 10), Ok(Spend::First));
    holder.unlock()?;
    assert_eq!(store.purge_expired(i64::MAX), Ok(2));
    Ok(())
}

#[test]
fn sqlite_corrupt_file_refuses() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let garbage = tmp.path().join("garbage.db");
    fs::write(&garbage, vec![0xA5u8; 8192])?;
    assert_eq!(SqliteSpentStore::open(&garbage).err(), Some(StoreError::Unavailable));
    // A valid header over garbage pages.
    let torn = tmp.path().join("torn.db");
    let mut bytes = b"SQLite format 3\0".to_vec();
    bytes.extend(vec![0x5Au8; 8192]);
    fs::write(&torn, bytes)?;
    assert_eq!(SqliteSpentStore::open(&torn).err(), Some(StoreError::Unavailable));
    // A real database, then its pages overwritten (header kept).
    let real = tmp.path().join("real.db");
    {
        let s = SqliteSpentStore::open(&real).map_err(se)?;
        for i in 0..200 {
            s.try_spend(&format!("t{i}"), 10).map_err(se)?;
        }
    }
    let mut bytes = fs::read(&real)?;
    for b in bytes.iter_mut().skip(100) {
        *b = 0x33;
    }
    fs::write(&real, bytes)?;
    let _ = fs::remove_file(tmp.path().join("real.db-wal"));
    let _ = fs::remove_file(tmp.path().join("real.db-shm"));
    assert_eq!(SqliteSpentStore::open(&real).err(), Some(StoreError::Unavailable));
    Ok(())
}

#[test]
fn sqlite_db_path_is_a_directory_or_under_a_file() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let d = tmp.path().join("spent.db");
    fs::create_dir(&d)?;
    assert_eq!(SqliteSpentStore::open(&d).err(), Some(StoreError::Unavailable));
    let f = tmp.path().join("file");
    fs::write(&f, b"x")?;
    assert_eq!(
        SqliteSpentStore::open(f.join("spent.db")).err(),
        Some(StoreError::Unavailable)
    );
    Ok(())
}

#[test]
fn sqlite_oracle_schema_refuses() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let db = tmp.path().join("spent.db");
    {
        let c = rusqlite::Connection::open(&db)?;
        c.execute_batch("CREATE TABLE spent (token_id TEXT PRIMARY KEY)")?;
        c.execute("INSERT INTO spent (token_id) VALUES ('tok-1')", [])?;
    }
    assert_eq!(SqliteSpentStore::open(&db).err(), Some(StoreError::Unavailable));
    Ok(())
}

#[test]
fn sqlite_lock_held_past_timeout_refuses_open() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let db = tmp.path().join("spent.db");
    drop(SqliteSpentStore::open(&db).map_err(se)?);
    let holder = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(SqliteSpentStore::lock_path(&db))?;
    holder.lock()?;
    let t = Instant::now();
    assert_eq!(
        SqliteSpentStore::open_with(&db, short()).err(),
        Some(StoreError::Unavailable)
    );
    assert!(t.elapsed() >= Duration::from_millis(250), "{:?}", t.elapsed());
    holder.unlock()?;
    let s = SqliteSpentStore::open_with(&db, short()).map_err(se)?;
    assert_eq!(s.try_spend("a", 1), Ok(Spend::First));
    Ok(())
}

#[test]
fn sqlite_write_lock_held_past_busy_timeout_refuses_spend() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let db = tmp.path().join("spent.db");
    let s = SqliteSpentStore::open_with(&db, short()).map_err(se)?;
    let c = rusqlite::Connection::open(&db)?;
    c.execute_batch("BEGIN IMMEDIATE")?;
    let t = Instant::now();
    assert_eq!(s.try_spend("a", 1), U);
    assert!(t.elapsed() >= Duration::from_millis(250), "{:?}", t.elapsed());
    c.execute_batch("ROLLBACK")?;
    assert_eq!(s.try_spend("a", 1), Ok(Spend::First));
    Ok(())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    /// Makes `dir` unwritable for this process and undoes it on drop. Root ignores
    /// mode bits, so as root this uses the ext4 immutable attribute instead.
    struct ReadOnly(PathBuf);

    impl ReadOnly {
        fn new(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
            if is_root() {
                let st = Command::new("chattr").arg("+i").arg(dir).status()?;
                if !st.success() {
                    return Err(fail("chattr +i failed: run the tests on ext4 (TMPDIR)"));
                }
            } else {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o500))?;
            }
            Ok(ReadOnly(dir.to_path_buf()))
        }
    }

    impl Drop for ReadOnly {
        fn drop(&mut self) {
            if is_root() {
                let _ = Command::new("chattr").arg("-i").arg(&self.0).status();
            } else {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            }
        }
    }

    #[test]
    fn file_read_only_dir() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("spent");
        let store = FileSpentStore::open(&dir).map_err(se)?;
        assert_eq!(store.try_spend("a", 10), Ok(Spend::First));
        {
            let _ro = ReadOnly::new(&dir)?;
            assert_eq!(store.try_spend("b", 10), U);
            assert_eq!(store.try_spend("a", 10), Ok(Spend::AlreadySpent));
        }
        assert_eq!(store.try_spend("b", 10), Ok(Spend::First), "the failed spend left no marker");
        // A brand-new store in a read-only directory cannot even create its lock file.
        let fresh = tmp.path().join("fresh");
        fs::create_dir(&fresh)?;
        fs::set_permissions(&fresh, fs::Permissions::from_mode(0o700))?;
        let _ro = ReadOnly::new(&fresh)?;
        assert_eq!(FileSpentStore::open(&fresh).err(), Some(StoreError::Unavailable));
        Ok(())
    }

    #[test]
    fn sqlite_read_only_dir_new_db_refuses() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("ro");
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let _ro = ReadOnly::new(&dir)?;
        assert_eq!(
            SqliteSpentStore::open(dir.join("spent.db")).err(),
            Some(StoreError::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn file_symlinked_dir_refused() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let real = tmp.path().join("real");
        fs::create_dir(&real)?;
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700))?;
        let link = tmp.path().join("link");
        symlink(&real, &link)?;
        assert_eq!(FileSpentStore::open(&link).err(), Some(StoreError::Unavailable));
        let dangling = tmp.path().join("dangling");
        symlink(tmp.path().join("nowhere"), &dangling)?;
        assert_eq!(FileSpentStore::open(&dangling).err(), Some(StoreError::Unavailable));
        Ok(())
    }

    #[test]
    fn file_dir_swapped_for_symlink_mid_run() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("spent");
        let store = FileSpentStore::open(&dir).map_err(se)?;
        assert_eq!(store.try_spend("a", 10), Ok(Spend::First));
        fs::rename(&dir, tmp.path().join("old"))?;
        let other = tmp.path().join("other");
        fs::create_dir(&other)?;
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700))?;
        symlink(&other, &dir)?;
        assert_eq!(store.try_spend("a", 10), U);
        assert_eq!(store.try_spend("z", 10), U);
        Ok(())
    }

    #[test]
    fn file_dir_group_or_world_writable_refused() -> TestResult {
        for mode in [0o770, 0o702, 0o777] {
            let tmp = tempfile::tempdir()?;
            let dir = tmp.path().join("spent");
            fs::create_dir(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode))?;
            assert_eq!(FileSpentStore::open(&dir).err(), Some(StoreError::Unavailable), "{mode:o}");
            let db_dir = tmp.path().join("db");
            fs::create_dir(&db_dir)?;
            fs::set_permissions(&db_dir, fs::Permissions::from_mode(mode))?;
            assert_eq!(
                SqliteSpentStore::open(db_dir.join("spent.db")).err(),
                Some(StoreError::Unavailable),
                "{mode:o}"
            );
        }
        Ok(())
    }

    #[test]
    fn new_dir_is_created_0700() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("a").join("spent");
        let _s = FileSpentStore::open(&dir).map_err(se)?;
        assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);
        let db = tmp.path().join("b").join("spent.db");
        let _d = SqliteSpentStore::open(&db).map_err(se)?;
        assert_eq!(fs::metadata(tmp.path().join("b"))?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&db)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn dir_not_owned_by_us_refused() -> TestResult {
        let tmp = tempfile::tempdir()?;
        if is_root() {
            let dir = tmp.path().join("spent");
            fs::create_dir(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            std::os::unix::fs::chown(&dir, Some(65534), Some(65534))?;
            assert_eq!(FileSpentStore::open(&dir).err(), Some(StoreError::Unavailable));
            let db_dir = tmp.path().join("db");
            fs::create_dir(&db_dir)?;
            fs::set_permissions(&db_dir, fs::Permissions::from_mode(0o700))?;
            std::os::unix::fs::chown(&db_dir, Some(65534), Some(65534))?;
            assert_eq!(
                SqliteSpentStore::open(db_dir.join("spent.db")).err(),
                Some(StoreError::Unavailable)
            );
        } else {
            // Not root: `/` is owned by root.
            assert_eq!(FileSpentStore::open("/").err(), Some(StoreError::Unavailable));
            assert_eq!(
                SqliteSpentStore::open("/spent.db").err(),
                Some(StoreError::Unavailable)
            );
        }
        Ok(())
    }

    #[test]
    fn sqlite_symlinked_db_refused() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let real = tmp.path().join("real.db");
        drop(SqliteSpentStore::open(&real).map_err(se)?);
        let link = tmp.path().join("link.db");
        symlink(&real, &link)?;
        assert_eq!(SqliteSpentStore::open(&link).err(), Some(StoreError::Unavailable));
        Ok(())
    }

    #[test]
    fn sqlite_db_unlinked_or_dir_removed_mid_run() -> TestResult {
        let tmp = tempfile::tempdir()?;
        let db = tmp.path().join("spent.db");
        let s = SqliteSpentStore::open(&db).map_err(se)?;
        assert_eq!(s.try_spend("a", 10), Ok(Spend::First));
        fs::remove_file(&db)?;
        assert_eq!(s.try_spend("a", 10), U);
        assert_eq!(s.try_spend("b", 10), U);

        let dir = tmp.path().join("d");
        let db2 = dir.join("spent.db");
        let s2 = SqliteSpentStore::open(&db2).map_err(se)?;
        assert_eq!(s2.try_spend("a", 10), Ok(Spend::First));
        fs::remove_dir_all(&dir)?;
        assert_eq!(s2.try_spend("a", 10), U);
        assert_eq!(s2.try_spend("b", 10), U);
        Ok(())
    }
}
