//! One sqlite database, primary-key insert in WAL mode. See design/store.md.
//!
//! The whole open sequence runs under an exclusive lock on `<db>.lock`, because
//! `busy_timeout` does not cover the brand-new-database WAL switch (PR #9).

use crate::fsutil;
use crate::{Spend, SpentStore, StoreError, StoreOptions, validate_token_id};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, ffi, params};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const U: StoreError = StoreError::Unavailable;

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS spent (token_id BLOB PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID";

pub struct SqliteSpentStore {
    conn: Mutex<Connection>,
    #[cfg_attr(not(unix), allow(dead_code))]
    path: PathBuf,
    /// (device, inode) of the db file as opened. An unlinked or replaced file keeps
    /// working through the open handle but is no longer the durable record, so a
    /// restart would forget every spent token: fail closed instead.
    #[cfg(unix)]
    ident: (u64, u64),
}

#[cfg(unix)]
fn file_ident(path: &Path) -> Result<(u64, u64), StoreError> {
    use std::os::unix::fs::MetadataExt;
    let md = fs::symlink_metadata(path).map_err(u)?;
    if !md.file_type().is_file() {
        return Err(U);
    }
    Ok((md.dev(), md.ino()))
}

fn u<E>(_: E) -> StoreError {
    U
}

impl SqliteSpentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with(path, StoreOptions::default())
    }

    pub fn open_with(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            return Err(U);
        }
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        fsutil::prepare_dir(&parent)?;
        let _lock = fsutil::lock_exclusive(&Self::lock_path(path), options.lock_timeout)?;
        fsutil::check_dir(&parent)?;

        // Refuse a symlink or a non-file; pre-create a new db with mode 0600.
        match fs::symlink_metadata(path) {
            Ok(md) if md.file_type().is_file() => {}
            Ok(_) => return Err(U),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let mut o = OpenOptions::new();
                o.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    o.mode(0o600);
                }
                let f = o.open(path).map_err(u)?;
                f.sync_all().map_err(u)?;
                fsutil::sync_dir(&parent)?;
            }
            Err(_) => return Err(U),
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags).map_err(u)?;
        conn.busy_timeout(options.lock_timeout).map_err(u)?;
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
            .map_err(u)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(U);
        }
        conn.pragma_update(None, "synchronous", "FULL").map_err(u)?;
        let sync: i64 = conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(u)?;
        if sync != 2 {
            return Err(U);
        }
        conn.execute_batch(SCHEMA).map_err(u)?;
        // The table must have exactly our columns (an oracle db has no expires_at).
        conn.prepare("SELECT token_id, expires_at FROM spent")
            .map_err(u)?;
        let mut cols: Vec<(String, String, i64, i64)> = Vec::new();
        {
            let mut st = conn
                .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info('spent') ORDER BY cid")
                .map_err(u)?;
            let rows = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .map_err(u)?;
            for row in rows {
                cols.push(row.map_err(u)?);
            }
        }
        // (name, type, pk); expires_at must also be NOT NULL. (token_id's notnull flag
        // is not checked: it is implied by WITHOUT ROWID primary key.)
        let schema_ok = match cols.as_slice() {
            [(n0, t0, _, pk0), (n1, t1, nn1, pk1)] => {
                n0 == "token_id"
                    && t0.eq_ignore_ascii_case("BLOB")
                    && *pk0 == 1
                    && n1 == "expires_at"
                    && t1.eq_ignore_ascii_case("INTEGER")
                    && *nn1 == 1
                    && *pk1 == 0
            }
            _ => false,
        };
        if !schema_ok {
            return Err(U);
        }
        let check: String = conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(u)?;
        if check != "ok" {
            return Err(U);
        }
        Ok(SqliteSpentStore {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
            #[cfg(unix)]
            ident: file_ident(path)?,
        })
    }

    /// Err unless the path still names the file this store opened.
    fn still_present(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        if file_ident(&self.path)? != self.ident {
            return Err(U);
        }
        Ok(())
    }

    /// The cross-process lock that serializes opening: `<db path>.lock`.
    pub fn lock_path(db_path: &Path) -> PathBuf {
        let mut s = OsString::from(db_path.as_os_str());
        s.push(".lock");
        PathBuf::from(s)
    }

    /// Delete records whose expiry is strictly before `now_unix_ms`.
    pub fn purge_expired(&self, now_unix_ms: i64) -> Result<u64, StoreError> {
        let mut conn = self.conn.lock().map_err(u)?;
        self.still_present()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(u)?;
        let n = tx
            .execute(
                "DELETE FROM spent WHERE expires_at < ?1",
                params![now_unix_ms],
            )
            .map_err(u)?;
        tx.commit().map_err(u)?;
        Ok(u64::try_from(n).unwrap_or(u64::MAX))
    }
}

impl SpentStore for SqliteSpentStore {
    fn try_spend(&self, token_id: &str, expires_at_unix_ms: i64) -> Result<Spend, StoreError> {
        validate_token_id(token_id)?;
        let id = token_id.as_bytes();
        let mut conn = self.conn.lock().map_err(u)?;
        self.still_present()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(u)?;
        let outcome = match tx.execute(
            "INSERT INTO spent (token_id, expires_at) VALUES (?1, ?2)",
            params![id, expires_at_unix_ms],
        ) {
            Ok(1) => Spend::First,
            Ok(_) => return Err(U),
            Err(e) if e.sqlite_extended_error_code() == Some(ffi::SQLITE_CONSTRAINT_PRIMARYKEY) => {
                tx.execute(
                    "UPDATE spent SET expires_at = ?2 WHERE token_id = ?1 AND expires_at < ?2",
                    params![id, expires_at_unix_ms],
                )
                .map_err(u)?;
                Spend::AlreadySpent
            }
            Err(_) => return Err(U),
        };
        // Re-check before commit: the file may have vanished since the first check.
        self.still_present()?;
        // First only once the insert is committed (synchronous=FULL).
        tx.commit().map_err(u)?;
        Ok(outcome)
    }
}
