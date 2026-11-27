//! TTL purge never removes a record before its expiry, and racing purges cannot turn
//! one spend into two.
mod common;
use common::*;
use dos_store::{FileSpentStore, Spend, SpentStore, SqliteSpentStore, StoreOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
fn purge_boundaries() -> TestResult {
    for backend in BACKENDS {
        let tmp = tempfile::tempdir()?;
        let store = open(backend, tmp.path()).map_err(se)?;
        assert_eq!(store.try_spend("a", 1_000), Ok(Spend::First));
        assert_eq!(purge(backend, tmp.path(), 999), Ok(0), "{backend:?}");
        assert_eq!(purge(backend, tmp.path(), 1_000), Ok(0), "{backend:?}: now == expiry keeps");
        assert_eq!(store.try_spend("a", 1_000), Ok(Spend::AlreadySpent), "{backend:?}");
        assert_eq!(purge(backend, tmp.path(), 1_001), Ok(1), "{backend:?}");
        assert_eq!(store.try_spend("a", 2_000), Ok(Spend::First), "{backend:?}");
    }
    Ok(())
}

#[test]
fn replay_with_later_expiry_extends_the_record() -> TestResult {
    for backend in BACKENDS {
        let tmp = tempfile::tempdir()?;
        let store = open(backend, tmp.path()).map_err(se)?;
        assert_eq!(store.try_spend("a", 100), Ok(Spend::First));
        assert_eq!(store.try_spend("a", 10_000), Ok(Spend::AlreadySpent));
        // An earlier expiry never shortens it.
        assert_eq!(store.try_spend("a", 50), Ok(Spend::AlreadySpent));
        assert_eq!(purge(backend, tmp.path(), 5_000), Ok(0), "{backend:?}");
        assert_eq!(store.try_spend("a", 1), Ok(Spend::AlreadySpent), "{backend:?}");
        assert_eq!(purge(backend, tmp.path(), 10_001), Ok(1), "{backend:?}");
    }
    Ok(())
}

#[test]
fn purge_removes_exactly_the_expired() -> TestResult {
    for backend in BACKENDS {
        let tmp = tempfile::tempdir()?;
        let store = open(backend, tmp.path()).map_err(se)?;
        for i in 0..100 {
            assert_eq!(store.try_spend(&format!("old-{i}"), 10 + i), Ok(Spend::First));
            assert_eq!(store.try_spend(&format!("new-{i}"), 1_000 + i), Ok(Spend::First));
        }
        assert_eq!(purge(backend, tmp.path(), 500), Ok(100), "{backend:?}");
        for i in 0..100 {
            assert_eq!(
                store.try_spend(&format!("new-{i}"), 1_000 + i),
                Ok(Spend::AlreadySpent),
                "{backend:?}"
            );
        }
        assert_eq!(purge(backend, tmp.path(), 500), Ok(0), "{backend:?}");
    }
    Ok(())
}

#[test]
fn file_unparsable_marker_is_spent_and_never_purged() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("spent");
    let opts = StoreOptions {
        lock_timeout: Duration::from_millis(200),
    };
    let store = FileSpentStore::open_with(&dir, opts).map_err(se)?;
    for (id, body) in [("empty", &b""[..]), ("partial", b"dos-spent-v1 12"), ("junk", b"\xff\xfe")] {
        let marker = dir.join(FileSpentStore::marker_file_name(id).map_err(se)?);
        std::fs::write(&marker, body)?;
        assert_eq!(store.try_spend(id, 5), Ok(Spend::AlreadySpent), "{id}");
        assert_eq!(store.try_spend(id, i64::MAX), Ok(Spend::AlreadySpent), "{id}");
    }
    assert_eq!(store.purge_expired(i64::MAX), Ok(0));
    for id in ["empty", "partial", "junk"] {
        assert_eq!(store.try_spend(id, 5), Ok(Spend::AlreadySpent), "{id}");
    }
    Ok(())
}

#[test]
fn file_purge_removes_orphan_temp_files_only() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("spent");
    let store = FileSpentStore::open(&dir).map_err(se)?;
    std::fs::write(dir.join(".tmp-orphan-1-2"), b"x")?;
    std::fs::write(dir.join("unrelated.txt"), b"x")?;
    assert_eq!(store.try_spend("a", 10_000), Ok(Spend::First));
    store.purge_expired(1).map_err(se)?;
    assert!(!dir.join(".tmp-orphan-1-2").exists());
    assert!(dir.join("unrelated.txt").exists(), "purge touches only its own names");
    assert!(dir.join(FileSpentStore::LOCK_FILE_NAME).exists());
    assert_eq!(store.try_spend("a", 10_000), Ok(Spend::AlreadySpent));
    Ok(())
}

/// Spenders (one store instance each) race a purger that runs with `now = 100`.
/// Every spender passes expiry 10^9, so whatever interleaving happens, the record must
/// exist at the end; with no prior record exactly one spender wins.
fn purge_race(backend: Backend, prior_record: bool) -> TestResult {
    const SPENDERS: usize = 16;
    for round in 0..30 {
        let tmp = tempfile::tempdir()?;
        let id = format!("tok-{round}");
        let stores = (0..SPENDERS)
            .map(|_| open(backend, tmp.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(se)?;
        let first_store = stores.first().ok_or_else(|| fail("no store"))?;
        // Background records so each purge pass has real work.
        for i in 0..50 {
            first_store.try_spend(&format!("bg-{i}"), 10).map_err(se)?;
        }
        if prior_record {
            assert_eq!(first_store.try_spend(&id, 10), Ok(Spend::First));
        }
        let stop = AtomicBool::new(false);
        let purge_errors = std::thread::scope(|s| {
            let purger = s.spawn(|| {
                let mut errors = 0u32;
                let file = FileSpentStore::open(tmp.path().join("spent"));
                let sqlite = SqliteSpentStore::open(tmp.path().join("spent.db"));
                let pass = || match backend {
                    Backend::File => file.as_ref().map_err(Clone::clone)?.purge_expired(100),
                    Backend::Sqlite => sqlite.as_ref().map_err(Clone::clone)?.purge_expired(100),
                };
                // At least one pass, then until the spenders are done.
                loop {
                    if pass().is_err() {
                        errors += 1;
                    }
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                }
                errors
            });
            let results = race(SPENDERS, |i| match stores.get(i) {
                Some(st) => st.try_spend(&id, 1_000_000_000),
                None => Err(dos_store::StoreError::Unavailable),
            });
            stop.store(true, Ordering::SeqCst);
            let errors = purger.join().unwrap_or(u32::MAX);
            (results, errors)
        });
        let (results, errors) = purge_errors;
        let (first, _already, errs) = tally(&results);
        assert_eq!(errs, 0, "{backend:?} round {round}: {results:?}");
        assert_eq!(errors, 0, "{backend:?} round {round}: purge errors");
        if prior_record {
            assert!(first <= 1, "{backend:?} round {round}: {results:?}");
        } else {
            assert_eq!(first, 1, "{backend:?} round {round}: {results:?}");
        }
        // The record now carries expiry 10^9: a purge at 100 must keep it.
        assert_eq!(purge(backend, tmp.path(), 100), Ok(0), "{backend:?} round {round}");
        assert_eq!(
            first_store.try_spend(&id, 1_000_000_000),
            Ok(Spend::AlreadySpent),
            "{backend:?} round {round}: record lost"
        );
    }
    Ok(())
}

#[test]
fn purge_racing_first_spends_keeps_exactly_once() -> TestResult {
    for backend in BACKENDS {
        purge_race(backend, false)?;
    }
    Ok(())
}

#[test]
fn purge_racing_extensions_never_drops_the_extended_record() -> TestResult {
    for backend in BACKENDS {
        purge_race(backend, true)?;
    }
    Ok(())
}
