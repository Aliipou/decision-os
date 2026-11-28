//! U-ONCE under thread contention: 32 threads, 50 rounds, exactly one `First`.
mod common;
use common::*;
use dos_store::{FileSpentStore, SpentStore, SqliteSpentStore};

const THREADS: usize = 32;
const ROUNDS: usize = 50;

#[test]
fn shared_instance_exactly_one_winner() -> TestResult {
    for backend in BACKENDS {
        let tmp = tempfile::tempdir()?;
        let store = open(backend, tmp.path()).map_err(se)?;
        for round in 0..ROUNDS {
            let id = format!("tok-{round}");
            let results = race(THREADS, |_| store.try_spend(&id, i64::MAX));
            assert_eq!(
                tally(&results),
                (1, THREADS - 1, 0),
                "{backend:?} round {round}: {results:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn instance_per_thread_exactly_one_winner() -> TestResult {
    for backend in BACKENDS {
        let tmp = tempfile::tempdir()?;
        let stores = (0..THREADS)
            .map(|_| open(backend, tmp.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(se)?;
        for round in 0..ROUNDS {
            let id = format!("tok-{round}");
            let results = race(THREADS, |i| match stores.get(i) {
                Some(s) => s.try_spend(&id, i64::MAX),
                None => Err(dos_store::StoreError::Unavailable),
            });
            assert_eq!(
                tally(&results),
                (1, THREADS - 1, 0),
                "{backend:?} round {round}: {results:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn concurrent_opens_of_a_new_store_all_succeed() -> TestResult {
    for round in 0..10 {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("new").join("spent");
        let db = tmp.path().join("newdb").join("spent.db");
        let results = race(THREADS, |_| FileSpentStore::open(&dir)?.try_spend("t", 1));
        assert_eq!(tally(&results), (1, THREADS - 1, 0), "file round {round}: {results:?}");
        let results = race(THREADS, |_| SqliteSpentStore::open(&db)?.try_spend("t", 1));
        assert_eq!(tally(&results), (1, THREADS - 1, 0), "sqlite round {round}: {results:?}");
    }
    Ok(())
}
