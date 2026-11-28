//! Shared test helpers. Temp dirs come from `TMPDIR` (run on ext4, see status/store.md).
#![allow(dead_code)]

use dos_store::{FileSpentStore, Spend, SpentStore, SqliteSpentStore, StoreError};
use std::path::Path;
use std::sync::Barrier;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An `Err` that carries a message, for `?` in tests.
pub fn fail(msg: impl Into<String>) -> Box<dyn std::error::Error> {
    msg.into().into()
}

pub fn se(e: StoreError) -> Box<dyn std::error::Error> {
    fail(format!("store error: {e:?}"))
}

#[derive(Clone, Copy, Debug)]
pub enum Backend {
    File,
    Sqlite,
}

pub const BACKENDS: [Backend; 2] = [Backend::File, Backend::Sqlite];

pub fn open(backend: Backend, root: &Path) -> Result<Box<dyn SpentStore + Send + Sync>, StoreError> {
    Ok(match backend {
        Backend::File => Box::new(FileSpentStore::open(root.join("spent"))?),
        Backend::Sqlite => Box::new(SqliteSpentStore::open(root.join("spent.db"))?),
    })
}

pub fn purge(backend: Backend, root: &Path, now: i64) -> Result<u64, StoreError> {
    match backend {
        Backend::File => FileSpentStore::open(root.join("spent"))?.purge_expired(now),
        Backend::Sqlite => SqliteSpentStore::open(root.join("spent.db"))?.purge_expired(now),
    }
}

/// Run `n` threads that each call `f` at the same instant; collect the results.
pub fn race<F>(n: usize, f: F) -> Vec<Result<Spend, StoreError>>
where
    F: Fn(usize) -> Result<Spend, StoreError> + Sync,
{
    let barrier = Barrier::new(n);
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let (b, f) = (&barrier, &f);
                s.spawn(move || {
                    b.wait();
                    f(i)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(Err(StoreError::Unavailable)))
            .collect()
    })
}

/// (first, already_spent, errors)
pub fn tally(results: &[Result<Spend, StoreError>]) -> (usize, usize, usize) {
    let first = results.iter().filter(|r| **r == Ok(Spend::First)).count();
    let already = results.iter().filter(|r| **r == Ok(Spend::AlreadySpent)).count();
    (first, already, results.len() - first - already)
}
