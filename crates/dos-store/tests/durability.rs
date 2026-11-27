//! Restart durability and the id contract, both durable backends.
mod common;
use common::*;
use dos_store::{MAX_TOKEN_ID_BYTES, Spend, StoreError};

#[test]
fn spend_drop_reopen_is_already_spent() -> TestResult {
    for backend in BACKENDS {
        let tmp = tempfile::tempdir()?;
        {
            let store = open(backend, tmp.path()).map_err(se)?;
            assert_eq!(store.try_spend("tok-1", 10_000), Ok(Spend::First), "{backend:?}");
        }
        let store = open(backend, tmp.path()).map_err(se)?;
        assert_eq!(store.try_spend("tok-1", 10_000), Ok(Spend::AlreadySpent), "{backend:?}");
        assert_eq!(store.try_spend("tok-2", 10_000), Ok(Spend::First), "{backend:?}");
        drop(store);
        // Purging other, expired ids must not touch the unexpired ones.
        let store = open(backend, tmp.path()).map_err(se)?;
        assert_eq!(store.try_spend("old", 5), Ok(Spend::First));
        drop(store);
        assert_eq!(purge(backend, tmp.path(), 100), Ok(1), "{backend:?}");
        let store = open(backend, tmp.path()).map_err(se)?;
        assert_eq!(store.try_spend("tok-1", 10_000), Ok(Spend::AlreadySpent), "{backend:?}");
        assert_eq!(store.try_spend("tok-2", 10_000), Ok(Spend::AlreadySpent), "{backend:?}");
        assert_eq!(store.try_spend("old", 5), Ok(Spend::First), "{backend:?}");
    }
    Ok(())
}

#[test]
fn id_length_contract() -> TestResult {
    for backend in BACKENDS {
        let tmp = tempfile::tempdir()?;
        let store = open(backend, tmp.path()).map_err(se)?;
        assert_eq!(store.try_spend("", 1), Err(StoreError::InvalidInput), "{backend:?}");
        let long = "x".repeat(MAX_TOKEN_ID_BYTES + 1);
        assert_eq!(store.try_spend(&long, 1), Err(StoreError::InvalidInput), "{backend:?}");
        // 129 two-byte chars = 258 bytes: the limit is bytes, not chars.
        let wide = "é".repeat(129);
        assert_eq!(store.try_spend(&wide, 1), Err(StoreError::InvalidInput), "{backend:?}");
        let max = "x".repeat(MAX_TOKEN_ID_BYTES);
        assert_eq!(store.try_spend(&max, 1), Ok(Spend::First), "{backend:?}");
        let wide_max = "é".repeat(128);
        assert_eq!(store.try_spend(&wide_max, 1), Ok(Spend::First), "{backend:?}");
        // Ids that differ only by a NUL or a trailing byte are different tokens.
        assert_eq!(store.try_spend("a\0b", 1), Ok(Spend::First), "{backend:?}");
        assert_eq!(store.try_spend("a\0", 1), Ok(Spend::First), "{backend:?}");
        assert_eq!(store.try_spend("a", 1), Ok(Spend::First), "{backend:?}");
        assert_eq!(store.try_spend("a\0b", 1), Ok(Spend::AlreadySpent), "{backend:?}");
    }
    Ok(())
}
