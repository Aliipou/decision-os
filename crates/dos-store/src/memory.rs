//! Single-process, non-durable store (the oracle's `InMemorySpentStore`).
//!
//! NOT shared across processes, replicas or restarts: a second process starts empty
//! and accepts every token again (HB-1). Compiled only with the `memory` feature (or
//! in this crate's unit tests), and constructed only by the explicitly named
//! [`MemorySpentStore::single_process_only`].

use crate::{Spend, SpentStore, StoreError, validate_token_id};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;

pub struct MemorySpentStore {
    spent: Mutex<HashMap<String, i64>>,
}

impl MemorySpentStore {
    /// A store valid for exactly one process. See the module docs before using it.
    pub fn single_process_only() -> Self {
        MemorySpentStore {
            spent: Mutex::new(HashMap::new()),
        }
    }

    /// Remove records whose expiry is strictly before `now_unix_ms`.
    pub fn purge_expired(&self, now_unix_ms: i64) -> Result<u64, StoreError> {
        let mut spent = self.spent.lock().map_err(|_| StoreError::Unavailable)?;
        let before = spent.len();
        spent.retain(|_, exp| *exp >= now_unix_ms);
        Ok(u64::try_from(before - spent.len()).unwrap_or(u64::MAX))
    }
}

impl SpentStore for MemorySpentStore {
    fn try_spend(&self, token_id: &str, expires_at_unix_ms: i64) -> Result<Spend, StoreError> {
        validate_token_id(token_id)?;
        let mut spent = self.spent.lock().map_err(|_| StoreError::Unavailable)?;
        match spent.entry(token_id.to_owned()) {
            Entry::Occupied(mut e) => {
                let exp = e.get_mut();
                *exp = (*exp).max(expires_at_unix_ms);
                Ok(Spend::AlreadySpent)
            }
            Entry::Vacant(e) => {
                e.insert(expires_at_unix_ms);
                Ok(Spend::First)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_TOKEN_ID_BYTES;
    use std::sync::Barrier;

    type R = Result<(), StoreError>;

    #[test]
    fn exactly_one_winner_32_threads_50_rounds() -> R {
        let store = MemorySpentStore::single_process_only();
        for round in 0..50 {
            let id = format!("tok-{round}");
            let barrier = Barrier::new(32);
            let results: Vec<Result<Spend, StoreError>> = std::thread::scope(|s| {
                let handles: Vec<_> = (0..32)
                    .map(|_| {
                        s.spawn(|| {
                            barrier.wait();
                            store.try_spend(&id, 1_000)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap_or(Err(StoreError::Unavailable)))
                    .collect()
            });
            let first = results.iter().filter(|r| **r == Ok(Spend::First)).count();
            let already = results
                .iter()
                .filter(|r| **r == Ok(Spend::AlreadySpent))
                .count();
            assert_eq!((first, already), (1, 31), "round {round}: {results:?}");
        }
        Ok(())
    }

    #[test]
    fn invalid_ids_refused() {
        let store = MemorySpentStore::single_process_only();
        assert_eq!(store.try_spend("", 1), Err(StoreError::InvalidInput));
        let long = "x".repeat(MAX_TOKEN_ID_BYTES + 1);
        assert_eq!(store.try_spend(&long, 1), Err(StoreError::InvalidInput));
        let max = "x".repeat(MAX_TOKEN_ID_BYTES);
        assert_eq!(store.try_spend(&max, 1), Ok(Spend::First));
    }

    #[test]
    fn purge_keeps_unexpired_and_respects_extension() -> R {
        let store = MemorySpentStore::single_process_only();
        assert_eq!(store.try_spend("a", 1_000)?, Spend::First);
        assert_eq!(store.purge_expired(999)?, 0);
        assert_eq!(store.purge_expired(1_000)?, 0, "now == expiry must keep");
        assert_eq!(store.try_spend("a", 1_000)?, Spend::AlreadySpent);
        assert_eq!(store.purge_expired(1_001)?, 1);
        assert_eq!(store.try_spend("a", 2_000)?, Spend::First);
        // A replay with a later expiry extends the record.
        assert_eq!(store.try_spend("a", 5_000)?, Spend::AlreadySpent);
        assert_eq!(store.purge_expired(3_000)?, 0);
        assert_eq!(store.try_spend("a", 1)?, Spend::AlreadySpent);
        Ok(())
    }
}
