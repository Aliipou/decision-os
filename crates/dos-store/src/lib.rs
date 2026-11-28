//! Decision OS stores: durable, atomic one-time spend of token ids (U-ONCE).
//!
//! Backends: [`FileSpentStore`] (one `O_EXCL` marker per token), [`SqliteSpentStore`]
//! (primary-key insert in WAL mode) and, behind the `memory` feature, the
//! single-process `MemorySpentStore`. Every error is [`StoreError::Unavailable`]
//! (fail closed); `Spend::First` is returned only once the record is durable.
//! Design: `design/store.md`.

pub use dos_core::store::{Spend, SpentStore, StoreError};
use std::time::Duration;

mod file;
mod fsutil;
mod sqlite;
pub use file::FileSpentStore;
pub use sqlite::SqliteSpentStore;

#[cfg(any(test, feature = "memory"))]
mod memory;
#[cfg(any(test, feature = "memory"))]
pub use memory::MemorySpentStore;

/// Largest accepted token id, in bytes of UTF-8.
pub const MAX_TOKEN_ID_BYTES: usize = 256;

/// Tunables shared by the durable backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreOptions {
    /// How long to wait for the cross-process lock (and sqlite's busy timeout)
    /// before refusing with `Unavailable`.
    pub lock_timeout: Duration,
}

impl Default for StoreOptions {
    fn default() -> Self {
        StoreOptions {
            lock_timeout: Duration::from_secs(5),
        }
    }
}

/// Refuse ids outside the contract: empty or longer than [`MAX_TOKEN_ID_BYTES`].
pub fn validate_token_id(token_id: &str) -> Result<(), StoreError> {
    if token_id.is_empty() || token_id.len() > MAX_TOKEN_ID_BYTES {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}
