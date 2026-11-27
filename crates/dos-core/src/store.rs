//! Store contracts used by the enforcement point. No I/O here: implementations live
//! in `dos-store` and `dos-audit`. Every method returns a `Result`; an error means
//! "could not establish the fact", and the PEP treats it as a refusal (fail closed).
//!
//! Time is always a parameter (`now_unix_ms`), never read from a clock in the core.

use alloc::string::String;

/// Why a store could not answer. The PEP refuses on every variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The backing store is missing, locked past its timeout, full, read-only or corrupt.
    Unavailable,
    /// The input is outside the store's contract (empty or oversized id, bad length).
    InvalidInput,
}

impl StoreError {
    /// Stable code used in audit reasons and conformance vectors.
    pub fn code(&self) -> &'static str {
        match self {
            StoreError::Unavailable => "store_unavailable",
            StoreError::InvalidInput => "store_invalid_input",
        }
    }
}

/// Outcome of trying to spend a one-time token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spend {
    /// This call spent the token. Exactly one call ever returns this for a token id,
    /// across threads, processes, restarts and every instance sharing the store.
    First,
    /// The token was already spent (a replay).
    AlreadySpent,
}

/// Durable, atomic, one-time spend of token ids (U-ONCE).
///
/// `expires_at_unix_ms` lets a store drop records after expiry, because an expired
/// token is refused by the PEP before it reaches the store; a store must never drop a
/// record before that time.
pub trait SpentStore {
    fn try_spend(&self, token_id: &str, expires_at_unix_ms: i64) -> Result<Spend, StoreError>;
}

/// Receipt for an appended audit entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReceipt {
    /// Position of the entry in the chain, from 0.
    pub seq: u64,
    /// Lowercase hex SHA-256 of the entry, chained to the previous one.
    pub entry_hash: String,
}

/// Append-only, hash-chained audit log (U-AUDIT, U-CHAIN-LOG). `append` returns only
/// after the entry is durable. An error means the entry may not be durable: the PEP
/// must not run the effect.
pub trait AuditSink {
    /// `entry_jcs` is the JCS bytes of the entry without `seq`, `prev_hash` and
    /// `entry_hash`; the sink assigns those under its lock.
    fn append(&self, entry_jcs: &[u8]) -> Result<AuditReceipt, StoreError>;
}

/// Trusted verifying keys by key id (U-SIG). Unknown kid means not trusted.
pub trait KeyStore {
    /// The 32-byte Ed25519 public key for `kid`, or `None` if it is not trusted at
    /// `now_unix_ms` (unknown, revoked or outside its validity window).
    fn verifying_key(&self, kid: &str, now_unix_ms: i64) -> Result<Option<[u8; 32]>, StoreError>;
}

/// Authoritative revocation state (U-REVOKE, U-EPOCH). Never taken from the request.
pub trait RevocationSource {
    /// True if any of `capability_ids` (kernel-computed ids) is revoked at `now_unix_ms`.
    fn any_revoked(&self, capability_ids: &[String], now_unix_ms: i64) -> Result<bool, StoreError>;
    /// The minimum acceptable epoch for capabilities rooted at `root_kid`.
    fn min_epoch(&self, root_kid: &str) -> Result<u64, StoreError>;
}
