//! Decision OS audit log. Design: `design/audit.md`.
//!
//! One file, one JSON object per line, each line the JCS bytes of the entry. Entry
//! `n` carries `seq`, `prev_hash` (the previous `entry_hash`, 64 zeros for the first),
//! `kid`, `sig` and `entry_hash`. The hash and the line are over JCS; the chain rule
//! is the Python oracle's (hash of every field except `entry_hash`), so each side can
//! verify the other's log (see `VerifyOptions::python_compat`).

mod anchor;
mod entry;
mod sink;
mod verify;

pub use anchor::{Anchor, FileAnchor, Head, read_anchor_file};
pub use entry::GENESIS;
pub use sink::FileSink;
pub use verify::{
    Verified, VerifyError, VerifyErrorKind, VerifyOptions, verify_file, verify_file_with_anchor_file,
};
