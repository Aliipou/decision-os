//! Decision OS authority layer: signed capabilities, attenuation, non-amplifying
//! delegation and the builtin PDP.
//!
//! Design: `design/authority.md`. Invariants: U-DENY, U-ATTEN, U-CHAIN, U-EXPIRY,
//! U-EPOCH, U-REVOKE (`spec/INVARIANT_MAP.md`). The capability chain model comes from
//! sluicegate (`authgate-kernel/src/tcb/dag.rs`, `engine.rs`), adapted to the spec.
//!
//! No I/O, no clock (time is a parameter), no `unsafe`, no panics on any input.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cap;
pub mod chain;
pub mod error;
pub mod mint;
pub mod pdp;
pub mod revocation;

pub use cap::{CapId, Capability, Link, Right, RightSet, SignedCapability};
pub use chain::{ValidChain, verify_chain};
pub use error::AuthorityError;
pub use mint::{Grant, delegate, issue_root};
pub use pdp::{AuthorityDecision, BuiltinPdp, Request};
