//! Decision OS trusted core.
//!
//! No I/O, no system clock (time is a parameter), no `unsafe`, no panics on any input.
//! Each module is specified in `spec/` and checked by `conformance/vectors/<area>/`.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod canon;
pub mod fingerprint;
pub mod sign;
pub mod verdict;
