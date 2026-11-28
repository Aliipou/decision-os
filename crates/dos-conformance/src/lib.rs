//! Decision OS conformance runner and adapter toolkit (spec/CONFORMANCE.md).
//!
//! - [`json`]: strict JSON reader/writer with exact comparison.
//! - [`vector`]: loads and validates `conformance/vectors/<area>/<name>.json`.
//! - [`manifest`]: adapter manifests `conformance/adapters/<name>/manifest.json`.
//! - [`protocol`]: request/response lines and [`protocol::serve`] for Rust adapters.
//! - [`runner`]: spawns an adapter, streams the vectors and judges the answers.
#![forbid(unsafe_code)]

pub mod json;
pub mod manifest;
pub mod protocol;
pub mod runner;
pub mod vector;
