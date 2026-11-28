//! Conformance adapter for the Rust core (spec/CONFORMANCE.md, adapter protocol).
//!
//! The area table lives in `areas/mod.rs`; adding an area is one module plus one line
//! there. Areas not in the table answer `{"unsupported": true}`.

mod areas;

fn main() -> std::process::ExitCode {
    dos_conformance::protocol::serve(areas::AREAS)
}
