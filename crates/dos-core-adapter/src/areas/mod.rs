//! Dispatch table: vector area name -> handler.
//!
//! To add an area (e.g. `canon`): create `areas/canon.rs` with
//! `pub fn handle(input: &Json) -> Output`, add `mod canon;` below and one line to
//! `AREAS`. Nothing else in the adapter or the runner changes.

use dos_conformance::protocol::Handler;

mod selftest;

pub const AREAS: &[(&str, Handler)] = &[
    ("selftest", selftest::handle),
    // ("canon", canon::handle),
    // ("verdict", verdict::handle),
    // ("sign", sign::handle),
];

#[cfg(test)]
mod tests {
    use super::AREAS;

    #[test]
    fn area_names_are_unique() {
        for (i, (a, _)) in AREAS.iter().enumerate() {
            assert!(AREAS.iter().skip(i + 1).all(|(b, _)| a != b), "{a} twice");
        }
    }
}
