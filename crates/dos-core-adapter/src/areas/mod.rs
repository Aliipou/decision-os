//! Dispatch table: vector area name -> handler.
//!
//! To add an area (e.g. `policy`): create `areas/policy.rs` with
//! `pub fn handle(input: &Json) -> Output`, add `mod canon;` below and one line to
//! `AREAS`. Nothing else in the adapter or the runner changes.

use dos_conformance::protocol::Handler;

mod audit;
mod jcs;
mod meet;
mod selftest;
mod sign;

pub const AREAS: &[(&str, Handler)] = &[
    ("selftest", selftest::handle),
    ("audit", audit::handle),
    ("jcs", jcs::handle),
    ("meet", meet::handle),
    ("sign", sign::handle),
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
