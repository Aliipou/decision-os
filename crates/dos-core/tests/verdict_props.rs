//! Property tests for the verdict lattice (spec/verdict.md).
//!
//! The order is restated here from the spec, independent of `verdict.rs`, so these
//! tests compare the implementation against the contract and not against itself
//! (same approach as oracle tests/test_compose_properties.py).

use dos_core::verdict::{Verdict, compose, compose_with, meet, parse};
use proptest::prelude::*;

const WIRE: [&str; 5] = ["ALLOW", "LIMIT", "CONTAIN", "DEFER", "DENY"];

/// Spec-side rank, least to most restrictive.
fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Allow => 0,
        Verdict::Limit => 1,
        Verdict::Contain => 2,
        Verdict::Defer => 3,
        Verdict::Deny => 4,
    }
}

fn spec_permitting(v: Verdict) -> bool {
    rank(v) <= 2
}

fn verdict() -> impl Strategy<Value = Verdict> {
    prop::sample::select(Verdict::ALL.to_vec())
}

fn verdicts() -> impl Strategy<Value = Vec<Verdict>> {
    prop::collection::vec(verdict(), 0..8)
}

/// Near misses: a wire string with case changes, padding or an inserted code point.
fn near_miss() -> impl Strategy<Value = String> {
    let pad = prop::sample::select(vec![
        "", " ", "\t", "\n", "\r", "\0", "\u{feff}", "\u{200b}", "\u{a0}", "\u{301}", "\u{2028}",
    ]);
    (
        prop::sample::select(WIRE.to_vec()),
        pad.clone(),
        pad,
        prop::collection::vec(any::<bool>(), 7),
    )
        .prop_map(|(w, pre, post, lower)| {
            let body: String = w
                .chars()
                .zip(lower.iter().chain(core::iter::repeat(&false)))
                .map(|(c, l)| if *l { c.to_ascii_lowercase() } else { c })
                .collect();
            format!("{pre}{body}{post}")
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn parse_is_exact_or_deny(s in any::<String>()) {
        let v = parse(&s);
        if WIRE.contains(&s.as_str()) {
            prop_assert_eq!(v.as_str(), s.as_str());
        } else {
            prop_assert_eq!(v, Verdict::Deny);
        }
    }

    #[test]
    fn near_misses_are_deny_unless_exact(s in near_miss()) {
        let v = parse(&s);
        if WIRE.contains(&s.as_str()) {
            prop_assert_eq!(v.as_str(), s.as_str());
        } else {
            prop_assert_eq!(v, Verdict::Deny);
            prop_assert!(!v.is_permitting());
        }
    }

    #[test]
    fn meet_rank_is_max(a in verdict(), b in verdict()) {
        prop_assert_eq!(rank(meet(a, b)), rank(a).max(rank(b)));
    }

    #[test]
    fn is_permitting_matches_spec(a in verdict()) {
        prop_assert_eq!(a.is_permitting(), spec_permitting(a));
    }

    #[test]
    fn compose_is_the_fold_from_allow(vs in verdicts()) {
        prop_assert_eq!(compose(vs.clone()), vs.iter().copied().fold(Verdict::Allow, meet));
    }

    #[test]
    fn compose_is_permutation_invariant(
        (vs, shuffled) in verdicts().prop_flat_map(|v| (Just(v.clone()), Just(v).prop_shuffle()))
    ) {
        prop_assert_eq!(compose(vs), compose(shuffled));
    }

    #[test]
    fn compose_is_antitone_under_extension(xs in verdicts(), ys in verdicts()) {
        let both = compose(xs.iter().chain(ys.iter()).copied());
        prop_assert!(rank(both) >= rank(compose(xs.clone())));
        prop_assert!(rank(both) >= rank(compose(ys.clone())));
        if both.is_permitting() {
            prop_assert!(compose(xs).is_permitting());
            prop_assert!(compose(ys).is_permitting());
        }
    }

    #[test]
    fn compose_with_never_loosens_authority(a in verdict(), evs in verdicts()) {
        let out = compose_with(a, evs.clone());
        prop_assert!(rank(out) >= rank(a));
        for e in &evs {
            prop_assert!(rank(out) >= rank(*e));
        }
        if out.is_permitting() {
            prop_assert!(a.is_permitting());
            prop_assert!(evs.iter().all(|e| e.is_permitting()));
        }
    }

    #[test]
    fn one_deny_vetoes_anywhere(a in verdict(), evs in verdicts(), at in 0usize..8) {
        let mut evs = evs;
        let at = at.min(evs.len());
        evs.insert(at, Verdict::Deny);
        prop_assert_eq!(compose_with(a, evs.clone()), Verdict::Deny);
        prop_assert_eq!(compose(evs), Verdict::Deny);
    }
}

#[test]
fn every_element_is_reachable_by_compose() {
    for v in Verdict::ALL {
        assert_eq!(compose([v]), v);
    }
}
