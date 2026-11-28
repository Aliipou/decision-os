//! Verdict lattice: the meet of a bounded chain, deny-dominant.
//!
//! Spec: `spec/verdict.md`. Vectors: `conformance/vectors/meet/`.
//! Oracle: `oracle/decision-os-min/decision_os_min/compose.py` (`normalize`, `meet`,
//! `compose`, `PERMITTING`). Lean: `FreedomKernel/Composition.lean`.
//!
//! Restrictiveness, least to most: `Allow < Limit < Contain < Defer < Deny`.
//! `meet` returns the more restrictive operand, so `Deny` absorbs and `Allow` is the
//! identity. Every function here is total and cannot panic.

/// A verdict. There is deliberately no `Ord`: compare restrictiveness with [`meet`],
/// never with `<`, whose direction a reader would have to guess.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Verdict {
    /// Execute as requested. Permitting.
    Allow,
    /// Execute a minimized payload. Permitting.
    Limit,
    /// Execute in a sandbox. Permitting.
    Contain,
    /// Escalate to a human. Not permitting.
    Defer,
    /// Refuse. Not permitting. Absorbing.
    Deny,
}

impl Verdict {
    /// Every verdict, least to most restrictive.
    pub const ALL: [Verdict; 5] = [
        Verdict::Allow,
        Verdict::Limit,
        Verdict::Contain,
        Verdict::Defer,
        Verdict::Deny,
    ];

    /// The wire string. `parse(v.as_str()) == v` for every `v`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "ALLOW",
            Verdict::Limit => "LIMIT",
            Verdict::Contain => "CONTAIN",
            Verdict::Defer => "DEFER",
            Verdict::Deny => "DENY",
        }
    }

    /// True for `Allow`, `Limit` and `Contain`: the verdicts that may mint a token.
    pub const fn is_permitting(self) -> bool {
        match self {
            Verdict::Allow | Verdict::Limit | Verdict::Contain => true,
            Verdict::Defer | Verdict::Deny => false,
        }
    }

    /// Restrictiveness rank, as oracle `_RANK` and Lean `rank`. Private on purpose.
    const fn rank(self) -> u8 {
        match self {
            Verdict::Allow => 0,
            Verdict::Limit => 1,
            Verdict::Contain => 2,
            Verdict::Defer => 3,
            Verdict::Deny => 4,
        }
    }
}

/// Wire string to verdict, fail closed. Only the five exact strings `"ALLOW"`,
/// `"LIMIT"`, `"CONTAIN"`, `"DEFER"`, `"DENY"` map to their verdict; everything else
/// (other case, whitespace, NUL, BOM, zero-width or lookalike characters, empty) is
/// `Deny`. No trimming, case folding or Unicode normalization, as oracle `normalize`.
pub fn parse(s: &str) -> Verdict {
    match s {
        "ALLOW" => Verdict::Allow,
        "LIMIT" => Verdict::Limit,
        "CONTAIN" => Verdict::Contain,
        "DEFER" => Verdict::Defer,
        _ => Verdict::Deny,
    }
}

/// The lattice meet: the more restrictive of `a` and `b`.
pub const fn meet(a: Verdict, b: Verdict) -> Verdict {
    if a.rank() >= b.rank() { a } else { b }
}

/// Fold [`meet`] over `verdicts`, starting from the identity `Allow`.
///
/// `compose([])` is `Allow`, as in the oracle. That is the lattice identity, not a
/// grant: kernel code composes the authority verdict with the evaluators through
/// [`compose_with`], so the fold it uses is never empty (AE-1, `spec/verdict.md`).
pub fn compose<I: IntoIterator<Item = Verdict>>(verdicts: I) -> Verdict {
    compose_with(Verdict::Allow, verdicts)
}

/// The authority verdict folded with every evaluator verdict (Lean `composed`).
/// The result is at least as restrictive as `authority` and as every evaluator, and
/// it is permitting only if all of them are (AE-2, AE-3).
pub fn compose_with<I: IntoIterator<Item = Verdict>>(authority: Verdict, evaluators: I) -> Verdict {
    evaluators.into_iter().fold(authority, meet)
}

/// Kani proofs. Run: `cargo kani -p dos-core`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `a` is at least as restrictive as `b`.
    fn at_least(a: Verdict, b: Verdict) -> bool {
        a.rank() >= b.rank()
    }

    #[kani::proof]
    fn meet_is_commutative() {
        let (a, b): (Verdict, Verdict) = (kani::any(), kani::any());
        assert!(meet(a, b) == meet(b, a));
    }

    #[kani::proof]
    fn meet_is_associative() {
        let (a, b, c): (Verdict, Verdict, Verdict) = (kani::any(), kani::any(), kani::any());
        assert!(meet(meet(a, b), c) == meet(a, meet(b, c)));
    }

    #[kani::proof]
    fn meet_is_idempotent() {
        let a: Verdict = kani::any();
        assert!(meet(a, a) == a);
    }

    #[kani::proof]
    fn deny_is_absorbing() {
        let a: Verdict = kani::any();
        assert!(meet(Verdict::Deny, a) == Verdict::Deny);
        assert!(meet(a, Verdict::Deny) == Verdict::Deny);
    }

    #[kani::proof]
    fn allow_is_the_identity() {
        let a: Verdict = kani::any();
        assert!(meet(Verdict::Allow, a) == a);
        assert!(meet(a, Verdict::Allow) == a);
    }

    #[kani::proof]
    fn meet_is_at_least_both_operands_and_selects_one() {
        let (a, b): (Verdict, Verdict) = (kani::any(), kani::any());
        let m = meet(a, b);
        assert!(at_least(m, a) && at_least(m, b));
        assert!(m == a || m == b);
        // Greatest lower bound in restrictiveness: anything at least as restrictive
        // as both operands is at least as restrictive as the meet.
        let c: Verdict = kani::any();
        if at_least(c, a) && at_least(c, b) {
            assert!(at_least(c, m));
        }
    }

    #[kani::proof]
    fn meet_does_not_amplify() {
        let (a, b): (Verdict, Verdict) = (kani::any(), kani::any());
        if meet(a, b).is_permitting() {
            assert!(a.is_permitting() && b.is_permitting());
        }
    }

    #[kani::proof]
    fn permitting_is_the_lower_three() {
        let a: Verdict = kani::any();
        assert!(a.is_permitting() == (a.rank() <= 2));
    }

    /// `parse` compares strings with `memcmp`; wire strings are at most 7 bytes, so 9
    /// unwindings suffice (unwinding assertions are on: a too-small bound fails).
    #[kani::proof]
    #[kani::unwind(9)]
    fn as_str_round_trips() {
        let a: Verdict = kani::any();
        assert!(parse(a.as_str()) == a);
    }

    /// Bounded: up to 4 evaluators after the authority verdict.
    #[kani::proof]
    #[kani::unwind(6)]
    fn compose_with_does_not_amplify() {
        let authority: Verdict = kani::any();
        let evs: [Verdict; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let Some(evs) = evs.get(..n) else { return };
        let out = compose_with(authority, evs.iter().copied());
        assert!(at_least(out, authority));
        for e in evs {
            assert!(at_least(out, *e));
        }
        if out.is_permitting() {
            assert!(authority.is_permitting());
            assert!(evs.iter().all(|e| e.is_permitting()));
        }
        if evs.contains(&Verdict::Deny) || authority == Verdict::Deny {
            assert!(out == Verdict::Deny);
        }
    }

    /// Bounded: every UTF-8 string of at most 8 bytes. `parse` returns a verdict other
    /// than `Deny` only when the input is exactly that verdict's wire string.
    #[kani::proof]
    #[kani::unwind(10)]
    fn parse_is_exact_or_deny() {
        let bytes: [u8; 8] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 8);
        let Some(prefix) = bytes.get(..n) else { return };
        if let Ok(s) = core::str::from_utf8(prefix) {
            let v = parse(s);
            if v != Verdict::Deny {
                assert!(s.as_bytes() == v.as_str().as_bytes());
            }
            if v.is_permitting() {
                assert!(s == "ALLOW" || s == "LIMIT" || s == "CONTAIN");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict::{Allow, Contain, Defer, Deny, Limit};
    use super::*;

    /// The 5x5 table, written out from `spec/verdict.md`, not computed from `rank`.
    /// Row = a, column = b, cell = meet(a, b).
    const TABLE: [(Verdict, [Verdict; 5]); 5] = [
        (Allow, [Allow, Limit, Contain, Defer, Deny]),
        (Limit, [Limit, Limit, Contain, Defer, Deny]),
        (Contain, [Contain, Contain, Contain, Defer, Deny]),
        (Defer, [Defer, Defer, Defer, Defer, Deny]),
        (Deny, [Deny, Deny, Deny, Deny, Deny]),
    ];

    #[test]
    fn meet_table_is_exact() {
        let mut cells = 0;
        for (a, row) in TABLE {
            for (b, want) in Verdict::ALL.into_iter().zip(row) {
                assert_eq!(meet(a, b), want, "meet({a:?}, {b:?})");
                cells += 1;
            }
        }
        assert_eq!(cells, 25);
    }

    #[test]
    fn wire_strings_round_trip() {
        let wire = ["ALLOW", "LIMIT", "CONTAIN", "DEFER", "DENY"];
        for (v, s) in Verdict::ALL.into_iter().zip(wire) {
            assert_eq!(v.as_str(), s);
            assert_eq!(parse(s), v);
            assert_eq!(parse(v.as_str()), v);
        }
    }

    #[test]
    fn permitting_is_exactly_allow_limit_contain() {
        assert!(Allow.is_permitting());
        assert!(Limit.is_permitting());
        assert!(Contain.is_permitting());
        assert!(!Defer.is_permitting());
        assert!(!Deny.is_permitting());
    }

    #[test]
    fn rank_order_is_the_spec_order() {
        let ranks: [u8; 5] = Verdict::ALL.map(Verdict::rank);
        assert_eq!(ranks, [0, 1, 2, 3, 4]);
    }

    #[test]
    fn hostile_strings_parse_as_deny() {
        let cases = [
            "",
            " ",
            "allow",
            "Allow",
            "aLLOW",
            "deny",
            "limit",
            "contain",
            "defer",
            "ALLOW ",
            " ALLOW",
            "ALLOW\n",
            "\tLIMIT",
            "CONTAIN\r",
            "ALLOW\0",
            "\0",
            "\u{feff}ALLOW",
            "ALLOW\u{200b}",
            "\u{200b}ALLOW",
            "ALLOW\u{a0}",
            "\u{ff21}\u{ff2c}\u{ff2c}\u{ff2f}\u{ff37}", // fullwidth ALLOW
            "\u{410}LLOW",                              // Cyrillic A
            "\u{391}LLOW",                              // Greek Alpha
            "L\u{130}M\u{130}T",                        // dotted capital I
            "ALLOW\u{301}",                             // combining acute
            "ALLOWED",
            "ALLO",
            "PERMIT",
            "WAT",
            "\"ALLOW\"",
            "ALLOW,DENY",
            "null",
        ];
        for s in cases {
            assert_eq!(parse(s), Deny, "parse({s:?})");
        }
    }

    #[test]
    fn laws_hold_on_every_element() {
        for a in Verdict::ALL {
            assert_eq!(meet(a, a), a, "idempotent");
            assert_eq!(meet(Deny, a), Deny, "deny absorbing left");
            assert_eq!(meet(a, Deny), Deny, "deny absorbing right");
            assert_eq!(meet(Allow, a), a, "allow identity left");
            assert_eq!(meet(a, Allow), a, "allow identity right");
            for b in Verdict::ALL {
                let m = meet(a, b);
                assert_eq!(m, meet(b, a), "commutative");
                assert!(m.rank() >= a.rank() && m.rank() >= b.rank(), "monotone");
                assert!(m == a || m == b, "selects an operand");
                if m.is_permitting() {
                    assert!(a.is_permitting() && b.is_permitting(), "no amplification");
                }
                for c in Verdict::ALL {
                    assert_eq!(meet(meet(a, b), c), meet(a, meet(b, c)), "associative");
                }
            }
        }
    }

    #[test]
    fn compose_empty_is_the_identity() {
        assert_eq!(compose([]), Allow);
        for a in Verdict::ALL {
            assert_eq!(compose_with(a, []), a);
        }
    }

    #[test]
    fn compose_examples() {
        assert_eq!(compose([Allow, Limit]), Limit);
        assert_eq!(compose([Limit, Contain]), Contain);
        assert_eq!(compose([Allow, Allow, Allow]), Allow);
        assert_eq!(compose([Allow, Deny, Allow]), Deny);
        assert_eq!(compose([Defer, Contain, Limit]), Defer);
        assert_eq!(compose_with(Deny, [Allow, Allow]), Deny);
        assert_eq!(compose_with(Allow, [Limit, Defer]), Defer);
        assert_eq!(compose_with(Limit, [Allow]), Limit);
    }

    #[test]
    fn compose_with_is_compose_of_the_chain() {
        for a in Verdict::ALL {
            for b in Verdict::ALL {
                for c in Verdict::ALL {
                    assert_eq!(compose_with(a, [b, c]), compose([a, b, c]));
                }
            }
        }
    }
}
