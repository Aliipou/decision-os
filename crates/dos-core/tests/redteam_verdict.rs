//! Red team (task/verdict @ 01a2f34): attacks on the verdict lattice that HELD.
//! Each test is a reproduction of a hypothesis from findings/verdict.md; all pass on the
//! target. They stay as permanent regression tests.

use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use dos_core::verdict::{Verdict, compose, compose_with, meet, parse};

const WIRE: [&str; 5] = ["ALLOW", "LIMIT", "CONTAIN", "DEFER", "DENY"];

fn want(s: &str) -> Verdict {
    match s {
        "ALLOW" => Verdict::Allow,
        "LIMIT" => Verdict::Limit,
        "CONTAIN" => Verdict::Contain,
        "DEFER" => Verdict::Defer,
        _ => Verdict::Deny,
    }
}

/// H1: every Unicode scalar value as a prefix or a suffix of every wire string, and as a
/// replacement of its first and last character. 5 x 1,112,064 x 4 inputs.
#[test]
fn rt_h1_every_code_point_around_a_wire_string_is_deny() {
    let mut checked = 0u64;
    for w in WIRE {
        let (_, rest) = w.split_at(1);
        let (init, _) = w.split_at(w.len() - 1);
        let mut buf = String::with_capacity(16);
        for c in (0u32..=0x10FFFF).filter_map(char::from_u32) {
            for variant in 0..4 {
                buf.clear();
                match variant {
                    0 => {
                        buf.push(c);
                        buf.push_str(w);
                    }
                    1 => {
                        buf.push_str(w);
                        buf.push(c);
                    }
                    2 => {
                        buf.push(c);
                        buf.push_str(rest);
                    }
                    _ => {
                        buf.push_str(init);
                        buf.push(c);
                    }
                }
                let got = parse(&buf);
                assert_eq!(got, want(&buf), "parse({buf:?})");
                if got.is_permitting() {
                    assert!(buf == "ALLOW" || buf == "LIMIT" || buf == "CONTAIN", "{buf:?}");
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 22_000_000);
}

/// H1: every ASCII case variant of every wire string; only the all-upper one is exact.
#[test]
fn rt_h1_case_variants() {
    for w in WIRE {
        for mask in 0u32..(1 << w.len()) {
            let s: String = w
                .chars()
                .enumerate()
                .map(|(i, c)| if mask & (1 << i) != 0 { c.to_ascii_lowercase() } else { c })
                .collect();
            assert_eq!(parse(&s), want(&s), "{s:?}");
        }
    }
}

/// H1/H10: very long inputs, including a wire string repeated or padded to megabytes.
#[test]
fn rt_h1_long_strings_are_deny() {
    let cases = [
        "ALLOW".repeat(1 << 20),
        format!("ALLOW{}", "\0".repeat(1 << 20)),
        format!("{}ALLOW", " ".repeat(16 << 20)),
        format!("{}LIMIT", "\u{200b}".repeat(1 << 20)),
        format!("CONTAIN{}", "\u{301}".repeat(1 << 20)),
    ];
    for s in &cases {
        assert_eq!(parse(s), Verdict::Deny, "len {}", s.len());
    }
}

/// H1: NFKC / confusable / normalization forms that a "helpful" parser would fold.
#[test]
fn rt_h1_confusables_and_normalization_forms() {
    let cases = [
        "\u{ff21}\u{ff2c}\u{ff2c}\u{ff2f}\u{ff37}", // fullwidth, NFKC -> ALLOW
        "\u{1d400}\u{1d40b}\u{1d40b}\u{1d40e}\u{1d416}", // math bold, NFKC -> ALLOW
        "\u{24b6}\u{24c1}\u{24c1}\u{24c4}\u{24cc}", // circled letters
        "\u{e0041}\u{e004c}\u{e004c}\u{e004f}\u{e0057}", // tag characters
        "A\u{34f}LLOW",                              // combining grapheme joiner
        "AL\u{ad}LOW",                               // soft hyphen
        "ALL\u{2060}OW",                             // word joiner
        "\u{202e}WOLLA",                             // RTL override + reversed
        "ALLOW\u{fe0f}",                             // variation selector
        "LIM\u{131}T",                               // dotless i
        "\u{1e9e}",                                  // capital sharp s
        "\u{212a}",                                  // Kelvin sign (folds to k)
        "\u{fffd}ALLOW",                             // lossy-decoder residue
    ];
    for s in cases {
        assert_eq!(parse(s), Verdict::Deny, "{s:?}");
    }
}

/// H4/H10: huge iterators. The fold is linear, keeps no counter, allocates nothing.
#[test]
fn rt_h4_huge_iterators_keep_the_laws() {
    const N: usize = 20_000_000;
    let allows = || std::iter::repeat_n(Verdict::Allow, N);
    assert_eq!(compose(allows()), Verdict::Allow);
    assert_eq!(compose(allows().chain([Verdict::Deny])), Verdict::Deny);
    assert_eq!(compose([Verdict::Defer].into_iter().chain(allows())), Verdict::Defer);
    assert_eq!(compose_with(Verdict::Deny, allows()), Verdict::Deny);
    assert_eq!(compose_with(Verdict::Contain, allows()), Verdict::Contain);
}

/// An iterator whose size_hint lies (claims empty, yields a Deny).
struct Liar(Option<Verdict>);
impl Iterator for Liar {
    type Item = Verdict;
    fn next(&mut self) -> Option<Verdict> {
        self.0.take()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

/// H4: a lying size_hint cannot make compose skip an element.
#[test]
fn rt_h4_lying_size_hint_is_ignored() {
    assert_eq!(compose(Liar(Some(Verdict::Deny))), Verdict::Deny);
    assert_eq!(compose_with(Verdict::Allow, Liar(Some(Verdict::Defer))), Verdict::Defer);
}

/// H4: a panicking iterator (caller code) unwinds out of compose; no verdict, and in
/// particular no ALLOW, is produced. The caller must treat the unwind as DENY.
#[test]
fn rt_h4_panicking_iterator_yields_no_verdict() {
    let it = [Verdict::Allow, Verdict::Allow].into_iter().chain(std::iter::from_fn(|| -> Option<Verdict> {
        panic!("evaluator iterator exploded")
    }));
    let r = catch_unwind(AssertUnwindSafe(|| compose_with(Verdict::Allow, it)));
    assert!(r.is_err(), "compose returned a verdict past a panicking iterator: {r:?}");
}

/// H7: derived Debug is not the wire string; reading Debug back through parse can only
/// fail closed (every verdict becomes DENY), never permit.
#[test]
fn rt_h7_debug_is_not_wire_and_fails_closed() {
    for v in Verdict::ALL {
        let dbg = format!("{v:?}");
        assert_ne!(dbg, v.as_str(), "Debug equals the wire string for {v:?}");
        assert_eq!(parse(&dbg), Verdict::Deny);
        assert_eq!(parse(&format!("{v:#?}")), Verdict::Deny);
    }
}

/// H12: derived Hash/Eq agree; a permitting set built from wire strings has exactly 3.
#[test]
fn rt_h12_hash_eq_consistent() {
    let permitting: HashSet<Verdict> = Verdict::ALL.into_iter().filter(|v| v.is_permitting()).collect();
    assert_eq!(permitting.len(), 3);
    for s in ["ALLOW", "LIMIT", "CONTAIN"] {
        assert!(permitting.contains(&parse(s)));
    }
    for s in ["DEFER", "DENY", "allow", "ALLOW\0", ""] {
        assert!(!permitting.contains(&parse(s)), "{s:?}");
    }
}

/// H3 (S3 design, see findings): the AE-1 obligation lives in prose only. Both shapes
/// below type-check and permit with no authority input at all. This test PASSES; it pins
/// the hazard so a future type-level fix (finding RT-VERDICT-2) shows up as a diff here.
#[test]
fn rt_h3_empty_fold_permits_through_both_public_entry_points() {
    let no_evaluators: Vec<Verdict> = Vec::new();
    assert!(compose(no_evaluators.clone()).is_permitting());
    // compose_with does not help by itself: the "authority" is any Verdict the caller
    // picks, and Verdict::Allow is a public constant.
    assert!(compose_with(Verdict::Allow, no_evaluators).is_permitting());
}

/// H8 (S3 note): discriminant order equals restrictiveness, and the zero discriminant is
/// the most permissive verdict. Pinned so a variant reorder is visible.
#[test]
fn rt_h8_discriminant_order() {
    let d: Vec<u8> = Verdict::ALL.iter().map(|v| *v as u8).collect();
    assert_eq!(d, [0, 1, 2, 3, 4]);
    assert_eq!(Verdict::Allow as u8, 0);
    for a in Verdict::ALL {
        for b in Verdict::ALL {
            assert_eq!(meet(a, b) as u8, (a as u8).max(b as u8));
        }
    }
}
