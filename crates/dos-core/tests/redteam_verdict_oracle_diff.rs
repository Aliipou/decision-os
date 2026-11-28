//! Red team: differential of `parse`/`meet` against the frozen oracle on inputs the
//! oracle can hold (Python `str`, including lone UTF-16 surrogates).
//!
//! The oracle side is generated outside the repo (writes nothing under oracle/):
//!   python -I -B gen_diff.py oracle/decision-os-min/decision_os_min/compose.py OUT 1200000
//! then:
//!   DOS_RT_VERDICT_DIFF=OUT cargo test -p dos-core --test redteam_verdict_oracle_diff -- --ignored
//! Line format: `<hexA>\t<hexB>\t<oracle normalize(A)>\t<oracle meet(A, B)>`, hex is
//! UTF-16LE code units. A Rust caller decodes with `String::from_utf16`; a decode error is
//! the caller's DENY (spec/verdict.md "out of reach of parse"). `from_utf16_lossy` is also
//! checked: it must never produce a permitting verdict for an input the oracle denies.

use dos_core::verdict::{Verdict, meet, parse};

fn units(hex: &str) -> Result<Vec<u16>, String> {
    let b = hex.as_bytes();
    if b.len() % 4 != 0 {
        return Err(format!("odd hex length {}", b.len()));
    }
    let mut out = Vec::with_capacity(b.len() / 4);
    for chunk in b.chunks(4) {
        let s = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        let lo = u8::from_str_radix(s.get(0..2).ok_or("hex")?, 16).map_err(|e| e.to_string())?;
        let hi = u8::from_str_radix(s.get(2..4).ok_or("hex")?, 16).map_err(|e| e.to_string())?;
        out.push(u16::from_le_bytes([lo, hi]));
    }
    Ok(out)
}

/// What a fail-closed Rust decoder hands the lattice.
fn strict(u: &[u16]) -> Verdict {
    match String::from_utf16(u) {
        Ok(s) => parse(&s),
        Err(_) => Verdict::Deny,
    }
}

#[test]
#[ignore = "needs DOS_RT_VERDICT_DIFF (oracle output file); run with --ignored"]
fn parse_and_meet_agree_with_oracle() -> Result<(), String> {
    let path = std::env::var("DOS_RT_VERDICT_DIFF")
        .map_err(|_| "set DOS_RT_VERDICT_DIFF to the oracle output file".to_string())?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let (mut n, mut lone, mut diverge) = (0usize, 0usize, Vec::new());
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let [ha, hb, pa, m] = f.as_slice() else {
            return Err(format!("bad line {line:?}"));
        };
        let (ua, ub) = (units(ha)?, units(hb)?);
        if String::from_utf16(&ua).is_err() {
            lone += 1;
        }
        let (va, vb) = (strict(&ua), strict(&ub));
        if va.as_str() != *pa {
            diverge.push(format!("parse {ha}: rust {}, oracle {pa}", va.as_str()));
        }
        if meet(va, vb).as_str() != *m {
            diverge.push(format!(
                "meet {ha} {hb}: rust {}, oracle {m}",
                meet(va, vb).as_str()
            ));
        }
        // A lossy decoder (U+FFFD substitution) must not create a permission either.
        let lossy = parse(&String::from_utf16_lossy(&ua));
        if lossy.is_permitting() && *pa != lossy.as_str() {
            diverge.push(format!("lossy permits {ha}: {}", lossy.as_str()));
        }
        n += 1;
    }
    println!(
        "{n} pairs, {lone} with lone surrogates, {} divergences",
        diverge.len()
    );
    assert!(n >= 1_000_000, "only {n} pairs");
    assert!(lone > 0, "no lone-surrogate inputs exercised");
    assert!(
        diverge.is_empty(),
        "divergences:\n{}",
        diverge
            .iter()
            .take(50)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    Ok(())
}
