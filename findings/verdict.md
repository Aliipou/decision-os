# Red team findings: verdict (task/verdict @ 01a2f34)

Status: FIRST PASS (hypotheses written before reading design/verdict.md or status/verdict.md).

## Surface

| Input | Trust | Where |
|---|---|---|
| `parse(&str)` argument | untrusted: evaluator / PDP / foreign engine output | `verdict::parse` |
| `meet(Verdict, Verdict)` | typed, closed enum; caller-held | `verdict::meet` |
| `compose(I)` / `compose_with(Verdict, I)` iterator | caller code (kernel); evaluators supply items | `verdict::compose*` |
| derived traits (`Hash`, `Debug`, `PartialEq`, `Clone`, `Copy`), `as` casts on a fieldless enum | any downstream crate | `Verdict` |
| `Verdict::ALL`, `as_str`, `is_permitting` | public API | `Verdict` |
| No serde, no `Display`, no `FromStr`, no `Default`, no `TryFrom<u8>` in dos-core | n/a | checked by grep |

## Hypotheses (ranked by impact)

1. H1 (S0 if true) Some non-exact string parses to a permitting verdict: case, whitespace,
   NUL, BOM, zero-width, combining marks, fullwidth, confusables, very long strings,
   strings with a wire string prefix/suffix.
2. H2 (S0/S1 if true) Rust `parse` diverges from oracle `normalize` on some string,
   including strings the oracle can hold but Rust `&str` cannot (lone surrogates), as
   a UTF-16 / JSON decoder would hand them over.
3. H3 (S1 design) `compose([]) == ALLOW` is reachable as the only authority input via a
   public API path; spec obligation "use compose_with" is not enforceable by types.
4. H4 (S1 if true) `meet`/`compose` amplify: result permitting while some input is not,
   or result less restrictive than authority, under any iterator shape (empty, huge,
   by-ref, chained, `ExactSizeIterator` lying about size, panicking iterator).
5. H5 (S3, verification) A Kani harness does not constrain what it claims: a mutated
   `meet`/`rank`/`parse`/`is_permitting` survives every harness.
6. H6 (S3, verification) The 108 vectors do not catch the same mutants.
7. H7 (S3) Derived `Debug` (`Allow`) differs from the wire string (`ALLOW`); a caller
   serializing with `{:?}` then parsing gets DENY (fail-closed) — check direction.
   Any serde path that leaks a non-wire repr.
8. H8 (S3) Fieldless enum discriminants are public through `as u8`: `Allow as u8 == 0`.
   A caller comparing `as u8` gets rank order by accident; reordering variants would
   silently invert it. Zeroed/default memory maps to the most permissive verdict.
9. H9 (S2) Any panic path: indexing, arithmetic, recursion; `no_std` holds; clippy lints
   deny indexing/unwrap/panic in the crate.
10. H10 (S2) Huge iterators: `compose` over `u64`-scale iterators terminates without
    allocation or overflow (fold, no counter). Very long strings in `parse` are O(1)/O(n)
    without allocation.
11. H11 (S3) `Verdict` is not `#[non_exhaustive]`; downstream exhaustive matches are fine,
    but a future variant (e.g. `Abstain`) would need care. Note only.
12. H12 (S2) Hash/Eq consistency: derived, so `HashSet<Verdict>` membership cannot be
    lied to (no analog of oracle round-2 str-subclass attack).
