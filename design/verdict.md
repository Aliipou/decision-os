# Design: verdict lattice (`dos-core::verdict`)

## Goal

Port the verdict lattice of `oracle/decision-os-min/decision_os_min/compose.py`
(`ALLOW`, `LIMIT`, `CONTAIN`, `DEFER`, `DENY`, `PERMITTING`, `normalize`, `meet`,
`compose`) to `crates/dos-core/src/verdict.rs`, with the same results on the same
inputs, proved by Kani and checked against the oracle through `conformance/vectors/meet/`.

Done means:

- `Verdict`, `parse`, `as_str`, `is_permitting`, `meet`, `compose` exist and are total.
- An exhaustive 5x5 meet table, the lattice laws and the parse rule are tested, including
  property tests over arbitrary strings.
- Kani proves the laws and non-amplification (AE-2) for every input.
- Vectors generated from the oracle cover all 25 pairs, at least 30 hostile parse
  inputs and the compose edge cases, and Rust passes all of them.

Out of scope: `as_decision`, `sanitize`, `more_restrictive` (decision dicts and
evaluator contributions, R1). They belong to the kernel task. `spec/verdict.md` states
what the lattice guarantees to them.

## Oracle facts (read from the code, not the brief)

| Oracle | Behavior | Where |
|---|---|---|
| rank | `ALLOW 0, LIMIT 1, CONTAIN 2, DEFER 3, DENY 4` | `_RANK` |
| `normalize(v)` | `_CANONICAL.get(str.__str__(v), DENY)` if `v` is a `str`, else `DENY`. Exact code-point lookup: no case folding, no trimming, no Unicode normalization. | `normalize` |
| `meet(a, b)` | normalize both, then `a if rank(a) >= rank(b) else b` | `meet` |
| `compose(vs)` | fold `meet` from `ALLOW`; `compose([]) == ALLOW` | `compose` |
| `PERMITTING` | `{ALLOW, LIMIT, CONTAIN}` | module top |

The Lean model (`oracle/sluicegate-py/formal/lean4/FreedomKernel/Composition.lean`)
has the same `rank`, `meet` and `permitting`, and its `composed auth evs` folds from the
authority verdict, not from `ALLOW`.

## Approaches

**A. Derived order.** `#[derive(PartialOrd, Ord)]` on the enum in declaration order;
`meet = core::cmp::max`. Short, but the security order becomes an accident of source
order: reordering variants (for readability, or alphabetically) silently changes which
verdict wins, and `a < b` reads as "less" with no clue whether it means less permissive
or less restrictive.

**B. Explicit rank.** A private `const fn rank(self) -> u8` with a `match`, `meet`
compares ranks, as in the oracle and the Lean model. No `Ord` on `Verdict`, so nobody can
write `<` between verdicts and guess the direction. `parse` is a `match` on the five exact
string literals with `_ => Deny`.

**Choice: B.** The order is written once, next to the spec table, and the match is
exhaustive, so adding a variant fails to compile until it gets a rank, a wire string and
a permitting answer.

## Empty composition

The oracle returns `ALLOW` for `compose([])`. The brief asks to weigh this against AE-1
(default deny). Returning `DENY` for an empty list looks safer and is not:

- it breaks the fold identity (`compose(xs) == fold(meet, ALLOW, xs)`);
- it breaks antitone extension, which AE-2 requires: `compose([]) = DENY` and
  `compose([ALLOW]) = ALLOW`, so adding an input would turn a refusal into a permission.

So `compose` keeps the lattice identity and matches the oracle. AE-1 is placed where it
belongs: the kernel composes the authority verdict with the evaluator verdicts, so the
fold is never empty. `compose_with(authority, evaluators)` is that shape (the Lean
`composed`), and the spec tells kernel code to use it. With no grant the authority
verdict is `DENY`, and DENY absorbs.

## Failure modes (each must refuse)

| Input | Result |
|---|---|
| Wire string not exactly one of the five (case, whitespace, NUL, BOM, zero-width, fullwidth, Cyrillic or Greek lookalikes, combining marks, empty, JSON-looking text) | `parse` returns `Deny` |
| Any `meet` with `Deny` | `Deny` |
| `meet` or `compose` with any non-permitting operand | non-permitting result (no amplification) |
| Future variant added to the enum | compile error until rank, string and permitting are given (exhaustive `match`, no wildcard in `rank`, `as_str`, `is_permitting`) |
| Lone UTF-16 surrogate on the wire | not representable as `&str`; the adapter or JSON parser must refuse before `parse` is reached (stated in the spec, tested by the conformance adapter task) |

No function can panic: no indexing, no arithmetic, no `unwrap`.

## Test plan

1. Unit tests in `verdict.rs`: the full 5x5 table written out from the spec (not
   computed from `rank`), `as_str`/`parse` round trip, `is_permitting` for each element,
   laws (commutative, associative, idempotent, DENY absorbing, ALLOW identity, result at
   least as restrictive as each operand), compose identity and examples.
2. proptest: `parse(s)` is `Deny` for every `s` not in the five; compose is the fold,
   is permutation invariant, is antitone under extension; permitting is downward closed.
3. Kani (`#[cfg(kani)]`): commutative, associative, idempotent, DENY absorbing, ALLOW
   identity, `meet` at least as restrictive as both operands and equal to one of them,
   no amplification for `meet`, bounded `compose_with` non-amplification, and `parse`
   returning a non-`Deny` verdict only for the exact wire strings (bounded length).
4. Differential: `conformance/gen/verdict_from_oracle.py` imports the frozen oracle,
   computes each case with both the oracle and an independent spec model, writes vectors,
   and records any difference as `oracle_expected`. An integration test replays every
   vector in `conformance/vectors/meet/` through the Rust functions.
