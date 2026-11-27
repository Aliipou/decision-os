# Status: verdict

Branch `task/verdict`. Design: `design/verdict.md`. Spec: `spec/verdict.md`.

## What changed

| File | Change |
|---|---|
| `crates/dos-core/src/verdict.rs` | `Verdict` enum, `parse`, `as_str`, `is_permitting`, `meet`, `compose`, `compose_with`; unit tests; 11 Kani harnesses under `#[cfg(kani)]` |
| `crates/dos-core/tests/verdict_props.rs` | proptest properties (4096 cases each) |
| `crates/dos-core/tests/meet_vectors.rs` | replays every `conformance/vectors/meet/*.json` through Rust; fails if fewer than 80 |
| `conformance/gen/verdict_from_oracle.py` | generator: oracle and an independent spec model per case, append-only writes, 200,000-case random differential |
| `conformance/vectors/meet/*.json` | 108 new vectors: 29 meet, 55 parse, 24 compose |
| `spec/verdict.md`, `design/verdict.md` | new |
| `crates/dos-core/Cargo.toml` | dev-dependencies `proptest = "1.12"` (1.12.0), `serde_json = "1"` (1.0.154). No normal dependencies. |
| `Cargo.toml` (workspace) | `unexpected_cfgs` check-cfg for `cfg(kani)`. Shared file: one lint line, needed so `#[cfg(kani)]` passes `clippy -D warnings`. |
| `Cargo.lock` | dev-dependency entries only |

Public API (`dos_core::verdict`):

```rust
pub enum Verdict { Allow, Limit, Contain, Defer, Deny }   // Clone, Copy, PartialEq, Eq, Hash, Debug; no Ord, no Default
impl Verdict {
    pub const ALL: [Verdict; 5];                 // least to most restrictive
    pub const fn as_str(self) -> &'static str;   // "ALLOW" .. "DENY"
    pub const fn is_permitting(self) -> bool;    // Allow, Limit, Contain
}
pub fn parse(s: &str) -> Verdict;                // exact wire string, else Deny
pub const fn meet(a: Verdict, b: Verdict) -> Verdict;
pub fn compose<I: IntoIterator<Item = Verdict>>(verdicts: I) -> Verdict;               // fold from Allow
pub fn compose_with<I: IntoIterator<Item = Verdict>>(authority: Verdict, evaluators: I) -> Verdict;
```

## Decisions

- **Parse matches the oracle exactly.** Oracle `normalize` is `_CANONICAL.get(str.__str__(v), DENY)`:
  an exact code-point lookup with no trimming, no case folding and no Unicode normalization. Rust
  `parse` is a `match` on the five literals. No divergence.
- **`compose([])` is `ALLOW`, as in the oracle.** `DENY` would break the fold identity and AE-2:
  `compose([]) = DENY` but `compose([ALLOW]) = ALLOW`, so adding an input would loosen. AE-1 is
  placed on authority: kernel code must use `compose_with(authority, evaluators)`, whose fold always
  contains the authority verdict. Argued in `spec/verdict.md`.
- **Explicit rank, no `Ord`.** The order cannot change by reordering variants, and nobody can write
  `<` between verdicts.

## Evidence

### Tests first, seen failing (stub bodies returned wrong values)

`wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/admin/dos-wt/verdict && CARGO_TARGET_DIR=/root/target/verdict cargo test -p dos-core --no-fail-fast --tests'`

```
     Running unittests src/lib.rs (/root/target/verdict/debug/deps/dos_core-2ae6af5e8bbdf4a5)
test verdict::tests::compose_examples ... FAILED
test verdict::tests::compose_with_is_compose_of_the_chain ... FAILED
test verdict::tests::hostile_strings_parse_as_deny ... FAILED
test verdict::tests::meet_table_is_exact ... FAILED
test verdict::tests::laws_hold_on_every_element ... FAILED
test verdict::tests::permitting_is_exactly_allow_limit_contain ... FAILED
test verdict::tests::rank_order_is_the_spec_order ... FAILED
test verdict::tests::wire_strings_round_trip ... FAILED
test verdict::tests::compose_empty_is_the_identity ... FAILED
test result: FAILED. 0 passed; 9 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/meet_vectors.rs (/root/target/verdict/debug/deps/meet_vectors-30f2db87a12e9686)
test every_meet_vector_passes ... FAILED
failing vectors:
.../conformance/vectors/meet/compose-allow-limit-contain.json: got ALLOW, expected CONTAIN
.../conformance/vectors/meet/compose-deny-first.json: got ALLOW, expected DENY
.../conformance/vectors/meet/meet-allow-deny.json: got ALLOW, expected DENY
... (truncated)
```

### Tests after implementation

`CARGO_TARGET_DIR=/root/target/verdict cargo test -p dos-core` (WSL Ubuntu)

```
     Running unittests src/lib.rs (/root/target/verdict/debug/deps/dos_core-2ae6af5e8bbdf4a5)
test verdict::tests::compose_with_is_compose_of_the_chain ... ok
test verdict::tests::laws_hold_on_every_element ... ok
test verdict::tests::hostile_strings_parse_as_deny ... ok
test verdict::tests::meet_table_is_exact ... ok
test verdict::tests::permitting_is_exactly_allow_limit_contain ... ok
test verdict::tests::rank_order_is_the_spec_order ... ok
test verdict::tests::wire_strings_round_trip ... ok
test verdict::tests::compose_examples ... ok
test verdict::tests::compose_empty_is_the_identity ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/meet_vectors.rs (/root/target/verdict/debug/deps/meet_vectors-30f2db87a12e9686)
test every_meet_vector_passes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.29s
     Running tests/verdict_props.rs (/root/target/verdict/debug/deps/verdict_props-b0b351d12437a010)
test compose_is_antitone_under_extension ... ok
test every_element_is_reachable_by_compose ... ok
test compose_is_the_fold_from_allow ... ok
test compose_with_never_loosens_authority ... ok
test meet_rank_is_max ... ok
test near_misses_are_deny_unless_exact ... ok
test is_permitting_matches_spec ... ok
test compose_is_permutation_invariant ... ok
test one_deny_vetoes_anywhere ... ok
test parse_is_exact_or_deny ... ok
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.32s
```

### Kani (11 harnesses, all proved)

Kani 0.67.0 bundles rustc 1.93.0-nightly, and the workspace declares `rust-version = "1.96"`.
`cargo kani` cannot pass `--ignore-rust-version`, so Kani runs on a throwaway copy
(`/root/kani-verdict`) of `Cargo.toml`, `Cargo.lock` and `crates/`, with only the `rust-version`
lines removed. The script checks that `src/` is identical to the worktree. Harnesses run one at a
time to keep memory low (the machine has 3.4 GB).

```
src identical to worktree
== meet_is_commutative exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== meet_is_associative exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== meet_is_idempotent exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== deny_is_absorbing exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== allow_is_the_identity exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== meet_is_at_least_both_operands_and_selects_one exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== meet_does_not_amplify exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== permitting_is_the_lower_three exit=0
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
== as_str_round_trips exit=0
VERIFICATION:- SUCCESSFUL
Verification Time: 0.629456s
== compose_with_does_not_amplify exit=0
VERIFICATION:- SUCCESSFUL
Verification Time: 5.129214s
== parse_is_exact_or_deny exit=0
VERIFICATION:- SUCCESSFUL
Verification Time: 295.94452s
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
298.25 s, 948464 KB
```

Bounds: the nine meet and element harnesses are complete over all inputs (the domain is finite).
`compose_with_does_not_amplify` covers up to 4 evaluators. `parse_is_exact_or_deny` covers every
UTF-8 string up to 8 bytes; the longest wire string is 7. Unwinding assertions are on (the Kani
default), so a bound that is too small fails rather than passing. The first full run had no
unwind bound on `as_str_round_trips`: `memcmp` unwound without limit (iteration 1889 seen in
the log) and the run died under memory pressure. It now has `#[kani::unwind(9)]`.

Mutation check: the copy's `meet` was changed to always return `a`, then restored:

```
== mutant meet_is_commutative
Failed Checks: assertion failed: meet(a, b) == meet(b, a)
VERIFICATION:- FAILED
== mutant meet_does_not_amplify
Failed Checks: assertion failed: a.is_permitting() && b.is_permitting()
VERIFICATION:- FAILED
copy restored
```

### Differential against the oracle

`/root/venv-verdict/bin/python -B -P conformance/gen/verdict_from_oracle.py` (venv with
`cryptography` only; the oracle is loaded from `oracle/decision-os-min` via `sys.path`, and
`sys.dont_write_bytecode` is set before the import)

```
vectors: 108 written, 0 unchanged, total 108
random differential: 200000 parse + 200000 meet cases, 0 divergences
```

Second run (append-only check): `vectors: 0 written, 108 unchanged, total 108`. No
`DIVERGENCE` lines, so no vector has `oracle_expected`. Counts: 29 meet (all 25 pairs plus 4
off-lattice), 55 parse (5 wire strings plus 50 hostile inputs), 24 compose. Hostile inputs come
from the oracle red-team and property tests (`deny`, `WAT`, `allow`, `permit`, empty) plus case,
whitespace, NUL, BOM, zero-width, NBSP, U+2028, fullwidth, Cyrillic, Greek, Turkish I, combining
mark, math-bold, JSON-looking and list-smuggling strings.

Oracle tree unchanged: `git status --porcelain --ignored oracle/ | wc -l` prints `0`.

### Gate

`GIT_DIR=... GIT_WORK_TREE=... CARGO_TARGET_DIR=/root/target/verdict bash scripts/gate-fast.sh fast`
(WSL; GIT_DIR is set because the worktree's `.git` file holds a Windows path that WSL git cannot read)

```
ok       cargo fmt
ok       cargo clippy
ok       cargo test (dos-conformance dos-core )
skipped  conformance (conformance/run.sh not present yet)
ok       protected paths unchanged
gate exit 0
note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked
protected paths: unchanged
protected exit 0
```

## Attack on this change (checklist)

Five inputs most likely to break it: NUL suffix (`ALLOW\0`), BOM prefix, Cyrillic homoglyph,
trailing newline, empty string. Each is a vector and a unit test, and returns DENY. The Kani parse
proof covers every string up to 8 bytes.

Three ways this could cause an incident in six months, each checked:

1. **Kernel composes evaluators without authority.** `compose(evaluators)` with no evaluators gives
   ALLOW. Mitigation: `compose_with` exists and the spec requires it for kernel code. Still open:
   nothing in the type system forces it. The red team should check the kernel task for it.
2. **A wire format that bypasses `parse`.** A future `serde` derive would serialize as `"Allow"`
   and would deserialize with an error, not DENY. Mitigation: no serde derive. The spec says the
   decoder maps missing, non-string or undecodable verdicts to DENY. `Debug` prints `Allow`, which
   is not the wire string.
3. **Order change through refactoring.** There is no `Ord` and no derived order. The rank is an
   exhaustive `match`, and the table test plus the Kani proofs pin it. Adding a variant fails to
   compile until it has a rank, a string and a permitting answer.

Platforms: vectors are ASCII-only JSON (`ensure_ascii`) written with LF, and `.gitattributes`
forces LF for `*.json`. The vector path is built with `Path::join`. Only Linux (WSL) was run.

## Not done

- Native Windows and macOS test runs. Windows `cargo test` fails to link (`link.exe` returned an
  unexpected error while building the `getrandom` build script, a proptest dev-dependency). This
  is an environment problem, not a code one, but it is unverified.
- `cargo audit` / `cargo deny` on the new dev-dependencies: not installed here (SG-16 requires them
  in workspace CI).
- No conformance adapter or `conformance/run.sh` (owned by the conformance-runner task). The
  vectors are checked here by `tests/meet_vectors.rs` only.
- Kani is not in CI, and it needs the MSRV workaround above until Kani's toolchain reaches 1.96.
- R1 `sanitize`, `as_decision` and `more_restrictive` (kernel task). Their required behavior is
  listed in `spec/verdict.md`.

## Open risks

- `compose` on an empty evaluator list is ALLOW by design (see Decisions); misuse in the kernel is
  the main risk.
- A lone UTF-16 surrogate in JSON (`"\ud800"`) cannot reach `parse`. Whether the Rust adapter or
  decoder refuses it (correct) or replaces it with U+FFFD and continues (it would still parse as
  DENY, but it is a silent rewrite) is the adapter's job. No vector covers it.
