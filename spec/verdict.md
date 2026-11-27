# Verdict lattice (v1)

Normative. Implemented by `crates/dos-core/src/verdict.rs`. Checked by
`conformance/vectors/meet/`. Oracle: `oracle/decision-os-min/decision_os_min/compose.py`.
Formal model: `oracle/sluicegate-py/formal/lean4/FreedomKernel/Composition.lean`.

## Elements and order

Five verdicts, least to most restrictive:

| Rank | Verdict | Wire string | Permitting | Meaning |
|---|---|---|---|---|
| 0 | Allow | `ALLOW` | yes | execute as requested |
| 1 | Limit | `LIMIT` | yes | execute a minimized payload |
| 2 | Contain | `CONTAIN` | yes | execute in a sandbox |
| 3 | Defer | `DEFER` | no | escalate to a human |
| 4 | Deny | `DENY` | no | refuse |

Only a permitting verdict may lead to a minted token.

## Meet

`meet(a, b)` is the operand of higher rank (the more restrictive). Full table, row `a`,
column `b`:

| meet | ALLOW | LIMIT | CONTAIN | DEFER | DENY |
|---|---|---|---|---|---|
| **ALLOW** | ALLOW | LIMIT | CONTAIN | DEFER | DENY |
| **LIMIT** | LIMIT | LIMIT | CONTAIN | DEFER | DENY |
| **CONTAIN** | CONTAIN | CONTAIN | CONTAIN | DEFER | DENY |
| **DEFER** | DEFER | DEFER | DEFER | DEFER | DENY |
| **DENY** | DENY | DENY | DENY | DENY | DENY |

Laws (all proved by Kani for every input, see `status/verdict.md`): commutative,
associative, idempotent; `DENY` absorbing; `ALLOW` identity; the result has rank at
least that of each operand and is one of them; `meet(a, b)` is permitting only if both
`a` and `b` are (no amplification, AE-2).

Non-claim, as in the oracle: `meet(LIMIT, CONTAIN) = CONTAIN` drops the redaction
obligation of LIMIT. Obligations do not compose (oracle COMPOSITION.md §7).

## Parse (wire string to verdict)

`parse(s)` returns the verdict whose wire string is exactly `s` (code-point equality),
and `DENY` for every other string. There is no trimming, case folding or Unicode
normalization. Examples that are `DENY`: `""`, `"allow"`, `"Allow"`, `"ALLOW "`,
`"ALLOW\n"`, `"ALLOW\u0000"`, `"﻿ALLOW"`, `"ALLOW​"`, fullwidth `"ＡＬＬＯＷ"`,
Cyrillic `"АLLOW"`, `"ALLOWED"`, `"PERMIT"`.

This is what the oracle's `normalize` does (`_CANONICAL.get(str.__str__(v), DENY)`):
no divergence. Fail closed is the point (oracle fix R2): a foreign or garbled
verdict can only make the outcome more restrictive.

Out of reach of `parse`, and therefore the caller's job:

- A non-string verdict (the oracle maps any non-`str` to `DENY`). A JSON decoder in
  front of `parse` must map a missing or non-string verdict to `DENY`.
- A lone UTF-16 surrogate (`"\ud800"` in JSON). Python can hold it, Rust `&str`
  cannot. The decoder must refuse such input, which a caller treats as `DENY`. It
  must never replace it with U+FFFD and continue.
- The oracle's lying `str` subclass attacks (`__eq__`/`__hash__` overrides,
  `tests/test_redteam_round2.py`) have no Rust analog: `Verdict` is a closed enum and
  `parse` compares bytes.

## Compose

`compose(vs)` folds `meet` over `vs` starting from `ALLOW`. `compose([]) = ALLOW`, as in
the oracle.

`compose_with(authority, evaluators)` folds starting from `authority`; it is the Lean
`composed auth evs` and equals `compose([authority] ++ evaluators)`.

### Why the empty fold is ALLOW, and where AE-1 holds

AE-1 (default deny) is about authority: with no grant, the authority verdict is `DENY`.
It is not a property of the empty fold. Making `compose([])` return `DENY` would break
the fold identity and break AE-2, because `compose([]) = DENY` while
`compose([ALLOW]) = ALLOW`, so adding an input would turn a refusal into a permission.

Rule for kernel code: compose with `compose_with(authority_verdict, evaluator_verdicts)`,
never `compose(evaluator_verdicts)` alone. The fold then always contains the authority
verdict, and a missing grant (`DENY`) absorbs everything.

## What the lattice guarantees to evaluators (and what it does not)

For any authority verdict `a` and evaluator verdicts `e1..en`, with
`c = compose_with(a, [e1..en])`:

1. `c` has rank at least that of `a` and of every `ei`. An evaluator can only restrict.
2. `c` is permitting only if `a` and every `ei` are permitting (AE-2, AE-3). An
   evaluator's `ALLOW` has no effect (identity); its `DENY` always holds (absorbing).
3. `c` does not depend on the order of `e1..en`.
4. Adding an evaluator never makes `c` less restrictive.
5. Any evaluator output that is not exactly a wire string is `DENY` once parsed.

These hold for the verdict only. The lattice says nothing about the other fields of a
decision. The kernel task must also port, with their own tests:

- R1 `sanitize`: an evaluator contributes only `verdict`, `reason`, `action_ref`,
  `legitimacy_digest`, `axiom_ids`; `action_ref` is always overwritten by the kernel;
  `reason` is coerced to a plain string. It never contributes `token_id`, `capability`,
  `containment`, `transformed_payload` or any other kernel field.
- `as_decision`: a non-dict non-string evaluator output, a missing verdict and a
  non-string verdict are all `DENY`.
- `more_restrictive`: ties keep the first (authority) decision. The reason string is
  then picked by registration order; this is a known provenance residual of the oracle,
  not an authorization issue.
- Evaluator errors and timeouts are `DENY` (oracle I4, SG-13).

## Conformance vectors

Area `meet`. Inputs, one of:

- `{"op": "meet", "a": "<string>", "b": "<string>"}`: `meet(parse(a), parse(b))`
- `{"op": "parse", "s": "<string>"}`: `parse(s)`
- `{"op": "compose", "verdicts": ["<string>", ...]}`: `compose(map(parse, verdicts))`

Expected: `{"ok": "<wire string>"}`. No case in this area has an error result. The
vectors are generated from the oracle by `conformance/gen/verdict_from_oracle.py`,
which also checks the oracle against an independent model of this spec.
