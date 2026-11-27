# Lean 4 models: audit chain and verdict logic

Core Lean only (no Mathlib). Check with `lean Audit.lean` and `lean Verdict.lean` (Lean 4.36.0);
no output and exit 0 means every theorem checks. No `sorry`; theorems depend on at most the
standard axioms `propext` and `Quot.sound`.

| File | Models | Main theorems |
|---|---|---|
| `Audit.lean` | the hash chain of `crates/dos-audit` | `append_valid`, `seq_eq_index`, `fork_free`, `valid_prefix`, `anchor_binds`, `truncation_visible` |
| `Verdict.lean` | `crates/dos-core/src/verdict.rs` (rank, meet, fold, parse) | commutative, associative, idempotent, DENY absorbs, ALLOW identity, `composeWith_permitting`, `composeWith_rank`, `composeWith_deny`, `parse_other_is_deny` |

What is assumed: collision resistance of the entry hash (a field of `Audit.Model`).
What is not modelled: signatures, the file format, the filesystem. These are models of the
design, not proofs of the Rust code; the Rust tests and the conformance vectors tie them
together. Theorem statements are never edited to make something pass (RUST_REWRITE.md rule 7).
