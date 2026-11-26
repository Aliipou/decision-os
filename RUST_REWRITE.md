# Decision OS: full Rust rewrite

Task file for Claude Code. Read all of it before starting any phase.

**How the work is run:** `CLAUDE.md` and `docs/agents/CHECKLIST.md`. Agents: `implementer`, `red-team`, `verifier` in `.claude/agents/`. Hooks in `.claude/` enforce the rules below.

## The decision

The whole stack moves to Rust, in one new monorepo and one Cargo workspace:

- the kernel (decide, sign, mint) and the PEP (verify, bind, spend, audit),
- the authority layer (capabilities, attenuation, delegation),
- stores and audit,
- the product layer (policy, guardrails, MCP proxy, model gateway, installer, dashboard, CLI).

Python survives in two roles only:

1. **Oracle.** The current Python implementations are frozen and used by differential tests until Rust reaches parity, then archived. They are never shipped again.
2. **Binding.** `dos-py` (PyO3) exposes the existing `decision_os_min` public API on top of the Rust core, so `pip install` users keep working.

Sources being replaced:

| Source | Size today | Becomes |
|---|---|---|
| `decision-os-min` core (`kernel.py`, `execute.py`, `compose.py`, `attenuation.py`, `authority_pdp.py`, `audit.py`, `spentstore.py`, `sealed.py`, `host.py`, `govern.py`) | ~4.4k lines | `dos-core`, `dos-authority`, `dos-pep`, `dos-store`, `dos-audit`, `dos-py` |
| `decision-os-min` gateway (PR #9 head) | ~5.5k lines + 115 tests | `dos-policy`, `dos-mcp`, `dos-llm`, `dos-install`, `dos-ui`, `dos-cli` |
| `sluicegate` Rust TCB (`authgate-kernel/src/tcb/*`, `authority_graph.rs`, `wire.rs`, `verifier.rs`) | ~10.8k lines incl. tests | reused, not rewritten, inside `dos-core` / `dos-authority` |
| `sluicegate` Python layer (`src/authgate`) | ~12.7k lines | oracle only; adapters re-done in Rust or dropped (see Phase 1 mapping) |
| `sluicegate/formal` (TLA+, Lean 4), Kani harnesses | | `formal/`, aligned to the spec in Phase 6 |

## Ground rules

1. **Oracle rule.** The Python implementations are tagged `oracle-v0` in Phase 0 and frozen. Never change oracle behavior to make Rust pass. When the two disagree, write the case to `conformance/disagreements/<name>.json`, stop that task, and report. The only allowed oracle changes are (a) the spec-driven canonicalization change in Phase 1, tagged `oracle-v1`, and (b) a real oracle bug, fixed in its own PR with a failing test first.
2. **Every PR is green on:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, the conformance suite, and the differential suite. No PR merges with a skipped or `xfail` conformance vector.
3. **Core crates** (`dos-core`, `dos-pep`): `#![forbid(unsafe_code)]`, no I/O, no system clock (time is a parameter), no panic on untrusted input (enforced by fuzzing).
4. **Ed25519:** `verify_strict` only, everywhere. sluicegate had non-strict call sites in `tcb/engine.rs`, `tcb/consent.rs`, `tcb/dag.rs`; they must not come along.
5. **One wire format**, defined in `spec/`, versioned (`v` field), canonicalized with JCS (RFC 8785).
6. **Parity first.** No new features until Phase 7. A behavior the oracle has and Rust lacks is a bug.
7. **Formal artifacts:** never edit a theorem statement, invariant or TLA+ property to make something pass. Models change only through the spec, and such a change is a stop condition.
8. Prose in docs and commit messages: plain, short sentences; no em dashes.

## Phase 0: monorepo and freeze (one PR)

Create `Aliipou/decision-os`. Import `decision-os-min` (at PR #9 head) and `sluicegate` with history (`git filter-repo --to-subdirectory-filter`, then merge). Layout:

```text
decision-os/
  spec/                 normative spec, JSON Schemas, versioned
  conformance/
    vectors/<area>/     language-neutral cases {name, input, expected}
    runner/             diffs any adapter against the vectors
    disagreements/
  crates/
    dos-core            types, JCS, fingerprint, verdict lattice and meet, sign/verify, mint, audit entry hash (no_std + alloc)
    dos-authority       capability graph, attenuation, non-amplifying delegation, builtin PDP, Cedar PDP (cedar-policy crate), OPA HTTP PDP
    dos-pep             executor: verify, binding, expiry, one-time spend, LIMIT/CONTAIN obligations, mandatory audit
    dos-store           SpentStore, KeyStore traits; memory, file, sqlite backends
    dos-audit           hash chain, cross-process locked append, anchor trait
    dos-policy          gateway TOML policy, profiles, rules, learned choices, guardrails
    dos-mcp             MCP stdio proxy
    dos-llm             model gateway (OpenAI chat + Responses, Anthropic Messages)
    dos-install         client registry, config wrap/unwrap, backups, byte-exact restore
    dos-ui              dashboard server (dashboard.html via include_str!), approvals
    dos-cli             the `decision-os` binary
    dos-py              PyO3 binding with the decision_os_min public API
  oracle/
    decision-os-min/    frozen Python, used only by tests
    sluicegate-py/
  formal/               Lean 4, TLA+, Kani notes
  docs/                 consolidated; sluicegate's root markdown files move here with an index
```

Tag `oracle-v0`. Move docs, delete nothing that anything links to.

**Done when:** both oracle test suites run unchanged from `oracle/` in CI and pass (except the known environment-dependent `test_tm_a_unsandboxed_probe_still_shows_ambient_risk`).

## Phase 1: spec v1 and conformance (no Rust yet)

### 1a. Unify the kernel model, in writing

`spec/MODEL.md` states one model:

- **External contract** (what callers and PEPs see) is decision-os-min's: a signed decision bound to the action fingerprint, carrying a one-time token; one audit entry per execute.
- **Authority** is sluicegate's: capabilities, macaroon-style attenuation, delegation that cannot amplify.
- **Legitimacy** stays veto-only evaluators, composed by meet before any mint.

Write `spec/INVARIANT_MAP.md`: every sluicegate invariant I1 to I9, every AE-1 to AE-10 requirement and every decision-os-min hardening item (HB-1..3, W-1..3, R1..3, I4, M5) mapped to where it holds in the unified model. **Any invariant that does not map is a stop condition.**

Also map each sluicegate Python module (`kernel/`, `adapters/`, `integrations/`, `distributed/`, `redteam/`, `research/`) to one of: ported (which crate), replaced by the gateway, or dropped (with reason). Ali approves this table before Phase 2.

### 1b. Spec documents

Action, Decision, token view, AuditEntry, verdict lattice with the full 5x5 meet table, fingerprint definition, JCS canonicalization, Ed25519 over JCS bytes with `kid`, executor refusal order, gateway policy semantics (rule order, learned choices, profiles, purposes), guardrail checks, MCP proxy behavior (gated methods, error shapes, id-less calls, cancellation, half-close), model gateway rewrite rules per API shape, installer contract (wrapped entry shape, state file, restore).

### 1c. Canonicalization change

The oracle hashes `json.dumps(sort_keys=True, separators=(",", ":"))`, which is not JCS (number formatting, non-ASCII escaping). Rust and Python must agree byte for byte, so:

- implement JCS in the oracle per RFC 8785, validated against the RFC's own examples;
- add `"v": 1` to decisions;
- re-run every oracle test; tag `oracle-v1`.

### 1d. Conformance vectors and runner

Vectors live in `conformance/vectors/<area>/`. Areas: `jcs`, `fingerprint`, `sign`, `meet`, `kernel`, `executor` (every `ExecutionRefused` branch), `attenuation`, `authority`, `redteam` (AE-1..AE-10, sluicegate `test_break*`, the 18 wire attack classes), `policy`, `guardrails`, `mcp` (JSONL transcripts in/out), `llm` (request + upstream bytes in, client bytes out, including byte-identical passthrough), `install` (config before, after, after uninstall).

Each implementation ships a `conformance-adapter` executable that reads one JSON case per line on stdin and writes results on stdout. The runner diffs adapters against expected values. Use a fixed test signing key for deterministic signatures.

**Done when:** every behavior-asserting test in both oracle suites maps to at least one vector, or is listed in `conformance/NOT_PORTED.md` as implementation detail with a reason. The Python adapter passes 100%.

## Phase 2: the trusted core

Port `kernel.py`, `execute.py`, `compose.py`, `attenuation.py`, `authority_pdp.py`, `contracts.py`. Reuse sluicegate `tcb/engine.rs`, `tcb/dag.rs`, `tcb/types.rs`, `tcb/sequence.rs`, `tcb/consent.rs`, `tcb/call_gate.rs`, adapting them to the spec instead of rewriting.

- **Kani:** keep sluicegate's 19 harnesses. Add: meet is commutative, associative and idempotent, with DENY absorbing; mint happens only when the composed verdict is permitting; the effect is never invoked when any PEP check fails; spend happens before the effect and at most once.
- **Fuzz** (`cargo fuzz`): JCS, decision verify, wire parser, policy parser.
- **TCB budget:** `dos-core` + `dos-pep` under 1,500 lines excluding tests, enforced in CI; report the real number.
- **Differential:** proptest-generated actions through Rust and the oracle adapter must give the same verdict, the same fingerprint, and signatures that verify across implementations.

**Done when:** core conformance areas pass 100%; 100,000 differential cases show no disagreement; all Kani harnesses prove.

## Phase 3: stores and audit

- **SpentStore:** memory, file (`O_EXCL` marker), sqlite. Open the sqlite store under a cross-process lock; first-open races caused "database is locked" in PR #9. Port the multi-process double-spend tests: exactly one spender wins.
- **Audit:** same chain format as the oracle. Rust must verify a Python-written log and Python must verify a Rust-written log. Cross-process locked append, `head()`, `verify_against_anchor`, anchor trait.
- **KeyStore:** PEM file, mode 0600, `O_EXCL` race-safe creation; trait ready for KMS/HSM.

## Phase 4: Python binding and swap

`dos-py` exposes `DecisionOS`, `Kernel`, `Executor`, `Governor`, `HashLog`, the stores, `AuthorityPDP` hooks and evaluator callbacks with the same signatures. Run the original `decision-os-min` pytest suite against the binding through an import alias.

Build wheels with maturin for manylinux, macOS and Windows in CI.

**Done when:** the binding passes the same tests the oracle passes, with the same skips.

## Phase 5: product layer in Rust

- **dos-policy:** TOML with the same validation messages. Guardrails: the oracle's regexes use lookahead `(?=...)`, which the `regex` crate does not support. Rewrite them in RE2-compatible form; do not pull in `fancy-regex` for this. The guardrail vectors prove equivalence.
- **dos-mcp:** tokio, newline-delimited JSON-RPC. Every behavior in `tests/gateway/test_mcp_proxy.py` and `test_mcp_sdk_interop.py`: tool hiding, annotation hints, approvals, cancellation, id-less calls dropped, `resources/read` gated, half-close replies, server-initiated requests. On Windows, launch `.cmd` servers correctly.
- **dos-llm:** axum + reqwest (rustls, honors `HTTPS_PROXY`). Streaming rewrite identical to the `llm` vectors, byte-identical when nothing is refused, fail closed on unknown encodings and unparseable bodies, gate every client-executed `*_call` item.
- **dos-install:** `toml_edit` for Codex (keeps comments), `serde_json` with `preserve_order`, JSONC detection, the same wrapped-entry shape (now pointing at the binary, not Python), backups, byte-exact restore. It must also unwrap entries written by the Python gateway.
- **dos-ui:** the same dashboard, API, token and Host checks.
- **dos-cli:** the same commands; output covered by `insta` snapshots.
- **Distribution:** one static binary per platform on GitHub Releases, signed with Sigstore, with SHA256SUMS. `install.sh`, `install.ps1` and `Install-DecisionOS.cmd` download and verify the binary. No Python needed.

**Done when:** all gateway vectors pass; `tests/e2e/installed.sh` runs against the binary on Linux, macOS and Windows in CI; measured RSS of one MCP proxy process is reported (target under 10 MB).

## Phase 6: formal alignment

- Lean 4 model of the spec-level semantics; connect the existing theorems to it. Run Lean's executable model against `dos-core` in differential tests (the Cedar approach).
- Update the TLA+ model to the unified model; TLC runs in CI with stated bounds.
- Verus pilot on the `dos-pep` spend path.
- Record in `formal/STATUS.md` what is proved, bounded, axiomatized (Ed25519) or open.

## Phase 7: retire Python, then new work

Archive `oracle/` (kept in the repo, never shipped). Point the old repos' READMEs to `decision-os`. Publish the binding wheels to PyPI as `decision-os` with trusted publishing.

Only after this: Postgres spent store, sharded audit with signed Merkle heads, KMS signing, Envoy filter (proxy-wasm), remote MCP proxying, AuthZEN endpoint.

## Running agents in parallel

One branch and one worktree per task; shared files only through the integrator; Phase 1d splits by vector area, Phase 2 splits after `dos-core` types land, Phase 5 splits by product crate after Phase 3.

## Stop and ask Ali

- any oracle/Rust disagreement on a security-relevant vector;
- any invariant in `INVARIANT_MAP.md` that does not map;
- any change to a theorem, invariant or TLA+ property;
- a Kani harness that cannot be proved within its bound;
- a dependency that needs `unsafe` in `dos-core` or `dos-pep`;
- dropping any sluicegate module not already approved in the Phase 1 table;
- licensing questions.

## Decisions already made (change them here if needed)

- Repo: `Aliipou/decision-os`. Product name: Decision OS. Crates: `dos-*`. The sluicegate name is retired as a product and credited in `dos-authority` docs.
- License: Apache-2.0.
- Canonicalization: JCS (RFC 8785).
- Order: Phase 0, then 1, then 2 and 3, then 4, then 5, then 6 and 7. Phases 2 and 3 can overlap. Phase 6 can start once Phase 2 is done.
- PR #9 is merged into `decision-os-min` before Phase 0, so the oracle includes the hardened gateway.
