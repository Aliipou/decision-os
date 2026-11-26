# Known gaps

Every gap found in the two oracles, and what the Rust implementation must do instead.
The oracles stay frozen (ground rule 1). A gap closed in Rust is a deliberate divergence:
its conformance vector records the oracle's behavior as `oracle_expected` and the spec's
behavior as `expected`, and the runner checks Rust against `expected`.

Status: `open` until a Rust test or vector proves the closure, then the ID of that test.

Sources: sluicegate at `c731f31`, decision-os-min at `5ee36cb` (both imported under
`oracle/`). File references are relative to the oracle directory named in each section.

## sluicegate (oracle/sluicegate-py)

| ID | Gap | Evidence | Rust requirement | Status |
|---|---|---|---|---|
| SG-1 | Revocations travel inside the adapter-built action, so an attacker drops them. I9 holds only if the caller is honest. | authgate-kernel/src/tcb/types.rs:148, engine.rs:95-104 | The PEP reads epoch and revocations from a trusted store it owns (trait `RevocationSource`), never from the request. | open |
| SG-2 | `proof_hash` is taken from the request and never recomputed, so a revocation keyed on it is dodged by changing it. | tcb/dag.rs:76 | Capability identity is the hash of its canonical signed bytes, computed by the kernel. | open |
| SG-3 | The binding hash is unkeyed SHA-256: whoever builds the action can recompute it after mutating the action. | tcb/types.rs:172-194 | Binding is the action fingerprint inside a kernel-signed decision (decision-os-min contract). | open |
| SG-4 | No replay defense: `action.timestamp` is not compared with `now`, there is no nonce store. Docs claim a 30 s window and a nonce cache. | engine.rs:360-375; THREAT_MODEL.md:50,276 | One-time token with a persistent, atomic spent store; expiry checked against a caller-supplied clock. | open |
| SG-5 | Only the leaf capability's expiry is checked; intermediate links may be expired. | engine.rs:61; dag.rs (no expiry check) | Every link in the chain must be unexpired at `now`. | open |
| SG-6 | The parent's DELEGATE right is never required for a delegation. | dag.rs (no RIGHT_DELEGATE check); ARCHITECTURE.md:159 says it is | Each delegated link requires DELEGATE on its parent. | open |
| SG-7 | Depth check `depth > 16` before increment allows 17 nodes. | dag.rs:44-47 | Chain length at most the stated bound, tested at bound and bound + 1. | open |
| SG-8 | Ed25519 `verify` (accepts small-order keys and malleable encodings) at 4 TCB sites. | dag.rs:62,71; engine.rs:134; consent.rs:154 | `verify_strict` only (ground rule 4); small-order key vectors. | open |
| SG-9 | No domain separation or version byte in any signed payload; capability, revocation and consent signatures can collide if a key is reused (Tamarin pilot, PR #21). | types.rs:65-81,122-127 | Every signed object is JCS bytes of an object with a `v` field and a type tag, plus a `kid`. | open |
| SG-10 | `crypto.rs` discards the `verify_strict` result and "verifies" by re-signing with the process key, so only this process's signatures validate. | crypto.rs:125 | Verification is a real signature check against a key looked up by `kid`. | open |
| SG-11 | Kani: 19 harnesses target the v1 engine, 4 live in an uncompiled file (`tcb/sequence.rs`), 7 in `formal/kani` are not wired to any crate. None run in CI. | kani_proofs.rs; tcb/mod.rs:13; formal/kani/ | Every harness compiles against the real crate and runs in CI with stated bounds. | open |
| SG-12 | Fuzz targets reference `freedom_kernel` and do not compile; not in CI. | authgate-kernel/fuzz | Fuzz targets build in CI; each runs for a bounded time per PR. | open |
| SG-13 | Extension and plugin exceptions are caught and logged instead of denying. | PLUGIN_MODEL.md:91 | Any evaluator or extension failure is DENY and is audited. | open |
| SG-14 | Signed-result canonical form differs between spec (big-endian) and code (little-endian, different field order). | SPEC.md:241-246; crypto.rs:47-72 | One canonical form (JCS), one definition in `spec/`. | open |
| SG-15 | TCB size is stated seven different ways; real non-test TCB is about 2,000 lines. | see docs digest | TCB lines measured by a script in CI against one budget. | open |
| SG-16 | The kernel's optional `sandbox` feature pins wasmtime with eight advisories (RUSTSEC-2026-0566..0573: host aborts, panics, unbounded memory). The oracle's supply-chain job fails, here and on sluicegate main. | authgate-kernel/Cargo.lock; job "Supply chain" in oracle-sluicegate-ci.yml | No dos-* crate ships a dependency with an open advisory: `cargo deny` and `cargo audit` block the workspace CI. Any sandbox uses a patched wasmtime. | open |

## decision-os-min (oracle/decision-os-min)

| ID | Gap | Evidence | Rust requirement | Status |
|---|---|---|---|---|
| DM-1 | HB-3 is not total. These refusal paths write no audit entry: missing `result["decision"]`, a non-dict decision, `UnfingerprintablePayload` at the PEP, an audit write failing on the refusal path, and `UnfingerprintablePayload` raised by `decide` inside `handle`. | execute.py:101,166-179; kernel.py | Every call to execute writes exactly one entry, or fails the call without running the effect if the audit write fails. | open |
| DM-2 | The fingerprint and decision canonical form is Python `json.dumps` (ASCII escaping, float repr, NaN allowed, `default=str`), not JCS. | kernel.py:67-69,130-144 | JCS (RFC 8785); NaN and infinity refused; non-JSON values refused, never stringified. | open |
| DM-3 | The audit line is written with non-canonical `json.dumps(entry)`; the hash uses `default=str`. | audit.py:89-110 | Audit entry hash over JCS bytes; the stored line is the same JCS bytes. | open |
| DM-4 | Decisions carry no `v` and no `kid`; `issued_by` is a fixed string. | kernel.py:147-156,549 | `v` and `kid` in every decision; verification picks the key by `kid`. | open |
| DM-5 | `DecisionOS` never wires an audit anchor, so tail truncation goes undetected by default. | audit.py:123-148 | Anchor trait wired by default; `verify_against_anchor` in the standard path. | open |
| DM-6 | The token view is unsigned and unused by the PEP; contracts.py types are stale. | kernel.py:551-560; contracts.py | Spec defines the decision as the only authority object; the token view is derived, never trusted. | open |

## Product layer (gateway, found this session)

Closed in the oracle by PR #9 and kept as regression vectors for Rust:
cwd shadowing (`python -P`), first-start sqlite lock, Windows notification code injection
through a tool name, ghost approvals after a killed proxy, `tools/call` without an id,
ungated gzip responses, lost replies on half-closed stdin.

## Docs and definitions

| ID | Gap | Requirement |
|---|---|---|
| DOC-1 | Invariant numbering differs between README (I1..I9), TLA+ (I1..I8) and TCB docs. | `spec/INVARIANT_MAP.md` uses one numbering with a crosswalk. |
| DOC-2 | AE-1..AE-3 and AE-6..AE-9 are named (ASSUMPTIONS.md:45-50) but defined in neither sluicegate nor decision-os-min. | Closed: defined in `oracle/contracts-spec/conformance/PROFILE.md` (imported in Phase 0). |

## Conformance suite (oracle/contracts-spec)

| ID | Gap | Rust requirement | Status |
|---|---|---|---|
| CS-1 | The AE-10 check passes on decision-os-min although DM-1 lists five refusal paths with no audit entry: the suite does not reach those paths. A green AE run is necessary, not sufficient. | Every DM-1 path gets its own vector in `conformance/vectors/executor/`; the Rust run must pass those as well as the AE suite. | open |
| CS-2 | Probe B1 (cumulative ceiling keyed on an agent-supplied session id) is UNSUPPORTED for decision-os-min: nothing is measured. | Either support the surface and measure it, or state in the spec that it is out of scope. | open |
