# Invariant map (draft for Ali's approval)

Every invariant and requirement from the three oracles, mapped to where it holds in
the unified model (`spec/MODEL.md`). One numbering: the names below. The crosswalk
gives every old number, because the oracles use three different ones (KNOWN_GAPS DOC-1).

Columns: **Holds in** is the component that enforces it. **Check** is the test, vector
area or proof that fails if it breaks; `planned` means no Rust check exists yet.
An invariant that does not map is a stop condition (CLAUDE.md).

## Unified invariants

| ID | Statement | Holds in | Check | Old numbers |
|---|---|---|---|---|
| U-DENY | Absent a grant covering the action, the verdict is DENY. Unknown is DENY. | dos-authority PDP, dos-core verdict::parse | vectors `meet`, `authority`; AE-1 | AE-1; SG README I2 filter |
| U-LATTICE | Verdicts form ALLOW ≺ LIMIT ≺ CONTAIN ≺ DEFER ≺ DENY; composition is meet; any off-lattice value is DENY. | dos-core verdict | Kani (commutative, associative, idempotent, DENY absorbing, ALLOW identity), vectors `meet` | DM R2; SG TLA I5 CompositionMono; CS AE-2 |
| U-VETO | Constraint inputs (legitimacy, safety, evaluators) can only lower the verdict, never grant, never change what executes; a failing, slow or malformed input is DENY. | dos-authority composition | Kani no-amplification, vectors `kernel`; AE-2, AE-3 | AE-2, AE-3; DM R1, R3, I4; SG legitimacy seam; SG-13 |
| U-BIND | A decision is bound to the action fingerprint (actor, capability, purpose, labels, action_ref, payload); the PEP recomputes it and refuses any mismatch. | dos-core fingerprint, dos-pep | vectors `fingerprint`, `executor` | AE-7; DM W-1, W-2; SG README I1 (replaced, SG-3) |
| U-SIG | Only a decision signed by a key in the trusted key set (by `kid`), with domain tag and version, under `verify_strict`, is authority. | dos-core sign, dos-pep | vectors `sign`, `executor` | DM M5 (binding signed); SG-8, SG-9, SG-10, DM-4 |
| U-ONCE | A token is spent at most once across processes, instances and restarts; an unavailable spent store refuses. | dos-pep + dos-store | multi-process double-spend test, vectors `executor` | AE-8; DM HB-1; closes SG-4 |
| U-EXPIRY | A token or capability is refused at or after its expiry, against a caller-supplied clock that cannot move backwards. Every link of a delegation chain is checked. | dos-pep, dos-authority | vectors `executor`, `attenuation` | AE-5; SG README I3, closes SG-5 |
| U-ATTEN | A delegated capability grants a subset of its parent's rights and resources, never outlives it, and requires the parent's DELEGATE right; transitively along the chain. | dos-authority | Kani, vectors `attenuation`, `authority` | AE-4, AE-5; DM AE-4/AE-5 tests; SG README I5, I6, I8; SG TLA I3, I6, I8; closes SG-6 |
| U-CHAIN | Each chain link is signed by the key whose hash is the parent's subject; chain length is bounded; the root is a configured trust anchor. | dos-authority | vectors `authority` | SG dag.rs signature + issuer binding (unnumbered); SG TLA I2; closes SG-7 |
| U-EPOCH | The leaf and every intermediate link meet the authoritative minimum epoch. | dos-authority | vectors `authority` | SG README I4, I7; SG TLA I1, I7 |
| U-REVOKE | Once revoked, no later action executes under the capability, including already-decided ones. Revocation state comes from a store the PEP trusts, never from the request; capability identity is computed by the kernel. | dos-authority + dos-store (RevocationSource) | vectors `authority`, `redteam` | AE-6; SG README I9; SG TLA I4; closes SG-1, SG-2 |
| U-MEDIATE | No path reaches an effect without the PEP: the executor is the only holder of tool handles. | dos-pep, dos-mcp, dos-llm | AE-9, vectors `mcp`, `llm` | AE-9; DM gateway (id-less calls, gzip, half-close) |
| U-AUDIT | Every execute call writes exactly one audit entry before any effect; the entry records the real reason and outcome; a failed audit write means no effect. Every refusal path is covered. | dos-pep + dos-audit | vectors `executor` (every refusal branch), AE-10 | AE-10; DM HB-3, W-3, AE-10; closes DM-1, CS-1 |
| U-CHAIN-LOG | The audit log is a hash chain over JCS bytes; edits, reordering and forks are detected; truncation is detected against an anchor that is wired by default. | dos-audit | vectors `audit`, cross-implementation verify | DM HB-2; closes DM-3, DM-5 |
| U-CANON | Every hashed or signed object is JCS (RFC 8785) of a strictly parsed value: no duplicate keys, no NaN or infinity, no non-JSON values. | dos-core canon | vectors `jcs`, fuzz | closes DM-2, SG-14; SG WA-1, WA-13 |
| U-CORE | The trusted core does no I/O, reads no clock, has no `unsafe`, and does not panic on any input. | dos-core, dos-pep | lints, fuzz, CI TCB budget | SG TCB_DISCIPLINE rules; closes SG-11, SG-12, SG-15 |

## Requirements not yet mapped to a unified invariant

| Old ID | Statement (short) | Proposed home | Status |
|---|---|---|---|
| SG Layer 4 consent | Actions marked `requires_consent` need a signed consent proof. The flag is set by the untrusted adapter. | dos-authority, with the flag coming from policy, not the request | needs Ali: keep in the core or move to policy |
| SG sovereignty flags, A1..A7 | v1 boolean flags and confidence lattice | dropped from the core; a deny-only policy input if kept at all | needs Ali |
| CS-2 | Cumulative ceiling per session (probe B1) | dos-policy | needs Ali: in scope or not |

## Crosswalk of old numbers

| Source | Number | Unified |
|---|---|---|
| sluicegate README | I1 CanonicalBinding | U-BIND |
| | I2 IdentityBinding | U-DENY, U-CHAIN |
| | I3 ExpiryGate | U-EXPIRY |
| | I4 EpochSafety | U-EPOCH |
| | I5 ResourceBinding | U-ATTEN |
| | I6 Attenuation | U-ATTEN |
| | I7 ChainEpoch | U-EPOCH |
| | I8 ChainComplete | U-ATTEN, U-CHAIN |
| | I9 RevocationSafety | U-REVOKE |
| sluicegate TLA+ | I1 EpochSafety, I2 IdentityBinding, I3 Attenuation, I4 RevocationSafety, I5 CompositionMono, I6 ResourceBinding, I7 ChainEpoch, I8 ChainComplete | U-EPOCH, U-CHAIN, U-ATTEN, U-REVOKE, U-LATTICE, U-ATTEN, U-EPOCH, U-ATTEN |
| decision-os-min | HB-1, HB-2, HB-3 | U-ONCE, U-CHAIN-LOG, U-AUDIT |
| | W-1, W-2, W-3 | U-BIND, U-BIND + U-CANON, U-AUDIT |
| | R1, R2, R3 | U-VETO, U-LATTICE, U-VETO |
| | I4 (fail-closed evaluators) | U-VETO |
| | M5 (legitimacy binding signed) | U-SIG + U-VETO |
| contracts-spec | AE-1 .. AE-10 | U-DENY, U-LATTICE + U-VETO, U-VETO, U-ATTEN, U-EXPIRY + U-ATTEN, U-REVOKE, U-BIND, U-ONCE, U-MEDIATE, U-AUDIT |

All 9 sluicegate README invariants, all 8 TLA+ invariants, all 11 decision-os-min items
and all 10 AE requirements map. The three rows above are design questions, not
unmapped invariants.
