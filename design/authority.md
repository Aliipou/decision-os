# Design: dos-authority (capabilities, attenuation, delegation, builtin PDP)

## Goal

`crates/dos-authority` answers one question for the kernel: does a presented delegation
chain give `actor` the `rights` on `resource` at time `now`? The answer is a `Verdict`
(`ALLOW` or `DENY`, never anything else from the builtin PDP). Every failure is `DENY`.

- Capabilities are signed objects: Ed25519 over the JCS bytes of the capability body,
  domain `capability`, strict verification only (`dos_core::sign`).
- Attenuation: a child may only narrow rights, resource scope, expiry and epoch.
- Delegation chain validation from a trusted root key (`KeyStore`), with expiry,
  revocation and minimum epoch from a trusted source (`RevocationSource`), never from
  the request.
- Revocation notices: root-signed, domain `revocation`, for a store that ingests them.
- No I/O, no clock (`now_unix_ms` is a parameter), `#![no_std]` + `alloc`, no `unsafe`,
  no `unwrap`/`expect`/`panic`/indexing in non-test code.

Out of scope: the Cedar and OPA PDPs (they need I/O or a new dependency; Phase 2 lists
them for this crate, they are a follow-up), SG consent (Layer 4; INVARIANT_MAP marks it
"needs Ali"), the kernel that composes the authority verdict with evaluators, a
RevocationSource or KeyStore backend (dos-store).

## Wire format (v1)

A capability body is a JSON object with exactly these members:

| member | type | rule |
|---|---|---|
| `v` | integer | `1` |
| `kid` | string | kid of the issuer key (32 lowercase hex) |
| `subject` | string | holder, 1..=256 bytes. To delegate further it must be the kid of the holder's key |
| `resources` | array of strings | 1..=64, strictly ascending by bytes, each 1..=256 bytes; `*` only as the last character (prefix pattern; `*` alone is everything) |
| `rights` | array of strings | 1..=8, strictly ascending, from `delegate execute model_invoke network policy_modify read spawn write` (sluicegate's bits) |
| `expires_at_ms` | integer | 0..=2^53-1, unix ms; the capability is dead at and after it |
| `epoch` | integer | 0..=2^53-1 |
| `parent` | string | delegated links only: id of the parent (64 lowercase hex) |
| `issuer_key` | string | delegated links only: issuer public key (64 hex) |

A root link has neither `parent` nor `issuer_key`; a delegated link has both. Any other
member, a missing member, a wrong type, an unsorted or duplicated set, or an out of
range number refuses. A signed link is `{"cap": <body>, "sig": "<128 hex>"}`; a chain
is a JSON array of links, root first, 1..=16 links. Input sizes are bounded before
parsing (32 KiB per link, 512 KiB per chain).

Signed bytes: `dos_core::sign` message for domain `capability` over `JCS(body)`.
Capability id: `hex(SHA-256(signed_message(capability, JCS(body))))`, computed by this
crate, never read from input (closes SG-2). The id covers the body, not the signature,
so re-signing the same body (a second valid signature) cannot dodge a revocation.

## Two approaches for chain validation, and the choice

**A. Bundle and search (sluicegate `dag.rs`).** The request carries a bag of proofs;
the verifier walks from the leaf, finding each parent by hash in the bag. Needs a depth
counter against cycles, accepts unused proofs in the bag, and the proof hash came from
the input (SG-2).

**B. Ordered chain, root first.** The caller presents `[root, ..., leaf]`. Link `i`
must name `id(link[i-1])` as `parent`; ids are computed here. A cycle would need a
hash fixpoint, the length bound is a plain slice length check, and there is nothing
unused to confuse.

**Choice: B.** Same checks as sluicegate, simpler to state and test, no search.

## Checks, in order (each failure refuses with a stable code)

1. Structure: `1 <= len <= 16` (`empty_chain`, `chain_too_long`, closes SG-7); link 0 is
   a root link (`root_not_anchored`); every later link is delegated (`unexpected_root`);
   no id twice (`cycle`).
2. Root: `KeyStore::verifying_key(kid, now)`: error `store_unavailable`, none
   `untrusted_root`, a key that fails the strict key checks `untrusted_root`; then
   `verify_with_kid` (`bad_signature`, `kid_mismatch`).
3. Each delegated link, against its parent: `parent == id(prev)` (`parent_mismatch`);
   issuer key strictly valid (`bad_issuer_key`) and its kid equals `kid`
   (`kid_mismatch`); `kid == prev.subject` (`issuer_not_parent_subject`, sluicegate
   AT-5.1); signature (`bad_signature`); `prev` holds `delegate` (`parent_lacks_delegate`,
   closes SG-6); `rights ⊆ prev.rights` (`rights_amplified`); every resource covered by
   a resource of `prev` (`resources_amplified`); `expires_at_ms <= prev.expires_at_ms`
   (`expiry_extended`); `epoch >= prev.epoch` (`epoch_lowered`).
4. Every link: `now < expires_at_ms` (`expired`, closes SG-5).
5. `RevocationSource::min_epoch(root kid)`: error `store_unavailable`; every link
   `epoch >= min` (`stale_epoch`).
6. `RevocationSource::any_revoked(all ids, now)`: error `store_unavailable`; true
   `revoked` (revoking any ancestor kills every descendant; closes SG-1).

Resource coverage: exact `r` covers only `r`; pattern `p*` covers every string, and
every pattern `q*`, that starts with `p`. This relation is transitive, so leaf coverage
implies root coverage.

## Builtin PDP

`BuiltinPdp::decide(chain, request, keys, revocations, now) -> AuthorityDecision`.
Request: `actor`, `resource` (exact, no `*`), required `rights` (non-empty), optional
`tool`, optional `purpose`, `data_labels`. In order: request well formed
(`bad_request`); `tool` given and `resource != "tool:" + tool` (`ambiguous_capability`,
oracle); chain valid (its code); `leaf.subject == actor` (`actor_mismatch`); leaf covers
`resource` (`resource_not_covered`); `rights ⊆ leaf.rights` (`rights_not_covered`);
purpose bindings as the oracle (`unknown_purpose_label` under default deny,
`purpose_mismatch`). Else `ALLOW` with reason `granted`. An empty chain is `DENY`
(AE-1 / U-DENY).

`canonicalize_external(value)` ports oracle `canonicalize_authority_output` for a
foreign PDP's JSON answer: a string or `{"verdict": <string>}` goes through
`verdict::parse`; anything else is `DENY`; the reason is bounded to 1024 characters and
marked fail-closed when the verdict was off lattice.

## Minting

`issue_root(root_key, grant)` and `delegate(parent, holder_key, grant, now)`.
`delegate` follows the oracle's clamping: rights are intersected, resources not covered
by the parent are dropped, expiry is clamped to the parent's, epoch raised to the
parent's. It refuses an expired parent (`expired`), a parent without `delegate`
(`parent_lacks_delegate`), a holder key that is not the parent's subject
(`issuer_not_parent_subject`), an empty result (`empty_after_attenuation`) and an
already expired result (`would_mint_expired`). The verifier never trusts the minter: it
re-checks every rule.

## Divergences from the oracles

| # | Oracle | Rust | Why |
|---|---|---|---|
| D1 | decision-os-min: HMAC macaroons with a process-local secret, string caveats `tools:`, `time <` | Ed25519 signed JCS capabilities, verified against a KeyStore | MODEL.md: authority is sluicegate's; HMAC needs the verifier to hold the minting secret |
| D2 | Oracle `holds` looks up a holder in an in-memory graph | the caller presents the chain | stateless core, U-CORE |
| D3 | Oracle has no rights, only tool names; a request is `tool:<name>` | a request names a resource and rights (`execute` for a tool call) | sluicegate rights model (U-ATTEN) |
| D4 | Oracle allows no expiry | expiry required | bounded authority; `2^53-1` is the "no expiry" value |
| D5 | Oracle `revoke` removes a flat grant only; delegated macaroons survive | revoking any link id denies every descendant | AE-6 / U-REVOKE; oracle leaves derived authority alive |
| D6 | sluicegate: proof bag, `proof_hash` from input, leaf-only expiry, no DELEGATE check, depth 17, `verify` (non-strict), no domain tag | ordered chain, computed ids, every link checked, DELEGATE required, 16 links, `verify_strict`, domain `capability` | SG-2, SG-5, SG-6, SG-7, SG-8, SG-9 |
| D7 | sluicegate: revocations and `min_epoch` come in the request | from `RevocationSource` | SG-1 |
| D8 | sluicegate: child epoch unconstrained against parent | child epoch >= parent epoch | narrowing includes epoch (task statement) |

## Failure modes (each must refuse) and the test that shows it

Forged root (unknown kid, wrong key, tampered body, signature from another domain),
forged or re-signed delegated link, issuer not the parent's subject, missing DELEGATE,
amplified rights, amplified resources (including pattern widening `tool:send*` to
`tool:*`), extended expiry, lowered epoch, expired root, middle or leaf, stale epoch on
any link, revoked root, middle or leaf, store errors (both trait methods, and KeyStore),
reordered, truncated-at-root and spliced chains, a cycle, 17 links, oversized input,
malformed encodings (unknown member, duplicate key, unsorted set, `*` in the middle,
negative or fractional or huge numbers, uppercase hex, lone surrogate, BOM, trailing
data, deep nesting), and a request asking for no rights.

## Test plan

- `tests/attenuation.rs`: oracle `test_attenuation.py` and `test_redteam_attenuation.py`
  cases, adapted (D1-D5).
- `tests/chain.rs`: sluicegate `dag.rs` and `engine.rs` cases, plus SG-1/2/5/6/7 closures.
- `tests/pdp.rs`: AE-1, AE-4, AE-5, AE-6 profile cases, oracle builtin PDP behavior
  (ambiguous capability, purposes, default deny), external output canonicalization.
- `tests/redteam.rs`: the attacks above, each a permanent test.
- `tests/props.rs` (proptest): minted chains always verify and never widen; a verified
  chain's leaf is within its root; random and mutated bytes never panic and never verify.
- `tests/vectors.rs`: the `conformance/vectors/authority/` files equal what the
  generator produces, and their `expected` equals what the crate returns.

## Invariant map

| Invariant | Where | Checked by |
|---|---|---|
| U-DENY | `BuiltinPdp::decide`: every path except the last is `DENY` | `pdp.rs` AE-1, every refusal test |
| U-LATTICE | PDP output is a `dos_core::verdict::Verdict`; external output via `verdict::parse` | `pdp.rs` external canonicalization |
| U-ATTEN | `verify_chain` step 3 | `chain.rs`, `attenuation.rs`, `props.rs` |
| U-EXPIRY | step 4, every link, `now >= exp` refuses | `chain.rs` expiry at, before, after; middle link |
| U-CHAIN | steps 1-3 | `chain.rs`, `redteam.rs` |
| U-EPOCH | step 5, every link | `chain.rs` stale middle link (AT-3.1) |
| U-REVOKE | step 6, ids computed here | `chain.rs`, `redteam.rs` re-signed body |
| U-SIG / U-CANON (for capabilities) | `dos_core::sign` strict, `dos_core::canon` strict parse | `redteam.rs` malformed encodings |
| U-CORE | `no_std`, lints | clippy `-D warnings`, no-panic props |

U-EXPIRY also says the clock "cannot move backwards". This crate takes `now` as a
parameter and cannot enforce that; it is the PEP's clock's job (open item in the status).
