# The unified model (draft for Ali's approval)

One model, three layers. Invariant names refer to `spec/INVARIANT_MAP.md`.

## 1. External contract (decision-os-min)

What callers and enforcement points see.

1. A caller submits an **Action**: actor, tool (capability `tool:<name>`), purpose,
   data labels, payload, and a caller-chosen `action_ref` (nonce).
2. The **kernel** decides. It returns a **Decision**: a verdict from the lattice, a
   reason, the action fingerprint, and for a permitting verdict a one-time `token_id`
   with an expiry. The kernel signs the decision (JCS bytes, domain `decision`, `v`,
   `kid`).
3. An **executor** (the PEP) runs the effect only if, in this order: the signature
   verifies under a trusted `kid`; the recomputed fingerprint matches; the verdict is
   permitting; the token is unexpired; obligations hold (LIMIT uses the transformed
   payload, CONTAIN checks the allowlist); the token is spent now, atomically, for the
   first time. Every call writes exactly one audit entry before any effect.

The decision is the only authority object. Anything else a caller holds (a token
view, a capability id) is derived and never trusted on its own.

## 2. Authority (sluicegate)

How the kernel knows a grant exists.

- A **capability** names a subject, a resource, a set of rights and an expiry and an
  epoch. A root capability is signed by a configured trust anchor; a delegated one by
  the parent's subject key, and it can only narrow: rights, resources and expiry are
  subsets of the parent's, and the parent must hold DELEGATE.
- The kernel walks the chain from the leaf to a trust anchor, checking every link
  (signature, issuer binding, expiry, epoch, attenuation, bounded length) and computes
  each capability's identity itself.
- Revocation and the minimum epoch come from a store the kernel trusts
  (`RevocationSource`), never from the request.
- The authority answer is a verdict: DENY unless a valid chain covers the action.

## 3. Legitimacy and constraints (veto-only)

Evaluators (legitimacy, safety, privacy, cost, policy rules) see a copy of the action
and return a verdict and a reason. Their verdicts are combined with the authority
verdict by meet before any token is minted. They can lower the verdict, attach a
reason, and nothing else: they cannot grant, rewrite the action, or choose what
executes. An evaluator that fails, times out or answers off-lattice is DENY.

## Trusted core

`dos-core` and `dos-pep` do no I/O and read no clock (time is a parameter). Stores
(spent tokens, keys, revocations, audit sink) are traits implemented outside the core.
The canonical form of everything hashed or signed is JCS (RFC 8785).

## Divergences from the oracles

Rust follows this model where the oracles fall short. Each divergence is listed in
`spec/KNOWN_GAPS.md` and has a conformance vector with `oracle_expected`.
