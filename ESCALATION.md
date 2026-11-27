# Escalation: decisions only Ali can make

Status 2026-11-27: Ali accepted E1 and E7 for Phase 0 and authorized the merge of PR #1
(merge commit 353008e) and the `oracle-v0` tag. Both stay open as risks until a
non-admin agent account exists.

Raised under CLAUDE.md "Stop and ask Ali". Nothing here is worked around; each item
waits for a decision.

## E1 (S0, Phase 0 red team F1): every merge is an admin bypass

`main` requires one approval and a Code Owner review. Ali is the only collaborator and
the only code owner, and the agents act through Ali's `gh` identity. A PR author
cannot approve their own PR, so every merge needs the admin bypass, and the bypass
also skips required checks. The guard hook does not block `gh pr merge --admin` or
deleting branch protection through `gh api`.

Options:
1. Add a second GitHub account (a bot or a person) as the PR author for agents, so
   Ali's review is a real second look and the admin bypass is never needed.
2. Keep one account, turn on `enforce_admins` so required checks bind admins too, and
   drop the review requirement to zero (checks become the only gate).
3. Extend `.claude/hooks/guard.py` to refuse `gh pr merge --admin`, `gh api -X DELETE
   .../protection` and `gh api ... rulesets` for agent roles.

Recommended: 1 + 3. Option 2 alone makes the oracle and kit protection depend only
on CI scripts an agent can edit.

## E2 (Phase 0 red team F4): new workflows are not code-owned

`.github/workflows/oracle-*.yml`, `ae-conformance.yml` and later `conformance.yml` are
the CI that proves the oracles and the AE profile. They are not in CODEOWNERS, the
guard's frozen list or `check-protected.sh`, so a change that turns them into no-ops
is caught by nothing but review. The 13 main suites and the AE job are now required checks on
`main` (about 18 other oracle jobs are not), which stops deleting a job, not hollowing one out.

Decision: add `/.github/workflows/` to CODEOWNERS (and to the guard's frozen list) or
accept review as the only control.

## E3 (Phase 0 red team F7): the `oracle-change/*` exemption is broken both ways

`check-protected.sh` reads the branch with `git rev-parse --abbrev-ref HEAD`. In CI the
checkout is detached (`HEAD`), so a legitimate oracle fix can never pass; locally,
naming a branch `oracle-change/x` silences the check. A fix reads `GITHUB_HEAD_REF` in
CI and refuses the exemption outside CI. It is a frozen kit file.

## E4 (verifier note): a new untracked file under `.claude/` passes `check-protected.sh`

It uses `git diff`, which does not see untracked files. Committed files are caught in
CI, so the gap is local only; the hooks are the local control. Fix if wanted: add
`git ls-files --others --exclude-standard -- <kit paths>` to the check.

## E5 (sign task): Rust decisions cannot verify against oracle decisions

By design (KNOWN_GAPS DM-4, SG-9): Rust signs `decision-os/v1/<domain>\0<JCS bytes>`
with a `kid`; the oracle signs untagged `json.dumps` bytes. RUST_REWRITE Phase 2 asks
for "signatures that verify across implementations". Choose:
1. Restate the requirement as "the same verdict and fingerprint, and each
   implementation verifies its own signatures; the oracle-v1 change (Phase 1c) adds
   the domain tag and `kid` to the oracle so cross-verification holds from then on", or
2. keep a compatibility verifier for untagged oracle decisions (rejected by the
   Rust spec as a downgrade path).

Recommended: 1.

## E6 (INVARIANT_MAP.md): three design questions

1. Consent (sluicegate Layer 4): keep it in the trusted core, or make it a policy
   input whose flag comes from policy, never from the request?
2. Sovereignty flags and the v1 confidence lattice: drop from the core (proposed), or
   keep as a deny-only policy input?
3. Per-session cumulative ceilings (AE probe B1): in scope for dos-policy or not?

`spec/MODEL.md` and `spec/INVARIANT_MAP.md` are Code Owner files and need your
approval in review.

## E7 (S1, Phase 0 red team F2 + F3, verifier round 2): the agents can move or delete the oracle tag

The ruleset "oracle tags are immutable" binds everyone except the Admin role, and the
agents push as Ali, who is the admin. The verifier pushed and deleted a throwaway
`oracle-v*` tag as the agents' identity: GitHub reported "Bypassed rule violations" and
allowed both. `guard.py` also allows `git push origin oracle-v1`. And
`scripts/check-protected.sh` fails open when no `oracle-v*` tag exists ("oracle/ not
checked"), so deleting the tag silences the freeze.

Options (any of them closes it; 1 is the root cause, shared with E1):
1. A non-admin GitHub account for agents (then the ruleset binds them).
2. `guard.py` refuses any push of `refs/tags/oracle-v*` for agent roles.
3. `check-protected.sh` fails closed after Phase 0 when the tag is missing (for
   example, when `oracle/` exists and no `oracle-v*` tag is found, exit 1 unless the
   branch is the Phase 0 import).
