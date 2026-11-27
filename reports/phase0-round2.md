# Verifier report: Phase 0, round 2 (PR #1, branch phase0/monorepo)

Verified head: `963f237664c793e5537ac5fba81af0824483629b` (local HEAD, `origin/phase0/monorepo`
after a fresh fetch, and `gh pr view 1 --json headRefOid` all agree). Round-1 head: `7ba6eb1`.
Date: 2026-11-27. Every result below was re-run by this verifier.

## 1. Repository settings (live, via gh api)

```
$ gh api repos/Aliipou/decision-os --jq '{allow_squash_merge,allow_rebase_merge,allow_merge_commit}'
{"allow_merge_commit":true,"allow_rebase_merge":false,"allow_squash_merge":false}

$ gh api repos/Aliipou/decision-os/rulesets
[{"id":28204244,"name":"oracle tags are immutable","target":"tag","enforcement":"active",...}]

$ gh api repos/Aliipou/decision-os/rulesets/28204244
"conditions":{"ref_name":{"exclude":[],"include":["refs/tags/oracle-v*"]}},
"rules":[{"type":"creation"},{"type":"update"},{"type":"deletion"},{"type":"non_fast_forward"}],
"bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}],
"current_user_can_bypass":"always"

$ gh api repos/Aliipou/decision-os/branches/main/protection/required_status_checks
"strict":true,"contexts":["protected-paths","full-gate","AE-1..AE-10 (decision-os-min oracle)",
"test (3.11)","test (3.12)","test (3.13)","contracts (3.11)","contracts (3.12)","contracts (3.13)",
"Python — lint + tests (3.11)","Python — lint + tests (3.12)","Rust — clippy + tests",
"Red team adversarial tests"]

$ gh api repos/Aliipou/decision-os/branches/main/protection --jq '{enforce_admins:..., reviews:...}'
{"enforce_admins":false,"reviews":{"require_code_owner_reviews":true,"required_approving_review_count":1,...}}
```

`actor_id 5` with `RepositoryRole` is the Admin role. `current_user_can_bypass: always` is for the
`gh` identity the agents use.

## 2. Tag ruleset test (task step 5)

```
$ git push origin 1da99b3:refs/tags/oracle-vtest-verifier
remote: Bypassed rule violations for refs/tags/oracle-vtest-verifier:
remote: - Cannot create ref due to creations being restricted.
 * [new tag]         1da99b3 -> oracle-vtest-verifier
push_rc=0
$ git ls-remote --tags origin 'oracle*'
1da99b369546eee1956e56452d384d4406d397e9	refs/tags/oracle-vtest-verifier

$ git push origin :refs/tags/oracle-vtest-verifier          (deleted at once)
remote: Bypassed rule violations for refs/tags/oracle-vtest-verifier:
remote: - Cannot delete this tag
 - [deleted]         oracle-vtest-verifier
$ git ls-remote --tags origin 'oracle*'                      -> (empty)
$ gh api repos/Aliipou/decision-os/git/matching-refs/tags/oracle   -> []
$ git tag -l 'oracle*'                                       -> (empty)
```

**GitHub did not block it.** The ruleset is active and its rules fire, but the push went through
on admin bypass. Creating and deleting an `oracle-v*` tag both work for the identity the agents
use. The ruleset only binds non-admins. No other tag or branch was pushed; the throwaway tag is
gone from the remote.

The local guard does not stop it either:

```
$ printf '{"tool_input":{"command":"git push origin oracle-v1"},"cwd":"."}' | python -I .claude/hooks/guard.py bash --role implementer; echo rc=$?
rc=0
$ printf '{"tool_input":{"command":"git push origin HEAD:refs/tags/oracle-v1"},...}' | ... --role implementer
rc=0
```

(guard.py only refuses force pushes, pushes naming main/master, and any push by verifier/red-team.)

## 3. Each round-1 item and red-team finding

| Item | Sev | Status | Evidence |
|---|---|---|---|
| R1 must-fix 1: Done-when vs red supply-chain job | - | Fixed | design lines 9-13 now name the Supply chain exception and SG-16; PR body has a "Known red check" section |
| R1 must-fix 2: SG-16 wording | - | Fixed | SG-16 now: fails here and on every sluicegate PR since 2026-11-19; passed on main's last run (c731f31, 2026-11-15) |
| R1 must-fix 3: vacuous sandbox `--exact` steps | - | Fixed (gap) | OR-2 in KNOWN_GAPS, with a Rust requirement (non-zero test count per gate) |
| R1 must-fix 4: reason for dropping deployment-testimony.yml | - | **Partly**. Recorded as OR-3 with a requirement, but design choice 3 (line 46) still says only "records deployments across other repositories", and the failure-mode row "A dropped workflow was the only home of a real test: listed above with reason" still points at that sentence. The design note does not mention OR-3 |
| R1 should-fix 5: README conformance/ crates/ | - | Fixed | README now says "arrives with the first Rust tasks" for both |
| R1 should-fix 6: required checks | - | Fixed (partial scope) | 13 required contexts (above). Not required: Gateway x2, wheel e2e x3, docker, TM-A, TLC, Lean x2, TCB, sandbox, seccomp, CLI, API smoke, attack harness. E2 and the design note say "the oracle test jobs"; that is the main suites, not all oracle jobs |
| F1 merges need admin bypass; agents are the admin | S0 | Escalated | ESCALATION.md E1, options 1-3, recommendation 1+3. Still true: `enforce_admins:false`, review required, single collaborator. Merge of this PR is itself an admin bypass |
| F2 freeze not in force until a tag exists | S1 | Procedure only | Design: "the tag is pushed in the same step as the merge". PR body: "Merge with a merge commit, then tag oracle-v0". Today no `oracle-v*` exists on origin and `check-protected.sh` prints "oracle/ not checked". Before merge this is expected (the PR creates oracle/). The other half of F2 (the script fails open when the tag is missing, instead of refusing once oracle/ exists) is neither fixed nor in ESCALATION.md. With section 2 it matters: an agent can delete the tag and the check goes silent |
| F3 tags can be re-baselined | S1 | **Not fixed for the threat, not escalated as such.** Ruleset exists, but section 2 shows the agents' identity creates and deletes `oracle-v*` tags through it, and the guard allows the push. The design says "for everyone but the repository admin", which is accurate but leaves out that the agents are the admin. E1 talks about merges, branch protection and `gh api ... rulesets`; it does not name tag pushes, and its option 3 does not add a guard rule for `git push ... oracle-v*` |
| F4 workflows unprotected / not required | S1 | Fixed (required part) + escalated (E2, CODEOWNERS) | required checks above; E2 |
| F5 Done-when not met | S2 | Fixed | see must-fix 1 |
| F6 squash/rebase enabled | S2 | Fixed | `allow_squash_merge:false, allow_rebase_merge:false` |
| F7 oracle-change/* exemption | S2 | Escalated | E3 |
| F8 not hermetic | S2 | Gap | OR-1 |
| F9 vacuous inherited gates | S3 | Gap | OR-2 |
| F10 deployment-testimony unique checks | S3 | Gap | OR-3 (design text still stale, see must-fix 4) |
| F11 history hygiene | S3 | Gap, accepted | OR-4. But see section 5: OR-4 says the `.gitignore` "keeps build outputs out of new history", and this branch's own new history (566db6a) has 137 `target/` files |

## 4. Core claims, re-checked

### 4a. Tree hashes (fresh clones `C:\Users\admin\dos-src\vf2-{decision-os-min,sluicegate,contracts-spec}`)

```
decision-os-min 5ee36cbcc48a89019f02f4c5f2f63f0910d94c66 src=4162db98c757244d672171193cc722cec66d070b oracle=4162db98c757244d672171193cc722cec66d070b EQUAL
sluicegate      c731f31e23a64363d2128b989d0422fdcf8a1797 src=a184b82d35e81ebfc4639bdc42122b159f20db1c oracle=a184b82d35e81ebfc4639bdc42122b159f20db1c EQUAL
contracts-spec  d7af60237a945847158318000d48e4ed88dcea87 src=a23ed78616400e5a135d7b432ac7b45a0738197c oracle=a23ed78616400e5a135d7b432ac7b45a0738197c EQUAL
d7af602 is on origin/feat/composition-contract-and-adr
```

`git diff --name-only 7ba6eb1 963f237` touches nothing under `oracle/`.

### 4b. No tracked build output

```
$ git ls-files | grep -E '(^|/)target/' | grep -v '^oracle/'     -> (empty)
$ git ls-files | grep -E '(^|/)target/' | wc -l                  -> 0
566db6a: 137 files added under target/ (status A), plus ESCALATION.md, design, findings, KNOWN_GAPS
d42d2ce: 137 deletions under target/ (status D), plus A .gitignore (/target/, **/*.rs.bk)
```

Note on the task's commit range: `c6e3503` is not an ancestor of `963f237`
(`git merge-base --is-ancestor` fails); it is a merge on `rust/workspace`, `task/install`,
`task/store`. The removal on this branch is `d42d2ce`. At HEAD no `target/` file remains.

### 4c. CI for head 963f237

All runs listed by `gh run list --branch phase0/monorepo` for `963f237`. After waiting for the
pending jobs:

```
$ gh pr checks 1 | count
     35 pass
      1 fail     Supply chain — cargo-deny + audit   (run 45922041819)
$ gh pr checks 1 --required    -> all 13 required checks: pass
Supply chain log: RUSTSEC-2026-0566 .. 0573 (the eight SG-16 IDs), nothing else.
```

This matches the documented exception.

## 5. Gates

Git Bash, in `C:\Users\admin\dos-wt\p0-verify2`:

```
$ bash scripts/check-protected.sh; echo rc=$?
note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked
protected paths: unchanged
rc=0
```

## 6. Diff since round 1 (`git diff --stat 7ba6eb1 963f237`)

```
 .gitignore                |   2 +
 ESCALATION.md             |  71 ++++++++
 README.md                 |   4 +-
 design/phase0-monorepo.md |  23 ++-
 findings/phase0.md        | 197 +++++++++++++++++++++
 reports/phase0-round1.md  | 423 ++++++++++++++++++++++++++++++++++++++++++++++
 spec/KNOWN_GAPS.md        |  11 +-
```

Read in full. All changes are docs plus `.gitignore`. No workflow, kit, script or oracle file
changed. Nothing unplanned in the tree. Two things in the history and text:

- 566db6a/d42d2ce leave 137 Rust build files (dos_core incremental output, from Rust work that is
  out of scope for Phase 0) in branch history. With merge-commit-only, they land in `main` history
  for good. OR-4's sentence about new history is therefore not true for this PR. Ali can either
  accept it (S3, say so in OR-4) or have the branch rebuilt without 566db6a's `target/` before merge.
- `ESCALATION.md` E5 and E6 (sign task, INVARIANT_MAP) refer to Phase 1/2 work, and E6 names
  `spec/MODEL.md` and `spec/INVARIANT_MAP.md`, which do not exist on this branch. Harmless, but
  that file is shared across branches.

## Summary

Verified true: the three oracle trees are byte-identical to the named source commits; no oracle
file changed since round 1; no build output is tracked at HEAD; CI is green except the
documented SG-16 supply-chain job, and all 13 required checks pass; `check-protected.sh` passes;
squash and rebase merges are off; round-1 must-fix 1, 2, 3 and should-fix 5, 6 are done; F1, F4
(CODEOWNERS), F7 are escalated; F8 to F11 are recorded.

Must fix:
1. **F3 (S1) is not fixed for the agents and not escalated as such.** Proven in section 2: the
   agents' `gh`/git identity creates and deletes `oracle-v*` tags through the ruleset (admin
   bypass), and `guard.py` allows `git push origin oracle-v1`. So an agent can still re-baseline
   or remove the freeze. Add this to ESCALATION.md (in E1 or a new item), with the evidence, and
   with a decision for Ali: a non-admin agent account (E1 option 1, which makes the ruleset bind),
   and/or a guard rule refusing any push of `refs/tags/oracle-v*` by an agent role. Correct the
   design note's F3 line to say the ruleset does not bind the agents today.
2. **F2 (S1), fail-open half.** `check-protected.sh` skips `oracle/` when no tag exists. Once
   `oracle/` is on main, a missing tag should be a failure, not a note. With item 1, a deleted tag
   silences the freeze. It is a kit file, so escalate it (one line in E3 or E1 is enough).
3. Round-1 must-fix 4, finish it: fix design choice 3 (line 46) so the reason for dropping
   `deployment-testimony.yml` names the FDK to M4 check and the live `/v1/decide` probe, and
   points at OR-3.

Should fix (not blocking):
4. OR-4: say this branch's own history has 137 `target/` files from 566db6a (or rebuild the branch
   without them before merge).
5. E2 and the design say "the oracle test jobs" are required. 13 are; about 18 oracle jobs
   (Lean, TLC, sandbox, seccomp, TCB, gateway, wheel e2e, docker, TM-A, ...) are not. Say which.

VERDICT: CHANGES

Reasons: the S1 tag re-baseline (F3) is still open in practice. I pushed and deleted an
`oracle-v*` tag as the agents' identity, and GitHub only logged a bypass. That residual, and the
fail-open half of F2, are neither fixed nor escalated with a decision for Ali. Round-1 must-fix 4
is half done. All three are doc or escalation fixes. With them made and nothing else changed, this
would be APPROVE.
