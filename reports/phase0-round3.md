# Verifier report: Phase 0, round 3 (PR #1, branch phase0/monorepo)

Verified head: `5331ea24fa85c49557f677d5207c7f2307b03c5f` (local HEAD, `origin/phase0/monorepo`
after `git fetch`, and `gh pr view 1 --json headRefOid` all agree; PR state OPEN, MERGEABLE).
Round-2 head: `963f237`. Date: 2026-11-27. Every result below was run by this verifier.

## 1. Diff since round 2

```
$ git log --oneline 963f237..5331ea2
5331ea2 Phase 0 verifier round 2: escalate E7 (agents bypass the tag ruleset), correct wording

$ git diff 963f237..5331ea2 --stat
 ESCALATION.md             |  20 ++++-
 design/phase0-monorepo.md |  15 ++--
 reports/phase0-round2.md  | 203 ++++++++++++++++++++++++++++++++++++++++++++++
 spec/KNOWN_GAPS.md        |   2 +-
 4 files changed, 232 insertions(+), 8 deletions(-)

$ git diff --name-only 963f237..5331ea2 -- oracle .github scripts .claude docs/agents | wc -l
0
$ git diff 963f237..5331ea2 --stat -- oracle .github scripts .claude docs/agents CLAUDE.md RUST_REWRITE.md findings .gitignore README.md
(empty)
```

Read the full diff. Only the four expected files changed. `reports/phase0-round2.md` is new
and matches the round-2 verdict. ESCALATION.md adds E7 and rewords E2. The design note changes
choice 3, the F3, F4 and F2 lines. KNOWN_GAPS changes only the OR-4 row. No oracle, workflow,
script, kit or findings file changed. Result: pass.

## 2. Round-2 items

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 (blocking) | F3: the agents bypass the tag ruleset, escalated with a decision; design F3 line accurate | **Resolved** | ESCALATION.md E7 (S1) states the admin bypass, the round-2 push/delete evidence, and that `guard.py` allows `git push origin oracle-v1`. It gives three options and names option 1, a non-admin agent account, as the root cause shared with E1. The design F3 line now says "The agents act as the admin, so this does not bind them yet: escalated as E7". I re-checked the facts live (see below) |
| 2 (blocking) | F2: the check fails open without a tag, escalated | **Resolved** | E7 paragraph 1 and option 3 (fail closed when `oracle/` exists and no `oracle-v*` tag is found, except on the Phase 0 import). Design F2 line: "The check also fails open if the tag is later deleted: escalated as E7". Confirmed in `scripts/check-protected.sh` lines 41-43 |
| 3 (blocking) | Design choice 3 gives the full reason for dropping deployment-testimony.yml, consistent with OR-3 | **Resolved** | Choice 3 now says it "records deployments, and runs an FDK integration check and a live `/v1/decide` probe; both failed at the source and are tracked as OR-3". OR-3 says the same: "an FDK to M4 integration check and a live HTTP `/v1/decide` ALLOW/DENY plus audit probe. Both failed at the source." |
| 4 (should-fix) | OR-4 discloses the `target/` files in branch history | **Resolved** | OR-4 now names 566db6a (137 files), the removal in d42d2ce, and that they stay in history. Verified: `git show --name-status 566db6a` shows `137 A` under `target/`, d42d2ce shows `137 D`, and `git ls-files \| grep -c target/` is `0` at HEAD |
| 5 (should-fix) | The required-checks wording matches the API | **Mostly; two wording errors remain (non-blocking)** | See below |

Live checks behind item 1:

```
$ gh api repos/Aliipou/decision-os/rulesets/28204244 --jq '{enforcement,bypass_actors,current_user_can_bypass,rules:[.rules[].type]}'
{"bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}],"current_user_can_bypass":"always","enforcement":"active","rules":["creation","update","deletion","non_fast_forward"]}
$ grep -n "oracle-v\|tag" .claude/hooks/guard.py      -> (no match)
$ gh api repos/Aliipou/decision-os/branches/main/protection --jq '{enforce_admins:.enforce_admins.enabled, reviews:..., co:...}'
{"co":true,"enforce_admins":false,"reviews":1}
$ gh api repos/Aliipou/decision-os/collaborators --jq '[.[].login]'
["Aliipou"]
$ git ls-remote --tags origin 'oracle*'               -> (empty)
```

I did not repeat round 2's tag push. `current_user_can_bypass: always` together with the absence of
any tag rule in guard.py is enough to show that E7's description still holds.

Item 5 in detail:

```
$ gh api repos/Aliipou/decision-os/branches/main/protection/required_status_checks --jq '{strict,contexts,n:(.contexts|length)}'
{"contexts":["protected-paths","full-gate","AE-1..AE-10 (decision-os-min oracle)","test (3.11)","test (3.12)",
"test (3.13)","contracts (3.11)","contracts (3.12)","contracts (3.13)","Python — lint + tests (3.11)",
"Python — lint + tests (3.12)","Rust — clippy + tests","Red team adversarial tests"],"n":13,"strict":true}
```

These are 10 oracle suites, the AE job, `protected-paths` and `full-gate`.

- The design note matches: "the main oracle test suites and the AE job besides `protected-paths`
  and `full-gate` (13 checks)".
- **E2 does not match.** It says "The 13 main suites and the AE job are now required checks",
  which reads as 14 checks with 13 suites. The API shows 13 contexts in total: 10 suites, AE, and
  the two gate jobs.
- **"About 18 other oracle jobs are not required" undercounts.** `comm` of `gh pr checks` against
  `gh pr checks --required` gives **23** checks that are not required: 22, plus the
  documented Supply chain exception. Besides the jobs the design names, the unnamed ones include
  API smoke, the adversarial simulation, CLI, the Docker image build, the performance regression
  gate, the product site smoke, the attack harness, the OPA/Cedar comparison, the WASM adversarial
  cases and `docker`. The jobs the design does name are all actually not required.

Both are doc wording at S3. They do not overstate what blocks a merge: the list of required checks
is right. Fix them in the next docs touch: E2 should say "10 main suites and the AE job (13
required checks with protected-paths and full-gate)", and "about 18" should become "22 other
oracle jobs, plus Supply chain".

E7 has no "Recommended:" line, unlike E1 and E5. It does say that option 1 is the root cause,
which is a usable decision prompt. This is a note, not a defect.

## 3. Policy question: do E1 (S0) and E7 (S1) block merging this PR?

CLAUDE.md step 6: "Merge only on APPROVE, green gates and no open S0 or S1". CHECKLIST: "S0 ...
self-approval. Blocks everything." "S1: fail-open ... Blocks merge."

My answer: **yes, they block a merge of this PR by an agent. The only way past them is an
explicit decision by Ali.** They are not tracked independently of this PR. The reasons:

1. **E1 is not only an account property. Merging this PR is an instance of it.** Ali is the only
   collaborator and code owner, `enforce_admins` is false, and one approving review is required.
   An agent-authored PR can therefore reach `main` only through the admin bypass, which is the
   S0 itself (self-approval, with required checks skippable). "No open S0" is a precondition of
   the merge step. It cannot be satisfied by an action that is the S0. An agent running
   `gh pr merge --admin` here would be the bypass E1 describes.
2. **E7 bears directly on what this PR delivers.** The goal is "three frozen oracles ... Tag
   `oracle-v0` on merge". E7 shows the freeze rests on a tag that the agents' identity can move or
   delete, and that `check-protected.sh` goes silent when the tag is gone. The defect sits in
   account setup and kit files, not in this PR's content, but it is an open S1 against this PR's
   deliverable. CLAUDE.md does not exempt S1s whose fix lies outside the diff.
3. **Neither can be fixed inside this PR.** The fixes need a second account, a change to
   `.claude/hooks/guard.py`, or a change to `scripts/check-protected.sh`. The first is an account
   decision and the other two are frozen files an agent may not edit. So asking for more changes
   on this branch would be wrong, and CHANGES would not make progress. The correct path is what
   has been done: escalate to Ali.
4. **What does clear it:** Ali, as the human owner, either (a) resolves E1/E7 first (for example,
   option 1, the agent account), or (b) records explicitly that he accepts E1 and E7 as open
   risks for the Phase 0 merge, then merges it himself with a merge commit and pushes `oracle-v0`
   in the same step. Under (b) the residual risk stays live until E7 is fixed: an agent can delete
   or move `oracle-v0`, and the freeze check then reports "not checked" and passes.

So my APPROVE below is a verdict on the PR's content. It is **not** a statement that the merge
conditions in CLAUDE.md are met. They are not met while E1 and E7 are open. Note also that this
is the third round. Round 2's CHANGES plus E1/E7 already meet the "stop and ask Ali" condition, and
the escalation exists.

## 4. CI on 5331ea2

Several jobs, required ones among them, were pending at first. I waited
(`gh pr checks 1 --watch`) until every job had finished.

```
$ gh pr checks 1 -R Aliipou/decision-os | awk -F'\t' '{print $2}' | sort | uniq -c
      1 fail
     35 pass
$ gh pr checks 1 -R Aliipou/decision-os | grep -v pass
Supply chain — cargo-deny + audit	fail	31s	.../actions/runs/45922614511/job/140256595307
$ gh pr checks 1 -R Aliipou/decision-os --required ; echo rc=$?
(all 13 required checks: pass)
rc=0
$ gh run view 45922614511 --job 140256595307 --log | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' | sort -u
RUSTSEC-2026-0566 .. RUSTSEC-2026-0573   (8 IDs, nothing else)
```

The only failure is the documented SG-16 exception (KNOWN_GAPS SG-16: RUSTSEC-2026-0566..0573;
not a required check; named in the design's Done-when). All required checks are green.

## 5. check-protected.sh (Git Bash, in `C:\Users\admin\dos-wt\p0-verify3`)

```
$ bash scripts/check-protected.sh; echo rc=$?
note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked
protected paths: unchanged
rc=0
```

This is the expected behaviour before the merge: no `oracle-v*` tag exists on origin, and this
PR creates `oracle/`. The fail-open behaviour after Phase 0 is E7 option 3.

`scripts/gate-fast.sh fast` was not in the scope of this round. CI `full-gate` passes on this head.

## Summary

All three blocking items from round 2 are resolved, both escalated in E7 with evidence and options.
Should-fix 4 is resolved. Should-fix 5 is resolved in the design note. E2's "13 main suites" and
the "about 18" figure (the real number is 22 plus Supply chain) are still wrong. They are S3
wording errors and do not block. Nothing outside the four expected files changed. The required
checks are green, and the only red job is the documented SG-16 exception. `check-protected.sh`
returns rc=0.

VERDICT: APPROVE

Reasons: every round-2 blocking item is fixed in text, matches the live repository state, and the
diff touches nothing else. The remaining wording errors are S3. **Merge condition not met:** E1
(S0) and E7 (S1) are open. Under CLAUDE.md they block an agent merge of this PR. Only Ali can
merge it, after he resolves them or explicitly accepts them for Phase 0 (section 3).
