# Red team findings: Phase 0 (PR #1, branch phase0/monorepo at 7ba6eb1)

Worktree: `C:\Users\admin\dos-wt\p0-redteam` (HEAD 7ba6eb1 = origin/phase0/monorepo).
Fresh source clones: `C:\Users\admin\dos-src\rt-{decision-os-min,sluicegate,contracts-spec}`.
Scratch copies for attacks (never pushed): a local clone of the worktree under the session scratchpad (`pt/`).
`$SC` below means that scratchpad directory. No commit, push, tag or merge was made.

First-pass hypotheses were written before reading `design/phase0-monorepo.md` or the PR body (H1..H15 below).

## Summary

| ID | Sev | Title |
|---|---|---|
| F1 | S0 | Every merge to main needs an admin bypass, and agents hold that admin identity: CODEOWNERS and required checks do not protect `oracle/` |
| F2 | S1 | The oracle freeze is not in force in CI: no `oracle-v*` tag on origin, so `check-protected.sh` skips `oracle/` |
| F3 | S1 | Freeze can be re-baselined by pushing any newer `oracle-v*` tag; nothing stops the tag push |
| F4 | S1 | The new oracle workflows and `ae-conformance.yml` are unprotected and not required checks: they can be neutered or left red and the PR still merges |
| F5 | S2 | Phase 0 "done when" is not met: `oracle sluicegate CI` is red on the PR head (Supply chain / cargo-deny) |
| F6 | S2 | "Full history" depends on the merge button: squash and rebase merges are enabled |
| F7 | S2 | The `oracle-change/*` exemption can never apply in CI (detached HEAD), and locally it is granted by branch name alone |
| F8 | S2 | The frozen oracle is not hermetic: unpinned Python deps, `@stable` toolchains, `*-latest` runners |
| F9 | S3 | Inherited vacuous gates: sandbox `--exact` steps run 0 tests; `continue-on-error` on "all lib tests"; weak TLC grep fallback |
| F10 | S3 | Dropped `deployment-testimony.yml` was the only home of two checks (FDK -> M4 integration, live HTTP `/v1/decide` ALLOW/DENY probe) |
| F11 | S3 | History hygiene: 96 Rust `target/` build artifacts (6.3 MB), a 7 MB PDF, a `.coverage` db and local `C:\Users\admin` paths came in with history |

---

## F1 (S0) Merges require admin bypass, agents run as the admin; CODEOWNERS gives no protection

Class: self-approval / path around the gate (process).

Reproduction:
```
gh api repos/Aliipou/decision-os/branches/main/protection
gh api repos/Aliipou/decision-os/collaborators -q '.[].login'
gh api user -q .login
gh pr view 1 --repo Aliipou/decision-os --json author,reviewDecision,mergeStateStatus
```
Result:
- protection: `required_approving_review_count: 1`, `require_code_owner_reviews: true`, required checks only `protected-paths` and `full-gate`, `enforce_admins: {"enabled": false}`.
- collaborators: `Aliipou` only. CODEOWNERS owner for `/oracle/`: `@Aliipou`.
- the `gh` identity used by agents in this session: `Aliipou` (token scopes `repo`, `workflow`; repo `permissions.admin = true`).
- PR #1: author `Aliipou`, `reviewDecision: REVIEW_REQUIRED`, `mergeStateStatus: BLOCKED`.

GitHub does not let a PR author approve their own PR, and there is no other collaborator, so the required code-owner review can never be given. Every merge (this one included) can only happen through the admin bypass (`enforce_admins` off), and that bypass also skips the required `protected-paths` check. The account doing the bypass is the same account the agents use. The guard hook does not stop it:
```
printf '{"tool_input":{"command":"gh pr merge 1 --admin --merge"},"cwd":"."}' | python -I .claude/hooks/guard.py bash --role implementer; echo rc=$?
-> rc=0   (allowed; same for "gh api -X DELETE repos/Aliipou/decision-os/branches/main/protection")
```
So the "CODEOWNERS makes that PR need Ali's review" line in `check-protected.sh` is not true in practice: an agent can change `oracle/` (or the kit) and merge it with no human in the loop. Repo configuration, not a file in the diff, but claim 4 ("still protects oracle/") depends on it. Per CLAUDE.md an S0 needs escalation to Ali.

## F2 (S1) No `oracle-v*` tag on origin: CI does not check `oracle/` at all

Class: fail-open (freeze disabled).

Reproduction:
```
git ls-remote --tags origin 'oracle*'                       -> (nothing)
gh api repos/Aliipou/decision-os/git/matching-refs/tags/oracle -> []
git tag -l 'oracle*'   (local only) -> oracle-v0 -> 7ba6eb1 (lightweight, not pushed)
gh run view 45898184760 --repo Aliipou/decision-os --log | grep note:
  -> "note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked"
     "protected paths: unchanged"
```
Tamper test in a scratch clone with no tag (what CI sees):
```
cd $SC/pt; git checkout -b agent/x
echo "# tamper" >> oracle/decision-os-min/decision_os_min/kernel.py; git commit -qam tamper
git tag -d oracle-v0; bash scripts/check-protected.sh; echo exit=$?
-> note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked
-> protected paths: unchanged
-> exit=0
```
The freeze only starts when someone pushes the tag by hand "after merge"; nothing enforces that, and until then every PR may edit `oracle/` with a green `protected-paths`. The script also fails open on a missing tag instead of refusing once `oracle/` exists. (With the local tag present the same tamper is caught: `exit=1`.)

## F3 (S1) Any newer `oracle-v*` tag silently re-baselines the freeze

Class: forged authority (baseline chosen by the attacker).

`check-protected.sh` compares against `git tag --list 'oracle-v*' --sort=-v:refname | head -1`, i.e. whichever tag sorts highest, with no check of who made it or that it is on main.
```
cd $SC/pt   (branch agent/x with the tampered kernel.py, oracle-v0 at 7ba6eb1)
git tag oracle-v1 HEAD;   bash scripts/check-protected.sh; echo exit=$?  -> protected paths: unchanged / exit=0
git tag oracle-vzzz HEAD; git tag --list 'oracle-v*' --sort=-v:refname | head -1 -> oracle-vzzz
                          bash scripts/check-protected.sh; echo exit=$?  -> protected paths: unchanged / exit=0
```
In CI `actions/checkout` with `fetch-depth: 0` fetches every tag on origin, so one `git push origin oracle-v1` (commit on any branch) makes CI accept that branch's `oracle/`. There are no tag rulesets (`gh api repos/Aliipou/decision-os/rulesets` -> `[]`), and the guard allows the push:
```
printf '{"tool_input":{"command":"git push origin oracle-v1"},"cwd":"."}' | python -I .claude/hooks/guard.py bash --role implementer; echo rc=$?  -> rc=0
```

## F4 (S1) Oracle and AE workflows are unprotected and not required

Class: path around the gate (conformance and differential can be switched off without touching `oracle/`).

`.github/workflows/oracle-*.yml` and `ae-conformance.yml` are not in `check-protected.sh`'s kit list, not in CODEOWNERS, not in the guard's FROZEN list, and none of their jobs are required status checks (only `protected-paths`, `full-gate`).
```
cd $SC/pt; git checkout -B agent/ci phase0; git tag -f oracle-v0 7ba6eb1
# edit: dosmin pytest -> "pytest -q --co" (collect only); sluicegate "pytest --cov..." -> "true || pytest ...";
#       ae-conformance: summary check -> "sys.exit(0)"
git commit -qam "neuter oracle CI"; bash scripts/check-protected.sh; echo exit=$?
-> protected paths: unchanged
-> exit=0
grep -n workflows .github/CODEOWNERS -> only /.github/workflows/protected.yml
```
Live evidence that they do not block: on the PR head `oracle sluicegate CI` concluded `failure` (run 45898184797) while the PR's only blocker is the missing review. A Rust PR that breaks the AE job or the oracle suites can merge.

## F5 (S2) Phase 0 done-when not met: `oracle sluicegate CI` is red

Class: claim not met / broken gate.

```
gh run view 45898184797 --repo Aliipou/decision-os --json jobs
-> failure "Supply chain — cargo-deny + audit" (step cargo-deny); all other 9 jobs success
```
RUST_REWRITE.md and the design note say every oracle job must be green. `spec/KNOWN_GAPS.md` SG-16 records it and says it also fails "on sluicegate main", but the source run on the imported commit c731f31 (run 43660186653, 2026-11-15) had that job `success`; the failure comes from advisories published since (see F8), not the port. An always-red required-looking workflow trains everyone to ignore it, which hides real regressions in the same workflow's Python suite.

## F6 (S2) Squash and rebase merges are enabled

Class: lost data (history).

```
gh api repos/Aliipou/decision-os -q '"squash="+(.allow_squash_merge|tostring)+" merge="+(.allow_merge_commit|tostring)+" rebase="+(.allow_rebase_merge|tostring)'
-> squash=true merge=true rebase=true
```
A squash merge of PR #1 drops all 493 imported commits; a rebase merge drops the three import merges and re-commits every replayed commit with a new committer. Claim 1 ("full history") holds on the branch but only survives a merge commit, and nothing forces one.

## F7 (S2) `oracle-change/*` exemption: dead in CI, name-only locally

Class: wrong refusal of the legitimate flow; local bypass by branch name.
```
cd $SC/pt; git checkout -b oracle-change/x   (tampered oracle)
bash scripts/check-protected.sh -> "note: oracle-change/x may change oracle/ ..." / exit=0
git checkout --detach; git rev-parse --abbrev-ref HEAD -> HEAD
bash scripts/check-protected.sh -> "oracle/ differs from oracle-v0 (frozen)..." / exit=1
```
On `pull_request` events actions/checkout leaves a detached merge ref, so `branch` is always `HEAD` in CI: a real oracle bug fix (the only allowed oracle change besides oracle-v1) can never pass `protected-paths` and needs the admin bypass of F1. Locally, any agent can silence the gate by naming its branch `oracle-change/...`.

## F8 (S2) The frozen oracle is not hermetic

Class: oracle behavior drift / broken install over time.

- Python deps are lower bounds only, no lock or constraints file: `cryptography>=42` (decision-os-min), `fastapi>=0.111.0`, `uvicorn[standard]>=0.29.0`, `pydantic>=2.7.0` (sluicegate), `jsonschema>=4.0`, `pytest>=8.0`, `ruff>=0.6` (contracts-spec). `ls oracle/*/ | grep -iE 'lock|requirements|constraints'` -> none for the Python packages.
- `dtolnay/rust-toolchain@stable`, `ubuntu-latest` (the AE job ran on `Ubuntu 26.04.1`), `elan-init.sh` from `master`, cargo-deny advisory DB live.
- Already observed: cargo-deny green on 2026-11-15, red now (F5). contracts-spec CI failed on its own source at d7af602 (run 32652855412) and passes here, so the environment, not the frozen code, decides the outcome.
"Frozen" code with floating dependencies is not a stable differential oracle: a dependency release can change oracle results without any oracle diff.

## F9 (S3) Inherited vacuous or masked gates (port is faithful; the checks are weak)

Class: gate that passes on nothing.
```
grep -a "test result" $SC/logs/45898184858.log
-> "Verify the key enforcement property":           0 passed; 317 filtered out
-> "Verify capability denial (zero WASM execution)": 0 passed; 317 filtered out
-> "Confirm both enforcement classes are exercised": 0 passed; 317 filtered out
grep -rn "fn write_tool_blocked_with_only_read_right" oracle/sluicegate-py/authgate-kernel/src -> src/sandbox.rs:454 inside `mod inner { mod tests }`
```
The real test path is `sandbox::inner::tests::...` but the steps use `--exact sandbox::tests::...`, so they match nothing and pass. The tests do run inside the broader `-- sandbox` step (11 passed), so coverage holds today, but deleting those tests would leave these "key property" steps green. Also: `oracle-sluicegate-tcb-tests.yml` "Run all lib tests" has `continue-on-error: true` (306 passed today, would never fail the job); `oracle-sluicegate-formal.yml` accepts any "distinct states" line if the 4227 count changes; the "Rust — clippy + tests" job runs no `cargo test`. Same as source (workflow diff below), so not a port regression.

## F10 (S3) Dropped `deployment-testimony.yml` held unique checks

Class: lost test.

`git -C $S/rt-contracts-spec show d7af602:.github/workflows/deployment-testimony.yml` runs `scripts/rigorous_testimony.py --skip-slow --live-service`. Besides the AE suite and pytest files that other jobs also run, it has two checks found nowhere else in this repo's CI:
- `gate_fdk_m4_integration`: freedom-decision-kernel `evaluate_legitimacy` output validated against the M4 verdict-artifact profile (cross-repo; FDK is not imported).
- `gate_live_service`: start the decision-os-min uvicorn service, POST `/v1/decide` ALLOW and DENY cases, and check the audit file is written (the dosmin `docker` job probes only `/healthz` and `/readyz`).
The design note says it "records deployments across other repositories". It was already failing at the source (run 32652855404), so nothing green was lost, but the "no unique tests" claim is not accurate. `release.yml` and `pr-checklist-gate.yml` hold no tests (held).

## F11 (S3) Unexpected but non-secret content in history

Class: supply chain / hygiene.
```
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' > $SC/objs.txt
grep ^blob $SC/objs.txt | awk '$4 ~ /\/target\// {n++; s+=$3} END{print n, s}'   -> 96 6282397
grep ^blob $SC/objs.txt | sort -k3 -n -r | head -1  -> 7149828 oracle/sluicegate-py/book/azadi_din_iran_Jannatkhah.pdf
```
Rust build output (`freedom-kernel/target/debug/deps/*.rlib`, `*.rmeta`, x86_64-pc-windows-gnu) is in history (not in the tip tree), plus a 7 MB PDF, a 3.8 MB text file, `oracle/sluicegate-py/.coverage` and a wasm blob; these embed the local path `C:\Users\admin`. No credential (see H12). All came from the source repo unchanged.

---

## Negative results (hypotheses that held)

| # | Hypothesis | Test | Result |
|---|---|---|---|
| H10 | Imported trees differ from source (bytes, CRLF, missing files) | `git rev-parse HEAD:oracle/<x>` vs `git -C rt-<x> rev-parse <sha>^{tree}`; `git ls-files --eol oracle \| awk '$1~/crlf\|mixed/'` | All three equal: dosmin 4162db98, sg a184b82d, cs a23ed786. 0 CRLF/mixed blobs, root `.gitattributes` causes no renormalization (`git status` clean) |
| H11a | History rewritten: commits lost, wrong author/committer/date, message changes | per-commit paired walk in topo order: subtree hash, author, committer, raw dates, full message hash vs source | 42/42, 424/424, 27/27 commits; 0 tree mismatches, 0 metadata diffs, 0 message diffs |
| H11b | Tags lost, collided or retargeted | each imported tag vs source tag: type, target subtree, author date, annotated tag body | 6/6 match (`decision-os-min-v0.1.0`, `sluicegate-v1.0.0..v1.3.0` annotated with identical bodies, `contracts-spec-v0.2.0`); no `oracle-v*` collision |
| H6 | Steps, matrix entries or jobs lost in the port | diff of each source workflow vs port with `oracle/<x>/` stripped | Only `name`, branch filters, `workflow_dispatch`, `defaults.run.working-directory` and the workflow's own path filter differ; every step and matrix entry identical |
| H15 | A ported job runs from the wrong dir and runs zero tests | PR head logs vs source CI logs at the imported commits | dosmin 413 passed/5 skipped x3, gateway 114 x2, TM-A 4; sluicegate 1371/1 x2, API 10, red team 42, TCB 211 + 306, seccomp 3 + 1, sandbox 11; contracts 28 x3; TLC 4227 distinct states; Lean jobs green. Same counts as source runs 45894939263, 43660186653, 43660186640 |
| H9 | AE job passes vacuously | mock drivers in `$SC/drv/rtdrivers.py`, `python -m conformance --driver rtdrivers:<D> --probes --json ...` | DenyAll: INCONCLUSIVE, exit 1. AllowAll: 1 pass 9 fail, exit 1. NoCaps (claims nothing): CLI exit 0 but summary `{pass:1, fail:0, not_applicable:9}`, which the workflow's exact `{10,0,0}` check rejects. Real run: 10 pass, 0 N/A, probes 0 broken (B1 UNSUPPORTED is not counted, minor) |
| H4 | A repo-root `conftest.py` can alter oracle test collection | root conftest that empties `items`, then `python -m pytest --co tests/test_core.py` in `oracle/decision-os-min` | Not loaded (each oracle has its own pyproject + conftest; rootdir stops the walk): 15 tests collected |
| H12 | Secret in imported history | gitleaks 8.21.2 (release binary, sha256 verified) `git --log-opts=--all --redact`, plus `$SC/blobscan.py` regex scan of all 1807 blobs on all refs | 8 gitleaks hits, all test fixtures: `ghp_abcdef...` and `AKIAABCD...` sequential fakes in installer/guardrail tests, a truncated OPENSSH PEM in `test_policy_guardrails.py`, `_key: Ed25519PrivateKey` type hints, prose. Regex scan: same fixtures plus test tokens like `token="alice..."` and a k8s secret *name* annotation. `.env.example` has placeholders only. No real credential |
| H14 | Rename/symlink/case-variant of `oracle/` evades the diff | reasoning plus F2 tamper test | Any change under `oracle/` (edit, delete, type change to symlink) appears in `git diff <tag> -- oracle/`; a new `Oracle/` path does not change what the workflows run. Held once a tag exists (but see F2/F3) |
| H8 | Path-filtered workflows did not run on the PR | `gh run list --branch phase0/monorepo` | Formal, Sandbox and Seccomp ran and passed on both PR heads (they will rarely run again once `oracle/` is frozen, same semantics as source) |
| H13b | CODEOWNERS paths wrong | read `.github/CODEOWNERS` | `/oracle/`, kit files and `protected.yml` listed correctly; the problem is F1, not the paths |

Not tried: fuzzing (the change adds no parser), Windows checkout differences beyond the eol check.
