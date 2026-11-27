# Verifier report: Phase 0 (PR #1, branch phase0/monorepo)

Verified head: `7ba6eb10e9f9fd4b1363eaf0bbfd6cf2a14b425b`. That is `origin/phase0/monorepo`, and this
worktree's HEAD is the same commit. Base: `main` at `1da99b3`. Date: 2026-11-26/27.
Everything below was re-run or re-read by the verifier. Command output is pasted, trimmed only
where marked `...`.

## 1. Gates

Git Bash, in this worktree:

```
--- check-protected.sh
note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked
protected paths: unchanged
exit=0
--- gate-fast.sh fast
skipped  cargo checks (no Cargo workspace yet)
ok       protected paths unchanged
exit=0
```

WSL, run in this worktree as instructed. The worktree was created by Windows git, so its `.git` file
holds a Windows path, which WSL git cannot read. Both scripts fail closed:

```
fatal: not a git repository: /mnt/c/Users/admin/dos-wt/p0-verify/C:/Users/admin/decision-os/.git/worktrees/p0-verify
gate-fast rc=1
check-protected rc=1
```

WSL, on a fresh ext4 clone of the PR branch (`/root/vf-p0`, cargo present at `/root/.cargo/bin/cargo`):

```
7ba6eb10e9f9fd4b1363eaf0bbfd6cf2a14b425b
skipped  cargo checks (no Cargo workspace yet)
ok       protected paths unchanged
gate-fast rc=0
note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked
protected paths: unchanged
check-protected rc=0
```

Result: green. Note: the WSL path only works on a WSL-native clone, not on a worktree created by
Windows git. This is an environment issue, not part of this PR.

## 2. Claims

### 2a. Sources, tree identity, commit counts

Fresh clones: `C:\Users\admin\dos-src\vf-decision-os-min`, `vf-sluicegate`, `vf-contracts-spec`.

```
== vf-decision-os-min: 5ee36cb -> 5ee36cbcc48a89019f02f4c5f2f63f0910d94c66
  ref origin/main head: 5ee36cbcc48a89019f02f4c5f2f63f0910d94c66
  source commits reachable from 5ee36cb: 42
  source tree: 4162db98c757244d672171193cc722cec66d070b
  oracle tree (PR head): 4162db98c757244d672171193cc722cec66d070b
== vf-sluicegate: c731f31 -> c731f31e23a64363d2128b989d0422fdcf8a1797
  ref origin/main head: c731f31e23a64363d2128b989d0422fdcf8a1797
  source commits reachable from c731f31: 424
  source tree: a184b82d35e81ebfc4639bdc42122b159f20db1c
  oracle tree (PR head): a184b82d35e81ebfc4639bdc42122b159f20db1c
== vf-contracts-spec: d7af602 -> d7af60237a945847158318000d48e4ed88dcea87
  ref origin/feat/composition-contract-and-adr head: d7af60237a945847158318000d48e4ed88dcea87
  source commits reachable from d7af602: 27
  source tree: a23ed78616400e5a135d7b432ac7b45a0738197c
  oracle tree (PR head): a23ed78616400e5a135d7b432ac7b45a0738197c
```

`gh pr view 9 -R Aliipou/decision-os-min`: `"state":"MERGED","mergeCommit":{"oid":"5ee36cb..."}`. So
`5ee36cb` is PR #9 merged, as claimed.

Imported histories, counted from the second parent of each import merge:

```
31496ae (decision-os-min import): imported tip 11a260a count=42
3e05aac (sluicegate import):      imported tip cf978b4 count=424
01a6bd2 (contracts-spec import):  imported tip 19f1e57 count=27
PR head total: 499  (= 1 kit + 42 + 424 + 27 + 3 merges + 2 Phase 0 commits)
```

Per-commit metadata (author, email, raw date, subject) for each whole imported history, compared
with its source:

```
vf-decision-os-min: src=42 dst=42 diff_lines=0
vf-sluicegate: src=424 dst=424 diff_lines=0
vf-contracts-spec: src=27 dst=27 diff_lines=0
```

Result: the claims hold. The three trees are byte-identical to the named source commits, and the
counts are 42, 424 and 27.

### 2b. Tag renames

```
v0.1.0 -> decision-os-min-v0.1.0 tree_eq=yes meta_eq=yes ancestor_of_head=yes srctype=commit dsttype=commit
v1.0.0 -> sluicegate-v1.0.0 tree_eq=yes meta_eq=yes ancestor_of_head=yes srctype=tag dsttype=tag
v1.1.0 -> sluicegate-v1.1.0 tree_eq=yes meta_eq=yes ancestor_of_head=yes srctype=tag dsttype=tag
v1.2.0 -> sluicegate-v1.2.0 tree_eq=yes meta_eq=yes ancestor_of_head=yes srctype=tag dsttype=tag
v1.3.0 -> sluicegate-v1.3.0 tree_eq=yes meta_eq=yes ancestor_of_head=yes srctype=tag dsttype=tag
v0.2.0 -> contracts-spec-v0.2.0 tree_eq=yes meta_eq=yes ancestor_of_head=yes srctype=commit dsttype=commit
```

The source repos have exactly these six tags. The renamed tags are already on the remote. No
`oracle-v*` tag exists, locally or on the remote (checked again after step 4).

### 2c. Local test numbers (WSL Ubuntu, ext4 clone, throwaway HOME, Python 3.14.4)

```
### contracts-spec
All checks passed!            ruff rc=0
Success: no issues found in 5 source files     mypy rc=0
28 passed in 1.15s
rule B OK — no non-kernel Decision emission.   rc=0
rule A OK — no forbidden cross-layer imports.  rc=0
### AE suite vs decision-os-min oracle
  10 pass · 0 fail · 0 not applicable
  0 broken
ae cli rc=0
{'pass': 10, 'fail': 0, 'not_applicable': 0}
ae summary rc=0
### decision-os-min two fs-sensitive tests on ext4
tests/test_identity_and_concurrency.py::test_key_file_is_private PASSED
tests/test_identity_and_concurrency.py::test_double_spend_across_processes_exactly_one_wins[file] PASSED
tests/test_identity_and_concurrency.py::test_double_spend_across_processes_exactly_one_wins[sqlite] PASSED
3 passed, 6 deselected in 4.61s
### decision-os-min full suite on ext4 (CI ignore list)
413 passed, 5 skipped, 1 warning in 41.61s
```

The same two tests on the Windows-mounted filesystem (`C:\ 9p ... /mnt/c`):

```
FAILED tests/test_identity_and_concurrency.py::test_key_file_is_private - Ass...
FAILED tests/test_identity_and_concurrency.py::test_double_spend_across_processes_exactly_one_wins[sqlite]
2 failed, 1 passed, 6 deselected in 127.09s
```

Result: the claims hold. Both failures depend on the filesystem and pass on ext4. Two limits on
this check. First, the full decision-os-min suite was not re-run on `/mnt/c`. The claimed
412 passed + 2 failed + 8 skipped = 422 is consistent with 413 + 5 on ext4 (CI ignore list), plus the
4 TM-A tests that CI runs separately. Second, sluicegate was not re-run locally. Its CI shows the
claimed numbers (2d).

### 2d. CI on the PR (`gh pr checks 1 -R Aliipou/decision-os`)

36 checks: 35 pass, 1 fail (`Supply chain — cargo-deny + audit`, see 6). Required checks on `main`
(`gh api .../branches/main/protection`): `"contexts":["protected-paths","full-gate"]`, so the
failing job is not required.

Test counts from the Actions logs of head `7ba6eb1`, compared with each source repo's own CI:

| Workflow / job | This PR | Source CI |
|---|---|---|
| dosmin `test (3.11/3.12/3.13)` | `413 passed, 5 skipped` each; ruff clean; mypy `35 source files` | decision-os-min main `5ee36cb` run 45894939263: `413 passed, 5 skipped` each |
| dosmin `Gateway on windows/macos` | `114 passed` each | `114 passed` each |
| dosmin `TM-A OS isolation` | `4 passed` | `4 passed` |
| dosmin `Installed wheel e2e` (ubuntu, macos, windows) | `all end-to-end checks passed` / `all Windows end-to-end checks passed` | same |
| dosmin `docker` | `{"status":"ok"}{"status":"ready",...,"key_persisted":true,...}` | n/a |
| dosmin `Real OPA / Cedar / MCP` | comparison JSON, `"scenario_count": 6` | n/a |
| sluicegate `Python — lint + tests (3.11/3.12)` | `1371 passed, 1 skipped`, `Total coverage: 99.36%` | sluicegate main `c731f31` run 43660186653: `1371 passed, 1 skipped`, 99.36% |
| sluicegate `API smoke` / `Red team` | `10 passed` / `42 passed` | `10 passed` / `42 passed` |
| sluicegate `Adversarial simulation` | `231 scenarios ... 230 properties hold, 1 known gap` | same |
| sluicegate `Rust TCB tests` | `211 passed ... 95 filtered out`; `306 passed` | run 43660186640: `211 passed`; `306 passed` |
| sluicegate `Python attack harness` | all four scripts `... passed` / `completed` | same |
| sluicegate `TLC` | `Model checking completed. No error has been found.` `4227 distinct states` | run 43660186609: same, 4227 |
| sluicegate `Lean 4 — Authgate` / `FreedomKernel` | `Build completed successfully (604 jobs).` / `Build completed successfully.` | same |
| sluicegate `Seccomp` | `3 passed`; `1 passed` | no recent source run |
| sluicegate `WASM sandbox` (build, adversarial) | `11 passed ... 306 filtered out` in each job; the `--exact` steps: `0 passed; ... 317 filtered out` | PR #18 run 44562482576: `11 passed`; `--exact` steps `0 passed; ... 326 filtered out` |
| contracts-spec `contracts (3.11/3.12/3.13)` | `28 passed` each; ruff and mypy clean | none: source run 32652855412 at `d7af602` never started ("recent account payments have failed") |
| AE `AE-1..AE-10 (decision-os-min oracle)` | `10 pass · 0 fail · 0 not applicable`, `0 broken`, `{'pass': 10, 'fail': 0, 'not_applicable': 0}` | not in source CI |

Every job ran real tests, with non-zero counts matching the source. One exception was found:

- **Vacuous sandbox steps (pre-existing, not recorded).** In `oracle-sluicegate-sandbox.yml`, "Verify
  the key enforcement property", "Verify capability denial" and "Confirm both enforcement classes"
  run `cargo test ... sandbox::tests::<name> --exact`. The tests actually live at
  `sandbox::inner::tests::<name>`, so each of these steps matches 0 tests and passes. The source
  repo does the same thing (PR #18 log above). The named tests do run in the broader `-- sandbox`
  step:
  `test sandbox::inner::tests::write_tool_blocked_with_only_read_right ... ok`, plus 10 others. So no
  coverage is lost. But these are green checks that measure nothing, which is the exact failure
  this design asks the verifier to catch. `spec/KNOWN_GAPS.md` does not list it.

## 3. Diff against main, excluding oracle/

`git diff --stat main...7ba6eb1 -- . ':!oracle'`: 12 files, +1214, 0 deletions. Changed: 8 workflows,
`README.md`, `design/phase0-monorepo.md`, `docs/INDEX.md`, `spec/KNOWN_GAPS.md`. No kit file
changed.

Each ported workflow, diffed against its source workflow at the named commit. The only changes are
the workflow `name`, triggers (`branches: [main]`, `workflow_dispatch`, path filters rewritten
under `oracle/sluicegate-py/`), `defaults.run.working-directory`, and the paths that actions read
(`workspaces:`, `manifest-path:`, cache `path`/`hashFiles`). Two examples:

```
######## decision-os-min/ci.yml vs oracle-dosmin-ci.yml
1c1  < name: ci                      > name: oracle dosmin ci
5c5  <     branches: [main, "feat/**", "product/**"]   >     branches: [main]
6a7,10 >   workflow_dispatch: / defaults: run: working-directory: oracle/decision-os-min
######## sluicegate/tcb-tests.yml vs oracle-sluicegate-tcb-tests.yml
30,31c33,34 < authgate-kernel/target / hashFiles('authgate-kernel/Cargo.lock')
            > oracle/sluicegate-py/authgate-kernel/target / hashFiles('oracle/sluicegate-py/authgate-kernel/Cargo.lock')
```

(The ci, formal, sandbox and seccomp diffs follow the same pattern. No step body changed.)

`ae-conformance.yml` is new and matches the design: it requires exactly 10 pass, 0 fail, 0 N/A.

Dropped workflows, read at source:
- decision-os-min `release.yml`: PyPI publish on `v*` tags. Dropping it is correct.
- sluicegate `pr-checklist-gate.yml`: PR-body checkbox gate. Dropping it is correct.
- contracts-spec `deployment-testimony.yml`: **the stated reason is incomplete.** The design says it
  "records deployments across other repositories". It also checks out `freedom-decision-kernel` and
  `decision-os-min@main`, then runs `scripts/rigorous_testimony.py`. That script has gates that run
  nowhere else: an FDK to M4 integration check, an FDK pytest set, and a live uvicorn probe of
  decision-os-min (`/readyz`, `/v1/decide` ALLOW, `/v1/decide` DENY, audit chain written). FDK is not
  imported, so dropping the FDK gates is fine. The live-service probe is only partly covered, by
  dosmin `docker` (`/healthz`, `/readyz`) and `tests/test_service.py`. Its other gates (M4 test, AE
  suite, dosmin core tests) do run elsewhere. The design's failure-mode row "a dropped workflow was
  the only home of a real test: listed above with reason" should say this.

`docs/INDEX.md`: all 45 relative links resolve.

`README.md`: the layout table lists `conformance/` and `crates/`, and says the AE suite "runs against
every implementation". Neither directory exists on this branch. It reads as current state; it
should say "added in Phase 1/2".

`spec/KNOWN_GAPS.md`: spot checks match the oracle code. SG-7 (`dag.rs:44-47`: `if depth > MAX_CHAIN_DEPTH`
before `depth += 1`). SG-8 (non-strict `.verify(` at `dag.rs:62,71`, `engine.rs:134`, `consent.rs:154`).
SG-10 (`crypto.rs:125` `let _ = kp.verifying_key.verify_strict(...)`). DM-2 (`kernel.py:69`
`json.dumps(..., default=str)`). SG-16 (`wasmtime` `49.0.5` in the lock; `deny.toml` ignores only the
two pyo3 advisories). SG-16's text is not accurate about sluicegate main (see 6).

Design "Done when": "every oracle job is green in this repository's CI, except ...
`test_tm_a_unsandboxed_probe_still_shows_ambient_risk`". **As written, this is not met.** The
supply-chain job is red. The design note does not list that exception, and the PR body does not
mention a red check. The fix is to amend the Done-when line to name SG-16. (For the record:
`test_tm_a_unsandboxed_...` lives in `tests/test_os_isolation.py`, which the `test` job ignores, and
the `-m tm_a` job reports `4 passed`.)

## 4. Mutation check of the safety net

Scratch worktree `C:\Users\admin\dos-wt\p0-mut`, branch `mut/p0-scratch` at `7ba6eb1`, local tag
`oracle-v0` at `7ba6eb1`:

```
### baseline (no tag)                           -> note: no oracle-v* tag yet ...  rc=0
### (a0) tag oracle-v0 set, oracle unchanged     -> protected paths: unchanged      rc=0
### (a1) tag set + uncommitted edit under oracle/ -> oracle/ differs from oracle-v0 (frozen). ... rc=1
### (a2) tag set + committed edit under oracle/   -> oracle/ differs from oracle-v0 (frozen). ... rc=1
### (a3) tag set + untracked new file under oracle/ -> oracle/ differs from oracle-v0 (frozen). ... rc=1
### (a4) tag set + staged deletion under oracle/  -> oracle/ differs from oracle-v0 (frozen). ... rc=1
### (b) uncommitted edit CLAUDE.md                -> agent-kit files changed ... M CLAUDE.md  rc=1
### (b) uncommitted edit docs/agents/CHECKLIST.md -> ... M docs/agents/CHECKLIST.md  rc=1
### (b) uncommitted edit .claude/agents/verifier.md -> ... M .claude/agents/verifier.md  rc=1
### (b) uncommitted edit scripts/gate-fast.sh     -> ... M scripts/gate-fast.sh  rc=1
### (b) uncommitted edit .github/workflows/protected.yml -> ... rc=1
### (b) uncommitted edit RUST_REWRITE.md          -> ... M RUST_REWRITE.md  rc=1
### (b) committed edit to check-protected.sh itself -> ... M scripts/check-protected.sh  rc=1
### (b) untracked new file in .claude/            -> protected paths: unchanged  rc=0   <-- not caught
### branch oracle-change/x, oracle edit           -> note: oracle-change/x may change oracle/ ...  rc=0 (by design)
```

(c) No `conformance/vectors` or `findings` exist on this branch. In a throwaway clone
(`C:\Users\admin\dos-wt\p0-mut-c`, local `main` = `7ba6eb1` plus a commit adding
`conformance/vectors/core/a.json` and `findings/p0.md`, `origin/main` ref removed so the script uses
`main`):

```
### (c0) base has vectors, branch unchanged  -> protected paths: unchanged  rc=0
### (c1) uncommitted edit of existing vector -> append-only files were modified ... M conformance/vectors/core/a.json  rc=1
### (c2) committed edit of existing vector   -> ... M conformance/vectors/core/a.json  rc=1
### (c3) committed delete of a finding       -> ... D findings/p0.md  rc=1
### (c4) rename of a vector                  -> ... R100 conformance/vectors/core/a.json conformance/vectors/core/b.json  rc=1
### (c5) new vector added (allowed)          -> protected paths: unchanged  rc=0
### (c6) edit of a vector added on this same branch -> protected paths: unchanged  rc=0
```

Cleanup:

```
Deleted branch mut/p0-scratch (was 7ba6eb1).
Deleted tag 'oracle-v0' (was 7ba6eb1)
local oracle tags: []
remote oracle tags: []
```

The worktree and clone were removed. No tag was pushed.

Result: (a), (b) and (c) all fail as required. Observations on the agent kit (on `main`, not this
PR), for Ali:
- An untracked new file under `.claude/` (or any kit dir) passes. `git diff` does not see untracked
  files. The file is caught once it is committed (status `A`).
- A vector edited on the same branch that added it passes (c6). This matches the rule ("existing"
  vectors are the ones on main), but nothing stops a branch from rewriting its own new vectors
  before review.
- The `oracle-change/*` exemption reads `git rev-parse --abbrev-ref HEAD`. Under `pull_request`,
  `actions/checkout` checks out a detached merge ref (`HEAD is now at 1c17437 Merge 7ba6eb1... into
  1da99b3`), so the branch name is `HEAD` and the exemption never applies in CI. This fails closed:
  an oracle-change PR would always fail `protected-paths`. It needs handling before the Phase 1
  `oracle-v1` change.
- `protected.yml` uses `fetch-depth: 0`, so the tag is present in CI and the oracle check runs there.

## 5. Error paths

AE job: the step runs under `shell: /usr/bin/bash -e {0}` (CI log). In
`oracle/contracts-spec/conformance/cli.py`, `main` returns `1 if failures else 0`. `failures` is the
FAIL count from `suite.run` (a check that raises becomes FAIL, and a failed liveness check returns 1)
plus the number of BROKEN probes. N/A does not count, so the summary snippet has to catch N/A. The
snippet was extracted verbatim from the workflow and run on crafted JSON:

```
good.json -> rc=0      ({"pass":10,"fail":0,"not_applicable":0})
fail.json -> rc=1      na.json -> rc=1      empty.json -> rc=1
extra.json -> rc=1     nosummary.json -> rc=1   blank.json -> rc=1   missing.json -> rc=1
```

End to end: the verbatim CI step body, under `bash -e`, with sabotaged drivers that subclass the
real driver (kept in the verifier's scratchpad, not in the repo):

```
== driver conformance.drivers.decision_os_min_driver:DecisionOSMinDriver -> step rc=0
  10 pass · 0 fail · 0 not applicable / 0 broken / {'pass': 10, 'fail': 0, 'not_applicable': 0}
== driver sabotage:NADriver -> step rc=1          (capabilities minus "audit")
  N/A   AE-10  Audit fidelity                     no audit
  9 pass · 0 fail · 1 not applicable / 0 broken / {'pass': 9, 'fail': 0, 'not_applicable': 1}
== driver sabotage:FailDriver -> step rc=1        (replay executes twice)
  FAIL  AE-8   Single use                         an authorization was spent twice
  9 pass · 1 fail · 0 not applicable              (CLI exits 1; bash -e stops before the summary check)
== driver sabotage:BrokenDriver -> step rc=1      (ignores a lowercase "deny" constraint)
  10 pass · 0 fail · 0 not applicable
  BROKEN       A2   [A] Off-lattice verdict from a foreign dialect   an unrecognised verdict string was not treated as a refusal
  1 broken
```

FAIL, BROKEN and N/A each fail the job. One minor point: the JSON summary comes from a second run of
the checks (`cli.py` re-runs `CHECKS` to build `rows`). The strict equality still requires a full
10/10 on that run, so this cannot fail open.

Wrong working directory, using the dosmin `test` job (`defaults.run.working-directory:
oracle/decision-os-min`; steps `pip install -e ".[service,dev]"`, `ruff check .`, `mypy
decision_os_min`, `pytest -q ...`). If the directory does not exist, the runner fails the step at
start, because it cannot spawn bash there. If the directory exists but is wrong:

```
### wrong dir = repo root: Install step     -> install rc=1  ERROR: file:///root/vf-p0 does not appear to be a Python project
### pytest from a dir with no tests         -> pytest rc=5   no tests ran in 0.00s
### wrong dir = oracle/sluicegate-py: mypy decision_os_min -> mypy rc=2
```

Each case fails loudly. The one silent-pass pattern in the ported CI is the stale `--exact` filter
from 2d. It comes from the oracle, not from a wrong directory.

## 6. Known accepted failure: supply chain (SG-16)

PR run 45898184797, `cargo-deny` step: `error[vulnerability]` for RUSTSEC-2026-0566, 0567, 0568,
0569, 0570, 0571, 0572 and 0573 (wasmtime, wasmtime-wasi, wasmtime-wasi-http), then
`advisories FAILED, bans ok, licenses ok, sources ok`.

Sluicegate (`gh run list -R Aliipou/sluicegate`):

```
43660186653 2026-11-15 c731f31 main CI push success      -> "Supply chain — cargo-deny + audit: success" ("advisories ok", 1509 advisories loaded)
44561396938 2026-11-19 38100d2 r-notes (PR #17) CI failure    -> Supply chain: failure; all other jobs success
44664694970 2026-11-20 4c45f03 t10-tamarin (PR #21) CI failure -> Supply chain: failure; all other jobs success
```

Both PR runs fail on the same eight IDs (`RUSTSEC-2026-0566` .. `0573`, each listed). Both branches
have merge-base `c731f31`, and `git diff --stat c731f31 origin/<branch> -- authgate-kernel/Cargo.lock
authgate-kernel/Cargo.toml authgate-kernel/deny.toml .github/workflows/ci.yml` is empty for each.

Result: the failure comes from advisories published after 2026-11-15 against the unchanged `c731f31`
dependency set. The import did not introduce it, and the job is not required. **But SG-16 says the
job fails "here and on sluicegate main".** The last run on sluicegate main passed. The failure is
shown on PRs #17 and #21, which are based on main and leave the dependencies unchanged. SG-16
should say that.

## Summary of findings

Verified true: the three trees are byte-identical to their sources; the commit counts (42, 424, 27)
and per-commit metadata match; the tag renames are correct; the local numbers match (contracts-spec
28, AE 10/0/0 with 0 broken, both filesystem-sensitive failures pass on ext4 and fail on `/mnt/c`);
CI is green except SG-16, and every job's counts match its source; the workflow ports change only
triggers, working directory and paths; the safety net fails as required for (a), (b) and (c); and
the AE job fails on FAIL, BROKEN and N/A. I found no security defect introduced by this PR.

Must fix (claims that are wrong or incomplete; all are documentation fixes):
1. `design/phase0-monorepo.md` "Done when" is not met as written. The supply-chain oracle job is red.
   Name the SG-16 exception there, and mention the red non-required check in the PR body.
2. `spec/KNOWN_GAPS.md` SG-16: "fails here and on sluicegate main" is not what the evidence shows.
   The last main run (`c731f31`, 2026-11-15) passed. The failure appears on PRs #17 and #21, which
   are based on main and leave the dependencies unchanged.
3. Add a gap entry for the vacuous sandbox CI steps. The `--exact sandbox::tests::*` filters match 0
   tests (`0 passed; ... 317 filtered out`), because the tests are under `sandbox::inner::tests::`.
   This is pre-existing in the source.
4. `design/phase0-monorepo.md` choice 3: correct the reason for dropping `deployment-testimony.yml`.
   It holds the FDK integration gates and a live `/v1/decide` ALLOW/DENY probe of decision-os-min.
   Say which parts are covered elsewhere and which are dropped (FDK, because it is not imported).

Should fix (not blocking on their own):
5. `README.md` presents `conformance/` and `crates/` as existing.
6. Only `protected-paths` and `full-gate` are required checks. AE conformance and the oracle jobs
   (except supply chain) are not, so a later PR could merge with the AE suite red. That contradicts
   ground rule 2. Ali should add them in the branch protection settings.

For Ali, about the kit on main (outside this PR's scope): untracked kit files pass
`check-protected.sh`; the `oracle-change/*` exemption never applies under `pull_request` checkouts
(it fails closed); WSL cannot run the gates in worktrees created by Windows git.

Verifier housekeeping: an early WSL run of mine ran with the wrong working directory and created
ignored cache directories (`.hypothesis`, `.mypy_cache`, `.ruff_cache`, `__pycache__`) in
`C:\Users\admin\decision-os`. They were removed: only items created after my script was written, 29
in total. Pre-existing ignored files were left untouched, and the tracked tree there is clean.

VERDICT: CHANGES. The import itself is correct, with identical trees, histories and tags; CI test
counts match the sources; the safety net and the AE job fail closed. But the design note's Done-when
is not met as written (a red oracle job it does not mention), SG-16 misstates where the failure is
seen, a vacuous CI check found during verification is not in the gap register, and the reason for
dropping `deployment-testimony.yml` leaves out the gates it held. All four are doc fixes. With them
made and nothing else changed, this would be APPROVE.
