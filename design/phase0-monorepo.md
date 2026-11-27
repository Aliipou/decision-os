# Phase 0: monorepo and freeze

## Goal

One repository with three frozen oracles imported with full history, each oracle's CI
running unchanged from its directory, and the AE conformance suite running against
the decision-os-min oracle. Tag `oracle-v0` on merge.

Done when: every oracle job is green in this repository's CI, except the known
environment-dependent `test_tm_a_unsandboxed_probe_still_shows_ambient_risk`, and
except the sluicegate "Supply chain" job, which fails on wasmtime advisories published
after sluicegate's last main run (KNOWN_GAPS SG-16). It tests dependencies, not
behavior; the oracle is never shipped; it stays visible and is not a required check.

Out of scope: any Rust code, any spec text beyond the gap register, any oracle edit.

## Sources

| Oracle | Source | Commits |
|---|---|---|
| `oracle/decision-os-min` | Aliipou/decision-os-min `main` at `5ee36cb` (PR #9 merged) | 42 |
| `oracle/sluicegate-py` | Aliipou/sluicegate `main` at `c731f31` | 424 |
| `oracle/contracts-spec` | Aliipou/contracts-spec `feat/composition-contract-and-adr` at `d7af602` | 27 |

contracts-spec is not in the plan's source table. It is added because it is the only
place AE-1..AE-10 are defined and the only conformance suite for them (KNOWN_GAPS
DOC-2). Its `main` branch lacks `conformance/`, so the feature branch is imported.

Tags were renamed with the repository name as prefix (`sluicegate-v1.0.0`, ...)
so oracle tags never collide with this repository's releases.

## Choices

1. **Import: `git filter-repo --to-subdirectory-filter` then merge with
   `--allow-unrelated-histories`** (the plan's method) over a subtree squash, so
   `git log -- oracle/...` and blame keep every original commit.
2. **Docs stay inside the oracles, `docs/INDEX.md` links to them** (deviation from
   "move docs"). Moving them would edit the oracle trees, break their internal links
   and any test that reads them, and contradict "suites run unchanged". The index
   gives the consolidated view; nothing moves, nothing breaks.
3. **Workflows: each oracle workflow copied to `.github/workflows/oracle-*.yml`** by
   a script that changes only triggers, default working directory and the paths
   actions read (cache keys, workspaces, manifests, path filters). Dropped:
   decision-os-min `release.yml` (the oracle is never shipped), sluicegate
   `pr-checklist-gate.yml` (PR-body format for that repository), contracts-spec
   `deployment-testimony.yml` (records deployments, and runs an FDK integration check
   and a live `/v1/decide` probe; both failed at the source and are tracked as OR-3).
4. **No root Cargo workspace yet.** The first `dos-*` crate adds it, with
   `exclude = ["oracle"]` so `oracle/sluicegate-py/authgate-kernel` keeps building as
   its own workspace.

## Failure modes (each must be caught)

| Failure | Caught by |
|---|---|
| A commit or file lost in the import | commit counts above; `git diff <source> <oracle tree>` empty (verifier) |
| An oracle file changed during import | same tree diff, then `check-protected.sh` after the tag |
| A workflow silently runs from the wrong directory | jobs fail on missing files; the verifier checks each job ran tests (non-zero test counts in logs) |
| A dropped workflow was the only home of a real test | listed above with reason |
| The AE job passes because nothing was measured | the job requires exactly 10 pass, 0 fail, 0 N/A |

## Test plan and local evidence (WSL Ubuntu, ext4 copies of the oracle trees)

- decision-os-min: 412 passed, 8 skipped, 2 failed on `/mnt/c`; both failures
  (`test_key_file_is_private`, sqlite double spend across processes) pass on ext4
  (9 passed). They are properties of the Windows-mounted filesystem.
- sluicegate: 1371 passed, 1 skipped, coverage 99.36 %, ruff clean.
- contracts-spec: 28 passed, ruff and mypy clean, both authority rules clean.
- AE-1..AE-10 against decision-os-min: 10 pass, 0 fail, 0 N/A; probes 0 broken.

## Red-team round 1 (findings/phase0.md) and what changed

- F3 (oracle tags could be moved): repository ruleset "oracle tags are immutable" now
  blocks creating, updating and deleting `refs/tags/oracle-v*` for everyone but the
  repository admin. The agents act as the admin, so this does not bind them yet:
  escalated as E7.
- F4 (new workflows not required): `main` now requires the main oracle test suites
  and the AE job besides `protected-paths` and `full-gate` (13 checks). About 18 other
  oracle jobs (Lean, TLC, sandbox, seccomp, TCB, gateway, wheel e2e) run but are not
  required. Protecting the workflow
  files themselves needs a CODEOWNERS change: escalated.
- F5: the SG-16 wording claimed the job fails on sluicegate main; corrected.
- F6 (a squash merge drops the imported history): squash and rebase merges are now
  disabled for the repository. Phase 0 merges with a merge commit.
- F8 to F11: recorded as OR-1 to OR-4 in `spec/KNOWN_GAPS.md`.
- F1 (single owner means every merge is an admin bypass), F7 (`oracle-change/*`
  exemption) and the CODEOWNERS part of F4 change the agent kit or who reviews:
  escalated in `ESCALATION.md`.
- F2 (the freeze is not in force until the tag exists): the tag is pushed in the same
  step as the merge; until then `oracle/` is protected only by review. The check also
  fails open if the tag is later deleted: escalated as E7.
