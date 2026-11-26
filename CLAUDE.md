# Decision OS

Security infrastructure for AI agents: a Rust core that signs decisions bound to exact actions, enforces one-time tokens and keeps a tamper-evident audit log, plus a gateway in front of every MCP server and model API. Plan: `RUST_REWRITE.md`. Before any task, read `docs/agents/CHECKLIST.md`.

## How a task runs

The main session plans and merges. For each task, in its own branch and worktree:

1. Write `design/<task>.md`: goal, two approaches and the choice, failure modes (each must refuse), test plan.
2. `implementer`: tests first (see them fail), then code, then `status/<task>.md` with evidence.
3. `red-team`, a new agent each time: attacks the change, writes failing tests for what it finds.
4. `implementer` fixes every finding; each repro stays as a permanent test.
5. `verifier`, a new agent each time: re-runs everything, checks every claim, says APPROVE or CHANGES.
6. Merge only on APPROVE, green gates and no open S0 or S1.

Stop and ask Ali (write `ESCALATION.md`) on: the oracle and Rust disagreeing on a security case, an invariant that does not map, any change to a theorem or invariant, any S0 finding, or three fix rounds without APPROVE.

## Never

- Edit `oracle/`, `.claude/`, `docs/agents/`, this file, `RUST_REWRITE.md` or the gate scripts.
- Edit existing conformance vectors or findings; add new files.
- Skip or delete tests, or remove assertions, to get green.
- `unsafe`, `unwrap`, `expect`, `panic!` in `dos-core` or `dos-pep`; non-strict Ed25519 verify anywhere.
- Run installers outside a throwaway HOME (set HOME, USERPROFILE, APPDATA, LOCALAPPDATA, XDG_CONFIG_HOME to a temp folder).
- Say something works without pasting the command output.

Hooks enforce most of this; `scripts/check-protected.sh` in CI catches the rest. If a hook blocks you, stop and read why.

## Commands

`scripts/gate-fast.sh fast` (runs automatically when the implementer finishes) · `scripts/check-protected.sh`
