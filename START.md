# Start (for Ali)

1. Merge PR #9 in `decision-os-min` after the Windows test.
2. Create `Aliipou/decision-os`, copy this kit into it, commit to `main`, push.
3. Protect `main` on GitHub: pull requests only, required checks, "Require review from Code Owners".
4. Install git, Python 3.9+ (for the hooks) and Rust (rustup).
5. Open Claude Code in the repo and trust the folder (needed for the agents' hooks).
6. Say: `Start Phase 0 of RUST_REWRITE.md following CLAUDE.md. Stop at the end of the phase with a report.`

Check the hooks once: ask Claude Code to edit `CLAUDE.md`. It should be blocked.
