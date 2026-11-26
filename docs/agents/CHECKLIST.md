# Checklist for every task

## Before code
- [ ] Restate the task, what "done" means, and what is out of scope.
- [ ] Read the spec section and the oracle code for this behavior. List the files.
- [ ] Every assumption is VERIFIED (how) or checked now. Library APIs come from the version in `Cargo.lock`, never from memory.
- [ ] Name each invariant touched and the test that fails if it breaks.

## While coding
- [ ] Tests first. Run them and see them fail.
- [ ] Small steps, one concern. Under about 400 changed lines, tests excluded.
- [ ] Every error, timeout, unknown format and parse failure in a security path refuses, and the refusal is audited.
- [ ] Same inputs through the oracle and the new code. Any difference: stop and report.

## Before saying done
- [ ] Test the five inputs most likely to break it.
- [ ] Three ways this could cause an incident in six months, each checked.
- [ ] Windows, macOS and Linux: paths, process launch, line endings, locking.
- [ ] `status/<task>.md`: what changed, evidence for each claim (command and output), what was NOT done, open risks.

## Mistakes already made here, check for them
- A path around the gate (a `tools/call` without an id was forwarded).
- Fail-open on the unexpected (a gzip or non-JSON response passed ungated).
- New protocol shapes not recognized (custom tool calls, `shell_call`).
- Replies lost on shutdown (half-closed stdin).
- First-start races (sqlite locked when several proxies started together).
- Loading code from the working directory (`python -m`).
- Library gaps when porting (Rust `regex` has no lookahead).
- Secrets reaching logs, errors or the audit.

## Severity (red team)
S0: bypass, forged or replayed authority, effect without audit, self-approval. Blocks everything.
S1: fail-open, secret leak, lost or corrupted user data. Blocks merge.
S2: crash, hang, broken install. Blocks release.
S3: hardening.
