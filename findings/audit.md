# Findings: audit (dos-audit)

Method: self red team by the implementer (no independent red-team agent yet; the protocol in `CLAUDE.md` still requires one). Tests: `crates/dos-audit/tests/redteam.rs`, `audit.rs`, vectors `conformance/vectors/audit/`.

## Findings

| # | Sev | Class | Finding | Repro | Result |
|---|---|---|---|---|---|
| A-1 | S2 | stale state | `FileSink` cached the head keyed on log length. A log replaced by another of the same length between two appends from one sink would be chained from the old head. | `redteam.rs::sink_follows_the_disk_not_a_cache` | Fixed: the sink re-reads the last line on every append. Test stays. |

## Held (attacks tried)

| Class | Tried | Held |
|---|---|---|
| Edit | every single-bit flip (bits 0x01, 0x20) at every byte of a 3-entry signed log, checked with an anchor | yes |
| Truncation | every byte prefix; tail truncation with and without anchor | yes with anchor; chain alone cannot see it (by design, HB-2) |
| Reorder, delete, insert, duplicate | all permutations of 3 lines, each removal, a duplicated line | yes |
| Rehash without key | edit plus recomputed `entry_hash` | yes (`bad_signature`) |
| Signature replay across entries, cross-domain signature, wrong or unknown key | | yes |
| Stripped `sig`/`kid` and rehash | strict mode | yes (`missing_signature`); compat mode accepts by design |
| Fork against anchor, forged, garbage or missing anchor file | | yes |
| Torn last line, garbage line, blank line, non-canonical line | verifier and sink (sink refuses to append) | yes |
| Concurrent writers | 4 threads on 2 sinks; 3 OS processes x 25 appends | yes, one chain |
| Hostile input | deep nesting, BOM, bad UTF-8, huge numbers, reserved keys, non-objects, to verifier and sink | no panic, no write |

## Not tried

kill -9 mid-write (a torn line is simulated, no process is killed); disk full; read-only filesystem (only an unwritable path); fuzzing (target written, not run: libfuzzer-sys is not available offline); the oracle on the same inputs (Python does not run on this machine); clippy and fmt (components not installed).

## Known limits, not defects

A key holder can rewrite log and anchor together; rolling both back to an older matching pair is undetectable without an external anchor; `python_compat` lets an attacker strip signatures and rehash.

## Interop review against the other implementations (sluicegate `kernel/audit.py`, gateway `LockedHashLog`)

Same principles hold in mine: append under an exclusive cross-process lock, re-read the last line for the head on every append, fsync, hash over all fields except `entry_hash`, head exposed for anchoring. Two gaps found and fixed:

| # | Sev | Finding | Fix and test |
|---|---|---|---|
| A-2 | S1 | The sink locked `<log>.lock`; the Python gateway locks `<home>/locks/audit.lock`. Writers using different lock files do not exclude each other, so a mixed Rust and Python deployment could fork the chain. | `FileSink::with_lock_path`; the lock directory is created. Test `shared_explicit_lock_file_is_used`. Deployment must pass the gateway's lock path. Flock (Unix) and byte-range lock (Windows) are the same OS mechanisms as Python's; not exercised live here (no Python). |
| A-3 | S2 | The sink refused to continue a Python log whose last entry has non-ASCII text (Python hashes the ASCII-escaped form, the sink checked only the JCS hash). | `scan_tail` accepts the legacy hash. Tests `rust_continues_a_python_log_with_non_ascii_tail`, `corrupt_python_tail_still_fails_closed`. |

sluicegate's `AuditLog` is not safe across processes, has no fsync and an in-memory rotation; nothing in it is needed beyond what the gateway log already covers.

## Adversarial round 2 (`tests/adversarial.rs`, 9 tests)

| # | Sev | Finding | Result |
|---|---|---|---|
| A-4 | S3 | `head()` read the log without the lock and could see a half-written tail under concurrent appends. | Fixed: `head()` takes the same locks; test `head_during_concurrent_appends_is_always_consistent`. |
| A-5 | S3 | No size limit on an entry; a huge entry made every later tail read huge. | Fixed: `MAX_ENTRY_BYTES` (1 MiB) -> `InvalidInput`; test `oversized_entry_is_refused`. |

Held: 3000 randomized rounds of 1 to 4 stacked mutations (byte replace, delete, insert, line duplicate, drop, swap, truncate) of a 6-entry log never verified in strict mode with the anchor; entries the canonical form cannot carry (unsafe integers, 1e999, lone surrogates, noncharacters, duplicate keys) are refused with nothing written; odd valid entries (empty object, nested reserved names, escapes, U+2028, astral keys, extreme numbers) round-trip and verify; a deleted log is not recreated by `append` and fails against the anchor; a read-only log refuses and stays byte-identical; an anchor signature cannot stand in for an entry signature; CRLF (Python text mode on Windows) logs verify in compat mode and the sink either continues or refuses.

Open design questions found, not changed: keys are looked up at verify time (`now`), not at entry time, so a key whose window has ended makes old entries fail; key rotation inside one log works only if the KeyStore trusts every kid for the whole log. Neither the log file nor the anchor's directory is fsynced after creation or rename.

## Red team 2 (independent agent, `findings/audit-redteam2.md`, `tests/redteam2.rs`) and the fixes

| # | Sev | Result |
|---|---|---|
| R2-1 | S0 | Fixed. Sink checks log against anchor before every append, chains last line to its predecessor, re-verifies a log longer than the anchor in full, rolls back on failure. See ESCALATION.md. |
| R2-2 | S1 | Fixed for verification: with an anchor demanded, a missing anchor file is `anchor_missing` even for an empty log. Never-used log vs wiped log stays indistinguishable (E-A1). |
| R2-3 | S1 | Fixed: unsigned entries after the anchored head are refused even in compat mode; the sink refuses a non-empty log without an anchor unless `adopt_unanchored(true)`. |
| R2-4 | S2 | Fixed: if the anchor cannot be published the entry is taken back (`set_len`), so `Err` means no entry. |
| R2-5 | S2 | Fixed: last-line read is capped (4 MiB) and linear. |
| R2-6 | S2 | Fixed by refusing U+2028, U+2029, U+0085 in entries (Python `splitlines` would cut the line). |
| R2-7 | S3 | Fixed by the two-line tail check plus R2-1. |
| R2-8 | S3 | Accepted (E-A1). |
| R2-9 | S3 | Accepted (E-A2). |
| R2-10 | S3 | Fixed: default lock file is the log path with extension `lock`, as Python's `LockedHashLog`. |
| R2-11 | S3 | Fixed: the CLI uses `<log>.anchor` automatically when it exists (`--no-anchor` opts out). |

Not fixed, from reading only: Python writes some floats differently (`1e-07`), so entries with non-integer numbers may not verify in the Python oracle; the secret passed to `FileSink::open` is the caller's copy to wipe.
Test changes caused by the fixes (all visible in git): `empty_log_verifies` now expects `anchor_missing` with the anchor demanded; `fork_detected_by_anchor` forges with an anchor-less sink; `sink_follows_the_disk_not_a_cache` now expects refusal (and uses different content, the old one swapped in an identical file); Python-continuation tests use `adopt_unanchored(true)`; red-team-2 tests h09 and a04 assert the fixed behavior, four tests are `#[ignore]` for E-A1 to E-A3.

## kill -9 (`tests/killnine.rs`)

Six rounds of killing a child that appends 200 KB entries in a loop (TerminateProcess), each followed by verify, optional repair, one more append and verification with the anchor: the log was intact every round (no torn line occurred; a kill between the write and the anchor update leaves the anchor one entry behind, which the sink and verifier accept after a full signed re-verify). `FileSink::repair_torn_tail` (new) removes a last line without a newline, the only damage a crash can cause, and nothing else; `repair_only_touches_a_torn_last_line` covers a torn line, an intact log and other damage. Not covered: power loss with a lost fsync, disk full.
