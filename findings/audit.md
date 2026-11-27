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
