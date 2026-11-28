# Red team 2: dos-audit

## First-pass hypotheses (written before reading status/audit.md and findings/audit.md)

1. H01 Truncate the tail, then let the sink append once: the sink re-reads only the on-disk tail and overwrites the anchor with the shorter head, so strict+anchor verification passes.
2. H02 Truncate the log to 0 bytes, then append: whole history replaced by a fresh chain that verifies against the rewritten anchor.
3. H03 Truncate the log to 0 bytes and delete the anchor (no append): `verify_file_with_anchor_file` returns ok entries=0.
4. H04 Anchor rollback: an old copy of the signed anchor plus a log truncated to that head verifies.
5. H05 Sink continues after a forged unsigned (hash-consistent) tail, or a duplicated tail line: it signs onto a chain that cannot verify (it only checks the last line's hash).
6. H06 Anchor publish fails (custom anchor error, `.anchor.tmp` blocked, or a Windows reader without FILE_SHARE_DELETE on `.anchor`): `append` returns Err but the entry is already durable.
7. H07 Same log reached through a hard link: two different `<log>.lock` files, no mutual exclusion, concurrent writers fork the chain.
8. H08 Default Rust lock `<log>.lock` differs from Python `LockedHashLog` default `path.with_suffix(".lock")`: a Rust and a Python writer on one log do not exclude each other unless configured.
9. H09 Rust writes U+2028, U+2029 and U+0085 raw (JCS does not escape them); Python `str.splitlines()` splits on them, so the Python `HashLog()` constructor and `verify()` break on a Rust log.
10. H10 The CLI without `--anchor-file` accepts a truncated log (anchor not wired by default, U-CHAIN-LOG).
11. H11 A huge tail without a newline makes `read_tail` quadratic (8 KiB steps, whole buffer copied each step): append or head() hangs while holding the lock.
12. H12 A verifier running during concurrent appends reports a spurious failure (torn read; anchor/log race).
13. H13 Byte-level mutations (delete, insert space/newline, replace) of an anchored log ever verify in strict mode, or change semantics and verify in compat mode.
14. H14 Hostile anchor files (empty, BOM, CRLF, deep nesting, duplicate keys, uppercase hex, string or huge seq, extra fields) panic or verify a tampered log.
15. H15 The secret key leaks through Debug, errors or any file the sink writes (log, anchor, lock, tmp).
16. H16 A tail at seq 2^53-1 (or beyond): append panics, writes, or overflows instead of refusing cleanly.
17. H17 Concurrency across threads and processes with different spellings of the same path (relative, `.\`, case) corrupts the chain.
18. H18 python_compat with an anchor accepts unsigned entries appended after the anchored head by someone without the key.
19. H19 python_compat: stripping the signature from the last entry and rehashing passes with an anchor.
20. H20 Compat mode: an entry with `kid` but no `sig` is accepted.

Additional angle (requested mid-run): an attacker who has only artifacts (log, anchor, the `dos-audit` binary, the public key, the oracle source) and no secret. Tests `a01`..`a05`.

## Method and evidence

Independent red team. All tests are in `crates/dos-audit/tests/redteam2.rs` (34 tests). No product code or existing test was edited. Command (PowerShell):

```
$env:PATH="C:\TDM-GCC-64\bin;$env:PATH"; $env:CARGO_TARGET_DIR='C:\Users\admin\dos-target\audit'; $env:CFLAGS_x86_64_pc_windows_gnu='-D_WIN32_WINNT=0x0A00'; cargo +stable-x86_64-pc-windows-gnu test -p dos-audit --offline -j 2 --no-fail-fast
```

Result: adversarial 9/9, audit 21/21, interop 4/4, redteam 11/11, vectors 1/1 pass. redteam2: `14 passed; 20 failed`. Each failing test is a finding below. I read `status/audit.md` and `findings/audit.md` only after writing the hypotheses above.

## Findings

| # | Sev | Finding | Repro (all FAIL on target) |
|---|---|---|---|
| R2-1 | **S0** | **Truncation or a full wipe is hidden by the next legitimate append.** `append` re-reads only the on-disk tail and never compares it with the anchor (or with a head it remembers). An attacker deletes the last N lines, or truncates the log to 0 bytes. The next append chains from the shorter head and `FileAnchor::publish` overwrites `<log>.anchor` with it, so strict verification with the anchor passes. Observed: 5 entries, the last 3 dropped, one append, result `Ok(Verified{entries:3})`. Wiped to 0 bytes plus one append gives `Ok(entries:1)`. The same happens across a restart (new `FileSink`). This defeats U-CHAIN-LOG ("truncation is detected against an anchor that is wired by default") as soon as any writer appends again. `deleted_log_is_not_silently_recreated_by_append` covers only `remove_file`, not truncation. Per CLAUDE.md an S0 needs escalation to Ali. | `h01_truncate_tail_then_one_append_verifies_with_anchor`, `h01b_truncate_tail_then_reopen_and_append_verifies_with_anchor`, `h02_wipe_log_then_append_verifies_with_anchor` |
| R2-2 | S1 | **Empty log plus deleted anchor verifies.** `verify_file_with_anchor_file` returns `Ok(entries:0)` when the log is 0 bytes and the anchor file is missing. The whole history is erased, and the check that is supposed to require the anchor reports success. | `h03_wipe_log_and_delete_anchor_verifies` |
| R2-3 | S1 (python_compat deployments) | **A keyless attacker mints history, and the real key then signs and anchors it.** Using only the oracle recipe (`json.dumps` line, sorted compact hash), the attacker writes unsigned entries ("rm", "exfil"). The sink accepts the forged tail, appends a signed entry on top, and publishes a signed anchor. Compat verification with the anchor and `dos-audit verify --python-compat` both then accept (exit 0). Separately, compat verification with an anchor accepts unsigned entries appended after the anchored head. Strict mode rejects both cases (held). | `a04_log_minted_from_the_python_recipe`, `h18_compat_with_anchor_accepts_unsigned_entries_after_the_head` |
| R2-4 | S2 | **`append` returns Err after the entry is already durable.** The line is written and fsynced before `Anchor::publish`. If publish fails, the caller is told the audit failed, so the PEP skips the effect, but the log holds a signed entry (for example `verdict: ALLOW`) for an effect that never ran. The anchor is also left stale, so that entry can be truncated undetected. On Windows any reader that opens `<log>.anchor` without FILE_SHARE_DELETE (a backup tool, an editor, an AV scanner) makes `rename` fail. Every append then fails while still writing its line. A pre-created `<log>.anchor.tmp` directory does the same. | `h06a_failed_append_leaves_no_entry`, `h06b_blocked_anchor_tmp_fails_append_and_leaves_entry`, `h06c_windows_reader_without_share_delete_on_anchor` |
| R2-5 | S2 | **Quadratic `read_tail` hangs the writer while it holds the lock.** A 24 MiB unterminated tail took **22.8 s** to refuse (debug build). Each 8 KiB step re-copies the whole buffer. Every writer and `head()` blocks on the lock meanwhile, and the cost grows with the square of the size. | `h11_huge_unterminated_tail_refuses_quickly` |
| R2-6 | S2 (interop) | **A Rust log breaks the Python oracle.** JCS writes U+2028, U+2029 and U+0085 raw. Python `HashLog.__init__`, `verify()`, `entries()` and `LockedHashLog.tail()` use `str.splitlines()`, which splits on them, so `json.loads` raises on a fragment. One attacker-controlled string (a tool argument or reason) in a Rust-written log means the Python `HashLog(path)` constructor raises, so the gateway cannot open the log. Shown on the Rust side: a 1-entry log splits into 4 pieces. The Python side is not run (no Python on this machine); this follows from reading `audit.py`. | `h09_rust_lines_survive_python_splitlines` |
| R2-7 | S3 | **The sink extends a tail it cannot vouch for.** `scan_tail` checks only that the last line's hash matches its own content. It does not check the signature, the kid, the seq relative to the line before, or the previous line at all. The sink therefore signs onto an unsigned forged line, a duplicated last line (two entries with the same seq) or a tail signed by an unknown key. It writes a chain that strict verification rejects, and makes R2-3 possible. | `h05a_sink_refuses_to_extend_a_forged_unsigned_tail`, `h05b_sink_refuses_to_extend_a_duplicated_tail`, `h05c_sink_refuses_tail_signed_by_another_key` |
| R2-8 | S3 (residual, partly known) | **Rollback and substitution.** (a) An old anchor plus a log truncated to it verifies, through the API and through the CLI with `--anchor-file`. This was already listed as a known limit. (b) New: a log and anchor pair taken from *another* log signed with the same key (staging, a rotated file) replaces this log and verifies. Neither entries nor anchor bind a log identity (a log id in the genesis entry and the anchor payload). | `h04_anchor_rollback_with_matching_truncation_verifies`, `a03_old_anchor_replay`, `a02b_whole_log_and_anchor_substituted_from_another_log_with_the_same_key` |
| R2-9 | S3 | **Hard-linked path forks the chain.** The lock file is derived from the path string (`<log>.lock`), so two names for one file get two locks. Two sinks appending concurrently through a hard link produce `SeqMismatch at line 1`. Different spellings of one path (`.\`, `sub\..`, case) hold: `h17`, `h17b`. | `h07_hard_linked_log_path_forks_the_chain` |
| R2-10 | S3 | **Default lock path differs from Python's default.** Rust locks `audit.jsonl.lock`. Python `LockedHashLog` defaults to `path.with_suffix(".lock")`, which is `audit.lock`. A Rust append runs while Python's default lock is held. Related to A-2, which was fixed only via the opt-in `with_lock_path`; the defaults still do not exclude each other. | `h08_default_lock_matches_python_locked_hashlog_default` |
| R2-11 | S3 | **The CLI does not wire the anchor by default.** `dos-audit verify <log> --key K` exits 0 on a truncated log even though `<log>.anchor` sits next to it. The anchor is checked only with `--anchor-file`. | `h10_cli_without_anchor_flag_accepts_truncated_log` |

Analysis only, no test: Python re-serializes floats differently from JCS (`1e-07` vs `1e-7`, `1e+16` vs `10000000000000000`). A Rust entry carrying such a float fails Python's `verify()` (false rejection, S3). The secret is copied into `FileSink::open`'s stack and argument, and the `&[u8; 32]` is not zeroized by this crate (S3 hardening; `SigningKey` itself is ZeroizeOnDrop).

## Attack classes that held

| Class | Tried | Held |
|---|---|---|
| Byte edits | every position of a 3-entry anchored log (one entry non-ASCII with `\u0000` and `-1.5e-7`): delete; insert space, `\n`, `\r`, `0`, `"`; replace with space, `\n`, `0`, `f`, xor 0x20, xor 0x01. Strict and compat, each with the anchor | yes: strict never verified; compat never verified with a changed meaning (`h13`) |
| Forgery without key | unsigned line; attacker key; attacker signature under the victim kid; reused last signature; zero signature. API and CLI | yes (`a01`) |
| Splicing two logs with the same key | prefix of A plus suffix of B at every cut, with no anchor, A's anchor and B's anchor, strict and compat | yes (`a02`) |
| Anchor from another log of equal length | | yes, `AnchorMismatch` (`a03`) |
| Hostile anchor files | empty, `\n`, BOM, CRLF, seq as string, duplicate seq, wrong seq, seq 2^53+1, 1e400, uppercased, 100k nesting, 0xFF bytes, doubled file. Against a truncated log | yes, no panic, never accepted (`h14`) |
| Seq limits | tail at 2^53-1, 2^53 and 1e300, correctly signed | yes, refuses, file byte-identical, no panic (`h16`) |
| Compat signature games | sig and kid stripped from the anchored last entry and rehashed; `kid` without `sig` | yes (`h19`, `h20`) |
| Secret leakage | `SigningKey` Debug and pretty Debug; `StoreError` Debug; every file in the log directory (log, anchor, lock, after a failed tmp); the `dos-audit` binary; CLI stdout and stderr, including the secret passed as `--key` by mistake. Raw and hex | yes, never found (`h15`, `a05`) |
| CLI hostile args | no args, missing values, bad hex, all-zero key, BOM and invalid-UTF-8 log, two positionals | yes, exit 1 or 2, no panic (`h10b`) |
| Concurrency | 4 threads through 4 spellings of one path; 3 OS processes through 3 spellings (plain, `.\`, case) | yes, one chain, verifies with the anchor (`h17`, `h17b`) |
| Verifier during appends | repeated anchored verification while 60 entries of 200 KB are appended | yes, no false alarm (`h12`) |
| Format recovery | the field set and hash rule recovered from the artifacts and the oracle source | trivial (public by design); gives nothing without the key in strict mode |

## Not done

No fuzzing (libfuzzer-sys is not available offline). Python was not run (no interpreter), so R2-6 and the float note come from reading the code. No kill -9 mid-write, disk-full or read-only-filesystem runs. No conformance vectors added: this task allowed only the test file and this report to be added. Every repro stays as a test in `redteam2.rs`.
