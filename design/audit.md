# Design: audit (crate `dos-audit`)

## Goal

Implement `dos_core::store::AuditSink` as an append-only, hash-chained, signed log, plus a verifier that detects edits, inserts, deletes, reordering, forks and truncation. Closes DM-3 and DM-5 (U-CHAIN-LOG, U-AUDIT) for the Rust core. Same chain rule as `oracle/decision-os-min/decision_os_min/audit.py` so each side verifies the other's log.

## Format

One line per entry, the JCS bytes of the entry plus `\n`. The sink receives the entry JCS without `seq`, `prev_hash`, `entry_hash` (refuses an input that has any of those or `sig`/`kid`) and adds:

- `seq` (0, 1, ...), `prev_hash` (64 zeros for entry 0), `kid` (signer);
- `sig` = Ed25519, domain `audit-head`, over the JCS of the entry without `sig` and `entry_hash`;
- `entry_hash` = SHA-256 hex over the JCS of every field except `entry_hash` (so it covers `sig`). The oracle's rule is the same: hash all fields but `entry_hash`; `sig` and `kid` are just extra fields to Python.

## Two approaches

A. Signatures in a sidecar of signed heads only. B. A signature on every entry plus a signed anchor head. Choice: B. Per-entry signatures stop an attacker without the key from rewriting any entry and re-hashing the chain; the anchor catches tail truncation, which no chain alone can.

## Append

Under an exclusive lock on `<log>.lock` (`File::lock`, cross-process): if the log length differs from the cached one, re-read and check the last line (hash, seq, trailing newline) to get the head; build the entry, write the line in one `write_all`, `sync_all`; update cache; publish the head to the `Anchor` (default `FileAnchor`, signed head file `<log>.anchor`, atomic replace). Any failure is `StoreError::Unavailable`; a torn or corrupt tail makes every later append fail (fail closed) until an operator repairs it.

## Verifier

`verify_file(path, opts)`, strict by default: every line is canonical JCS, `seq == line index`, `prev_hash` links, `entry_hash` recomputed, signature present and valid under a `KeyStore`-trusted kid. Errors carry the line index and a stable kind: `Malformed`, `NonCanonical`, `SeqMismatch` (reorder, delete, insert, head deletion), `PrevHashMismatch`, `HashMismatch`, `BadSignature`, `MissingSignature`, `UnknownKey`, `PartialLine` (no final newline), `Truncated` (head older than anchor), `AnchorMismatch` (fork: anchor's entry has a different hash), `AnchorMissing`, `AnchorInvalid`.

`python_compat` accepts oracle logs: unsigned entries allowed (signatures verified if present), blank lines skipped, non-canonical lines, and the Python hash (ASCII-escaped `json.dumps`) as an alternative to the JCS hash (differs only for non-ASCII text, DM-3).

## Failure modes (each refuses)

Unwritable or locked log, anchor failure, corrupt tail, non-object or reserved-key input, non-canonical input (parse_strict), seq beyond 2^53-1, wrong or unknown key.

## Tests

Round trip; every tamper above (edit field, edit hash, rehash without key, reorder, delete middle, delete head, delete tail with and without anchor, fork, append garbage, partial line, wrong key); concurrent appends from threads and two sinks on one file; restart resume; a Python-style log verifies in compat mode and fails strict; Rust log re-parsed with `serde_json` and hash checked with the Python recipe when ASCII.

## Open

Domain `audit-head` is reused for entry signatures (payloads are structurally distinct); a dedicated `audit-entry` domain needs a `spec/sign.md` change. Anchor in a separate trust domain is deployment work.

## As built (changes since the first draft)

- No cached head: every append and `head()` re-reads the last line from disk under the locks (a cached head could be stale or swapped for a same-length file).
- `FileSink::with_lock_path`: every writer of one log must use one lock file, including the Python gateway (`<home>/locks/audit.lock`).
- The sink accepts a Python-written tail (same chain, ASCII-escaped hash) so Rust can continue an oracle log. Entries over 1 MiB are refused.
- Signatures: Ed25519 over the JCS of the entry without `sig` and `entry_hash`, domain `audit-head` (shared with the anchor; payloads are structurally distinct: an entry always has `prev_hash`, a head never does).
- Extra surface: `dos-audit verify` CLI; conformance area `audit` (16 vectors, answered by `dos-core-adapter`); Lean models in `formal/audit/`.
- Known limits: a key holder can rewrite log and anchor together; rolling both back to an older matching pair is undetectable without an external anchor; `python_compat` accepts unsigned entries; keys are checked at verify time, not entry time; no directory fsync after create or rename.
