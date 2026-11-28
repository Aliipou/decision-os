# Design: `dos-store` (Phase 3, SpentStore backends)

## Goal

Implement `dos_core::store::SpentStore` (U-ONCE: a token is spent at most once across
threads, processes, instances and restarts; an unavailable store refuses) in a new std
crate `crates/dos-store` with three backends:

- `MemorySpentStore`: single process only, behind the non-default `memory` feature (and
  `cfg(test)`); the only constructor is `MemorySpentStore::single_process_only()`, there is
  no `Default`.
- `FileSpentStore`: one marker file per token in a directory.
- `SqliteSpentStore`: one sqlite database (rusqlite, bundled sqlite).

Every backend also has `purge_expired(now_unix_ms) -> Result<u64, StoreError>`.

Out of scope: the PEP (`dos-pep`), audit, key store, revocation, Python binding, any
multi-machine store (Postgres is Phase 7).

## Contract decisions (all backends)

1. Token id: 1..=256 bytes of UTF-8 (`&str`), else `InvalidInput`. Any byte content is
   allowed (path characters, NUL, unicode): ids are never used as paths.
2. `First` is returned only after the record is durable (file + directory fsync, or a
   committed sqlite transaction with `synchronous=FULL`). Any error before that point is
   `Unavailable`. A record created by a call that then reports `Unavailable` stays spent
   (the token is lost, never doubled).
3. Expiry: the record keeps the **maximum** `expires_at_unix_ms` ever passed for its id.
   A replay with a later expiry extends the record (the trait says a store must never drop
   a record before "that time"; if a later call names a later time, that time is the bound).
4. Purge removes a record only when `stored_expiry < now_unix_ms` (strict: at `now ==
   expiry` the PEP already refuses, keeping the record one more millisecond costs nothing).
   A record whose expiry cannot be read is never purged.
5. `AlreadySpent` vs `Unavailable` on the replay path: both refuse. A replay whose
   extension write fails reports `Unavailable`.

## FileSpentStore

Marker name: lowercase hex SHA-256 of `"dos-store/spent-file/v1\0" || token_id` (64
chars, never the raw id). Marker content: exactly `dos-spent-v1 <expiry>\n`. Because the
content ends in `\n`, no proper prefix of it parses: a reader that races the writer sees
"unparsable", never a wrong expiry.

Approaches considered:

- A. `create_new` (O_CREAT|O_EXCL) on the marker, then write + fsync file + fsync dir.
  The kernel does the compare-and-set. Window: the marker exists but is empty until the
  write lands.
- B. Write a temp file, fsync, then `hard_link(tmp, marker)` (atomic, fails if it exists),
  so a marker is never seen partial. Fails on filesystems without hard links (FAT/exFAT,
  some FUSE), adds a temp file per spend.

**Choice: A** (task requirement; it is the oracle's mechanism; works everywhere
`O_EXCL` works). The partial window is handled by the strict content format and rule 4.

Purge and extension safety: a store-wide lock file `<dir>/.dos-spent.lock`
(`std::fs::File::try_lock`, i.e. `flock` on Unix, `LockFileEx` on Windows, polled until a
timeout, default 5 s). Purge and expiry extension take it exclusively. The plain spend
does not take it: it never modifies an existing marker, and a purger only deletes a
marker while holding the lock, after re-reading it under the lock, so it cannot delete a
record that was created or extended after its read. Extension = write
`.tmp-<marker>-<pid>-<n>`, fsync, `rename` over the marker (the marker name exists at
every instant, so a racing spend still sees `AlreadySpent`), fsync dir. Purge also removes
`.tmp-*` orphans, which is safe because no extender can be active while it holds the lock.
If an extending replay finds an unparsable marker (a first spender mid-write), it polls
until it parses or the timeout passes; on timeout it returns `AlreadySpent` without
extending (the unparsable record is never purged, so that is safe).

Directory checks at `open` (Unix): create missing directories with mode 0700; then
`symlink_metadata(dir)` must be a real directory (not a symlink), owned by the effective
uid (`rustix::process::geteuid`, safe API; the crate forbids `unsafe`), with no group or
other write bit (`mode & 0o022 == 0`: anyone else who can write the directory can delete
markers and double spend). The directory's `(dev, ino)` is recorded; after every
successful create, before returning `First`, the directory is `lstat`ed again and must
have the same identity, so a directory removed, re-created or swapped for a symlink
mid-run gives `Unavailable` instead of a `First` in a fresh empty directory.

Windows: symlinks and junctions are refused (`symlink_metadata().file_type().is_symlink()`
covers name-surrogate reparse points). Ownership and ACLs are **not** checked (std has no
API, and calling Win32 needs `unsafe`, which the crate forbids); the directory should live
under the user's profile, whose inherited ACL is owner-only. Directory identity is the
creation time (`MetadataExt::creation_time`, 100 ns), weaker than an inode number.
Directory fsync is skipped (NTFS journals metadata; `File::open` on a directory fails
without backup semantics). These are documented gaps, not tested here.

## SqliteSpentStore

Schema: `spent(token_id BLOB PRIMARY KEY, expires_at INTEGER NOT NULL) WITHOUT ROWID`
(BLOB: exact byte comparison, no collation, NUL-safe).

Approaches considered for the spend:

- A. `BEGIN IMMEDIATE; INSERT ...;` primary-key conflict (extended code
  `SQLITE_CONSTRAINT_PRIMARYKEY`) means `AlreadySpent`, then `UPDATE ... SET expires_at =
  max(expires_at, ?)` in the same transaction; `COMMIT`; only a successful commit of the
  insert returns `First`.
- B. `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` with a marker column to tell insert
  from update. One statement, but relies on subtle `RETURNING` semantics and hides the
  conflict.

**Choice: A**: the single INSERT with PK conflict detection is the atomic compare-and-set;
the transaction makes extension and purge serializable with it.

Opening (the PR #9 bug): approaches were (a) rely on `busy_timeout` alone, which does not
cover the brand-new-database WAL switch ("database is locked" without waiting), or (b)
serialize the whole open sequence across processes with an exclusive lock on
`<db>.lock`. **Choice: (b)**, as the oracle gateway does. Under the lock: check the parent
directory (same checks as the file store), refuse a symlinked db path, pre-create the db
file with mode 0600 (sqlite gives `-wal`/`-shm` the db file's mode), open with
`SQLITE_OPEN_NOFOLLOW`, `busy_timeout`, `journal_mode=WAL` (verified to return `wal`),
`synchronous=FULL` (verified), create the table, verify the schema by preparing
`SELECT token_id, expires_at FROM spent`, `PRAGMA quick_check` must return `ok`. Spends
use `busy_timeout` (default 5 s). One connection per store behind a `Mutex`; a poisoned
mutex is `Unavailable`. A db file unlinked or renamed while open gives
`SQLITE_READONLY_DBMOVED` on Unix, so it fails closed. Purge: `DELETE ... WHERE
expires_at < ?`.

## Failure modes (each refuses)

| Failure | Result |
|---|---|
| empty or > 256-byte id | `InvalidInput` |
| store dir missing at spend, removed mid-run, re-created, replaced by symlink | `Unavailable` |
| dir is a regular file, a symlink, not owned by euid, group/other writable | `Unavailable` at open |
| read-only dir, disk full, any create/write/fsync error | `Unavailable` (marker may stay: token lost, not doubled) |
| lock not acquired within timeout (purge, extension, sqlite open) | `Unavailable` |
| sqlite: corrupt file, not a database, wrong schema, busy past timeout, `DBMOVED`, commit failure, poisoned mutex | `Unavailable` |
| unparsable marker | treated as spent forever; purge keeps it |

## Differences from the oracle (`decision_os_min/spentstore.py`)

| Case | Oracle | Rust | Why |
|---|---|---|---|
| empty id | accepted (spends `sha256("")`) | `InvalidInput` | the trait contract; an empty id is a caller bug |
| > 256-byte id | accepted | `InvalidInput` | contract; bounds sqlite rows |
| marker name | `sha256(id)` | `sha256(tag \|\| id)` | domain separation (task requirement). Consequence: Rust does not see markers written by the oracle. Swap procedure (Phase 4): stop the Python processes and wait for the maximum token TTL (30 s) before starting Rust on the same directory |
| marker content | raw token id | `dos-spent-v1 <expiry>\n` | no raw id on disk; expiry needed for purge |
| expiry / purge | none (grows forever) | max expiry kept, strict purge | task requirement |
| dir checks | `mkdir(parents)` only | 0700, no symlink, owner, no g/o write, identity re-check | a writable or swapped dir allows double spend |
| dir fsync | none (file fsync only) | file + dir fsync | the new directory entry is what makes the spend durable |
| sqlite schema | `token_id TEXT PRIMARY KEY` | `BLOB PRIMARY KEY, expires_at` | expiry; an oracle db fails the schema check (refuses) |
| sqlite open race | store itself unguarded; gateway wraps it in `file_lock` | the store takes the lock itself | every caller gets it |
| sqlite sync | `synchronous=FULL`, WAL | same, verified | |

## Test plan

Unit (`src/`): id validation, marker format parser (prefixes never parse), memory store
contention (32 threads x 50 rounds), memory purge.

Integration (`tests/`), run on ext4 in WSL (`TMPDIR` on `/root`, not tmpfs `/tmp`, not
`/mnt/c`):

- `contention.rs`: 32 threads x 50 rounds, same id, file and sqlite, one shared store and
  one store per thread: exactly one `First`.
- `multiprocess.rs` (`harness = false`, re-executes itself with `DOS_STORE_CHILD`): 8
  processes x 50 rounds per backend, same id: exactly one `First`; 16 processes opening a
  brand-new sqlite path at once (x 20 rounds): all open and spend without error, exactly
  one `First`.
- `durability.rs`: spend, drop, reopen, `AlreadySpent` (both backends, also after purge
  of other expired ids).
- `fail_closed.rs`: read-only dir (chmod 0500, or `chattr +i` when running as root, since
  root ignores mode bits), dir removed mid-run, dir removed and re-created, dir swapped for
  a symlink, regular file in place of the dir, symlinked dir, dir not owned by us, group
  writable dir, corrupt sqlite file, db path that is a directory, oracle-schema db, db
  unlinked mid-run, lock held past timeout: `Unavailable`, never `First`.
- `path_safety.rs` (proptest): arbitrary ids including `../../x`, `a/b`, `C:\x`, NUL,
  256-byte, unicode: nothing created outside the store dir, every entry is the lock or a
  64-hex marker, same id same marker, distinct ids distinct markers.
- `purge.rs`: unexpired kept, `now == expiry` kept, `expiry + 1` removed, unparsable kept,
  extension by replay respected, purge racing spends and extensions keeps exactly-once.
