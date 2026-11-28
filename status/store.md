# Status: `dos-store` (Phase 3, SpentStore backends)

Branch `task/store`. Design: `design/store.md`.

## What changed

- `crates/dos-store` (new crate): `FileSpentStore` and `SqliteSpentStore` implemented,
  replacing the tests-first stubs. `MemorySpentStore` (feature `memory`), `fsutil`
  (dir checks, identity, dir fsync, timed lock) and all tests were already written in the
  tests-first step. No test was changed, skipped or weakened.
- `file.rs`: domain-tagged SHA-256 marker names, `create_new` compare-and-set, strict
  `dos-spent-v1 <expiry>\n` content (unit tests: no proper prefix parses, non-canonical
  numbers refused), file fsync + dir fsync + dir identity re-check before `First`;
  replay extends under the lock via temp file + rename; purge under the lock removes
  expired markers and `.tmp-*` orphans only.
- `sqlite.rs`: the open sequence runs under `<db>.lock`. Steps: dir checks, refuse a
  non-file or symlinked db, pre-create it with mode 0600, `NOFOLLOW`, `busy_timeout`,
  WAL (verified), `synchronous=FULL` (verified), schema created, then checked column by
  column through `pragma_table_info`, `quick_check == ok`. A spend is `BEGIN IMMEDIATE`
  + INSERT. A PK conflict leads to `UPDATE ... max expiry`, then COMMIT. `First` is
  returned only after the commit.
- `lib.rs`: registers the `fsutil` module.
- `Cargo.lock`: adds the crate's dependencies (all from the local cache, `--offline`).

### Deviations / additions vs design

- File store identity check also requires the store's lock file to still exist with
  the identity recorded at open. On Windows the dir identity is only the creation time,
  and NTFS name tunneling can give a re-created directory the old creation time. A
  re-created directory has no lock file, so it still refuses.
- File store, Windows only: `PermissionDenied` from `create_new` is retried until
  `lock_timeout` and then refused. This covers a marker in NTFS "delete pending" state
  while a purger removes it. A marker vanishing between create and read (purged) makes
  the spend retry the create.
- Purge of a marker or temp file that fails to delete (other than NotFound) returns
  `Unavailable`.

## Build (Windows, TDM-GCC, no MSVC, no WSL)

```
$env:PATH="C:\TDM-GCC-64\bin;$env:PATH"; $env:CARGO_TARGET_DIR='C:\Users\admin\dos-target\store'
$env:CFLAGS_x86_64_pc_windows_gnu='-D_WIN32_WINNT=0x0A00'
cargo +stable-x86_64-pc-windows-gnu test -p dos-store --offline -j 2
```

The `GetTickCount64 undeclared` failure in libsqlite3-sys is fixed by the CFLAGS alone.
No sqlite feature gate was needed.

## Test results (Windows 10, NTFS, two consecutive full runs, both green)

| target | passed |
|---|---|
| lib unit (file parser/name, memory) | 6 |
| contention | 3 |
| durability | 2 |
| fail_closed (portable part) | 9 |
| multiprocess (harness=false) | 4 (file 8x50, sqlite 8x50, first-start sqlite 16x20, file 16x20) |
| path_safety (proptest) | 5 |
| purge (incl. purge races) | 7 |
| **total** | **36, 0 failed** |

Not run here: the `#[cfg(unix)]` tests in `fail_closed.rs` (10 tests: read-only dir,
symlinks, ownership, modes, `DBMOVED`). They need Unix mode bits, owners, symlinks or
`chattr`, and the design plans to run them on ext4 in WSL. They are already cfg-gated
in the test file.

## Open decisions / gaps

- **Unix tests unverified**: run the whole suite on Linux ext4 (TMPDIR not tmpfs)
  before merge. This includes the 10 Unix-only fail-closed tests and the `rustix` path.
- **clippy not run**: no clippy for the gnu toolchain here, and the msvc clippy cannot
  link build scripts without MSVC. The crate avoids `unwrap`/`expect`/`panic`/indexing
  in non-test code by construction, but the gate still has to run.
- **rustfmt**: new sources are rustfmt-clean (default config). The pre-existing test
  files are not rustfmt-clean under the default `fn_call_width` heuristic. They were
  left untouched because the tests are frozen; decide whether to add a `rustfmt.toml`
  or format them.
- Windows gaps (documented in design): no ACL/owner check, creation-time dir identity,
  dir fsync is a no-op, `SQLITE_OPEN_NOFOLLOW` is not honored by the win32 VFS (the
  `symlink_metadata` pre-check still refuses a symlinked db at open).
- Red-team and verifier rounds not yet done.
