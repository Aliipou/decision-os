# status: dos-install

Branch `task/install`. Design: `design/install.md`.

## Changes

- `crates/dos-install`: the client registry (`clients.rs`), the wrapped entry (`entry.rs`),
  the Python `json.dumps` printer (`pyjson.rs`), the state file (`state.rs`), atomic
  writes, backups and the lock (`fsio.rs`), the JSON path (`jsonfile.rs`), the Codex TOML
  path (`codex.rs`: toml_edit parse, whole-line splice from key/value spans, re-parse
  and verify), and the driver (`lib.rs`).
- `read_config` applies Python's universal newlines (CRLF and lone CR become LF) before
  editing, as the oracle's `read_text` does; the `codex-crlf-*` vectors require it.
- `conformance/gen/install_from_oracle.py` and 102 vectors in `conformance/vectors/install/`.
- Tests: `tests/vectors.rs` (replays every vector), `tests/props.rs` (proptest),
  `src/tests.rs` (red-team cases that need the before-replace hook).
- Fixed a wrong expectation in `fsio::tests::civil_dates`: 1_795_000_000 is
  2026-11-18 11:06:40 UTC (20775 days plus 40000 s), not 10:26:40.

## Test results (Windows, stable-x86_64-pc-windows-gnu)

`cargo +stable-x86_64-pc-windows-gnu test -p dos-install --offline -j 2`:

```
running 18 tests ... test result: ok. 18 passed; 0 failed      (unit + red-team)
running 4 tests  ... test result: ok. 4 passed; 0 failed       (props)
running 1 test   ... test result: ok. 1 passed; 0 failed       (vectors)
skipped Some(String("json-symlinked-file")): this host cannot create symlinks
102 vectors: 93 run, 8 registry, 0 failure(s)
```

Red-team unit tests: an app writing between our read and our rename (refused, the app's
bytes stay, state not updated), corrupt state refuses the run, unknown client and missing
home refuse, dry run creates nothing (not even the home), backups never overwritten under
the same clock, two concurrent installs keep both state entries, a `command =` line
inside a TOML multi-line string is not edited, every global target is inside the given
home. Read-only files, NaN/Infinity, deep nesting, lone surrogates, BOM and invalid UTF-8
are covered by vectors.

## Gaps and open decisions

- `json-symlinked-file` is skipped on hosts that cannot create symlinks (Windows without
  Developer Mode or admin, error 1314); it runs on Linux, macOS and CI. Not run here.
- clippy is not installed for the GNU toolchain on this machine, so the workspace clippy
  lints (`unwrap_used`, `indexing_slicing`, ...) were not checked. A grep finds no
  `unwrap`/`expect`/`panic!` outside `src/tests.rs`.
- `spec/install.md`, which the crate docs and the generator mention, does not exist yet
  (codes, divergences, vector format). The divergences are recorded in each vector's
  `divergence` field for now.
- Universal newlines: like the oracle, an edited CRLF Codex or JSON file is written with
  LF. A byte-exact uninstall still restores the CRLF original. Keeping CRLF would be
  friendlier but would diverge from the vectors; it needs Ali's decision.
- toml_edit 0.25 parses TOML 1.1, and Python `tomllib` parses 1.0. A file that only 1.1
  accepts (newlines in inline tables, `\e`) is edited by Rust and refused by the oracle.
- Codex: the Rust code finds the table and keys from the parse tree, so it also edits
  quoted keys and escaped server names that the oracle's regexes miss (and the oracle
  then reports `manual`). None of the vectors covers this.
- The design's red-team classes still need a separate red-team pass (CLAUDE.md step 3).
