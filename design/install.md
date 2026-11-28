# dos-install: client registry, config wrap/unwrap, backups, byte-exact restore

## Goal

A Rust library with the behavior of the oracle installer
(`oracle/decision-os-min/decision_os_min/gateway/installer.py`, `clients.py`, `paths.py`):
find every MCP client config, wrap each stdio server so it starts behind
`decision-os mcp-proxy`, and undo it exactly. The CLI comes later and builds on this.

Done when:

- every client of `clients.py` is in the registry, with the same paths per OS, computed
  only from an explicit `Env` value (the library never reads the process environment);
- every config shape is wrapped and unwrapped with output bytes identical to the oracle,
  checked by vectors generated from the oracle (`conformance/vectors/install/`);
- entries written by the Python gateway are recognized and unwrapped;
- install then uninstall restores the original bytes when nothing else touched the file,
  and unwraps entry by entry when something did;
- property tests and the red-team classes for the installer pass.

Out of scope: the CLI, `init_home` (policy and key creation), doctor, the conformance
adapter executable (the vectors are replayed by a cargo test for now).

## Approaches

### Codex TOML

1. **toml_edit DOM edit.** Parse into `DocumentMut`, set `command`/`args`, print.
   Comments survive, but the printer decides the bytes: it writes `\n` after every
   key/value (CRLF files change), it may choose literal strings for Windows paths, and
   new keys go to the end of the table. Matching the oracle byte for byte would fight
   the printer on every case.
2. **toml_edit parse + span splice (chosen).** Parse with toml_edit (spans kept), locate
   the `[mcp_servers.<name>]` table and the `command`/`args` statements from the real
   parse tree, and replace exactly the lines the oracle replaces with exactly the text
   it writes (`<indent>command = <json string><nl>`, a one-line array). Every other byte
   is untouched by construction, comments included, and the edit is verified by
   re-parsing with toml_edit. The oracle finds the same lines with regexes; the parse
   tree is never fooled by a `command =` line inside a multi-line string.

### JSON

1. **serde_json `to_string_pretty`.** Different from Python `json.dumps(indent=n)` in
   number forms (`1e5` vs `100000.0`), indent units (tabs, odd widths) and escapes.
2. **serde_json parse (`preserve_order`, `arbitrary_precision`) + a printer that is
   Python's `json.dumps(indent=..., ensure_ascii=False)` (chosen).** Key order is kept by
   `IndexMap` (duplicate keys: first position, last value, the same as CPython's
   scanner). Numbers keep their source text and are printed the way Python prints them
   (int as is, `-0` as `0`, floats with `repr`). The printer is small and every rule is
   pinned by a vector.

### Wrapped entry

The Rust shape is `command = <decision-os binary>`,
`args = ["mcp-proxy", "--home", H, "--client", C, "--server", S, "--", cmd, args...]`.
Recognized and unwrapped: that shape, the oracle shape
`[-P] -m decision_os_min.gateway --home H mcp-proxy --client C --server S -- cmd ...`
(parsed by position, so a server named `--` round-trips), and anything the oracle's
loose predicate accepts (args contain the module name, `mcp-proxy` and `--`), unwrapped
after the first `--` like the oracle.

## State, backups, writes

The state file is the oracle's format (`state.json`, version 1, `entries` keyed by
Python `json.dumps([path, pointer, name])`, `files` with `backup` and `written_sha256`),
so a Rust uninstall restores byte for byte what the Python gateway installed.

Per file, install: re-read and compare with the parsed bytes, write a new backup
(never overwrite one), update and save the state, atomic write (temp in the same
directory, fsync, rename, fsync directory; the file is re-read just before the rename
and the write is refused if it changed), read back and compare. Uninstall writes the
file first and the state after, so a failure between the two only leaves stale state,
which is harmless. One run holds an exclusive lock on `locks/install.lock`.

## Failure modes (each refuses or leaves the file untouched)

| Failure | Behavior |
|---|---|
| file missing | status `missing` |
| not UTF-8, BOM, invalid JSON/TOML, top level not an object | status `error`, untouched |
| JSON with comments or trailing commas | status `manual`, untouched, unless `force_jsonc` |
| NaN or infinity in JSON, nesting deeper than 128 | status `error`, untouched |
| file is read-only | status `error`, untouched |
| symlinked file | the link is kept; the target is written atomically |
| the app rewrites the file while we work | detected before the rename: status `error`, the app's bytes stay |
| non-server content would change (verification) | status `error`, untouched |
| backup or state cannot be written | status `error`, untouched |
| a wrapped entry with nothing after `--` | left as is, message `no-original-command` |
| codex table we cannot locate (inline table, dotted keys) | status `manual`, untouched |
| state file unreadable or not JSON | run refused (`StateCorrupt`); the oracle silently starts over and loses the backup pointers |
| another install running | waits on the lock |
| unknown client id | run refused |
| no home directory in `Env` | run refused |
| remote (http/sse) entry | reported, never touched |
| dry run | nothing is created or written, not even the home directory |

## Test plan

1. `conformance/gen/install_from_oracle.py` runs the oracle in throwaway HOMEs on every
   shape of `test_installer.py` plus BOM, CRLF, trailing commas, comments, duplicate
   keys, empty, invalid, huge, unicode and odd names, args with spaces, env blocks,
   disabled, already wrapped (both shapes), remote, read-only, numbers, escapes,
   project files and every client; it writes the vectors.
2. `tests/vectors.rs` replays every vector (steps, reports, bytes) and the registry
   vectors. Written before the code, seen failing.
3. `tests/props.rs` (proptest): install then uninstall is the identity on bytes,
   install is idempotent, unwrap(wrap(x)) == x for any command and args, the Python
   float printer matches a reference on random doubles.
4. `tests/redteam.rs` and unit tests: symlinks, read-only, concurrent installs, the app
   writing between our read and our rename, state corruption, backups never
   overwritten, dry run writes nothing.
