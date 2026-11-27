# Status: decision

Branch `task/decision` (from `rust/integrate` at 1a56a2e). Design: `design/decision.md`.

## What changed

| File | Change |
|---|---|
| `crates/dos-decision/` | new crate: `policy` (parse_policy, validation messages), `eval` (classify_tool, rule_matches, evaluate, slug, parse_action, authority_verdict), `glob` (Python 3.13 fnmatchcase), `path` (ntpath/posixpath expanduser, expandvars, normpath, normcase; `PathEnv` parameter), `py` (json.dumps, float/str repr) |
| `crates/dos-decision/tests/policy_vectors.rs` | replays every `conformance/vectors/policy/*.json`; fails under 300 vectors |
| `conformance/gen/policy_from_oracle.py` | generator: loads oracle `gateway/policy.py` and `gateway/engine.py` by path (engine imports stubbed, `GatewayAuthorityPDP.evaluate` runs as written), append-only writes |
| `conformance/vectors/policy/*.json` | 331 new vectors: 84 parse, 34 classify, 74 normalize_path (37 posix, 37 nt), 8 slug, 108 evaluate, 23 pdp |
| `design/decision.md` | new |
| `Cargo.lock` | toml_edit 0.25.21 (parse feature only), toml_parser, toml_datetime, winnow, indexmap, hashbrown, equivalent |

Verdict mapping (engine.py): `allow -> Allow`, `deny -> Deny`, `ask -> Defer` unless the caller's
`is_approved` returns true (then `Allow`); observe mode always `Allow` with an "observe: would ..."
reason; no policy or purpose mismatch -> `Deny`.

## Evidence

Generator (run twice, second run proves determinism / append-only):

```
$ python -B -I conformance/gen/policy_from_oracle.py
331 cases: 331 written, 0 unchanged
$ python -B -I conformance/gen/policy_from_oracle.py
331 cases: 0 written, 331 unchanged
```

(`python` = uv CPython 3.13.5; the PATH Python 3.13 install is broken on this host.)

`cargo +stable-x86_64-pc-windows-gnu test --workspace --offline -j 2 --no-fail-fast`:

```
dos-decision unittests   test result: ok. 17 passed; 0 failed
dos-decision policy_vectors   test result: ok. 1 passed; 0 failed   (331 vectors)
dos-core (lib 41, canon 39, canon_vectors, meet_vectors, sign_vectors, verdict_props 10)  all ok
dos-conformance lib 11 ok; adapter_failures: 26 run, 1 failed (orphan_holding_stderr_does_not_hang, known Windows-only)
```

`scripts/check-protected.sh`: `protected paths: unchanged`.

## NOT done

- clippy and rustfmt are not installed for the gnu toolchain here; `-D warnings` clippy not run.
  Code was written to the workspace lints (no unwrap/expect/panic/indexing in `src/`), but unverified.
- No red-team or verifier round.
- The policy area is not wired into the `dos-core-adapter` conformance adapter nor the Python
  oracle adapter (the oracle adapter needs `cryptography`, absent here). Vectors are replayed by a
  cargo test instead, same as `meet`.
- Guardrails, approval/learned stores, file loading and reload-on-change are out of scope.
- `action_fingerprint` is still a stub in dos-core; approval is a caller-supplied closure.

## Known divergences from the oracle (no security case found; all fail closed or are stricter)

- TOML 1.1 (toml_edit) vs TOML 1.0 (tomllib): some files Python rejects parse in Rust. The
  `invalid TOML:` detail text differs (vectors compare the prefix only).
- `llm.upstreams` truthy non-table: oracle crashes with AttributeError, Rust returns PolicyError.
- POSIX `~user` is not expanded (no pwd lookup). Windows normcase uses `to_lowercase`, not LCMapStringEx.
- Python `repr` printability and datetime reprs in messages are approximations.
- Integers beyond i64 (TOML) or i128 (arguments) are not represented.
- A reversed range surviving fnmatch's empty-range pass makes Python raise `re.error`; Rust never matches.

## Open decisions

- Crate name: `dos-decision` (as asked) vs `dos-policy` (RUST_REWRITE.md layout).
- Whether to ship a spec doc `spec/policy.md`; not written in this task.
