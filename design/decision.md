# Design: decision engine (`dos-decision`)

## Goal

Port the gateway policy of `oracle/decision-os-min/decision_os_min/gateway/policy.py`
(`parse_policy`, `classify_tool`, `normalize_path`, `rule_matches`, `evaluate`) and the
policy PDP of `gateway/engine.py` (`GatewayAuthorityPDP.evaluate`, `parse_action`, `slug`)
to Rust, with the same results on the same inputs. The PDP answer is a
`dos_core::verdict::Verdict` (`allow -> Allow`, `ask -> Defer`, `deny -> Deny`), so the
kernel can fold it with the guardrail evaluators through `compose_with`.

Out of scope: guardrails (veto evaluator, its own task), approval and learned stores
(I/O), the dashboard, signing and minting (kernel task), loading the file from disk.

## Approaches

**A. Inside `dos-core`.** Rejected: `dos-core` is `no_std`, has no I/O and a 1,500 line
TCB budget. The policy needs a TOML parser, Unicode lowercasing and environment
lookups. None of that belongs in the trusted core; the PDP is replaceable by design.

**B. New crate `dos-decision`.** Depends on `dos-core` (verdict) and `toml_edit`
(parse only, no display), `sha2` (revision). Everything environment-dependent
(`~`, `$VAR`, `%VAR%`, `os.name`) is a parameter (`PathEnv`), so evaluation is pure and
vectors are deterministic. **Choice: B.** `RUST_REWRITE.md` calls this layer
`dos-policy`; renaming is a one-line change and is left to the main session.

## Python semantics reproduced exactly

- `fnmatch.fnmatchcase` (3.13): `*`, `?`, `[...]`, `[!...]`, unclosed `[` literal, the
  empty-range removal and "never matches" / "any char" cases. Implemented by building
  the same class text Python builds and interpreting it like `sre_parse`.
- `str.lower()` via `str::to_lowercase` (full Unicode, final sigma).
- `json.dumps` for non-string argument values: `ensure_ascii`, Python float `repr`,
  `NaN`/`Infinity`, `sort_keys` + compact separators for lists and objects.
- `ntpath` and `posixpath` `expanduser`, `expandvars`, `normpath`, `normcase`.
- Validation messages, including Python `repr` of offending values.

## Failure modes (each must refuse)

| Input | Result |
|---|---|
| Invalid TOML, unknown key, wrong type, bad enum value | `PolicyError`; the PDP answers `Deny` (fail closed) |
| No policy loaded | `Deny` with `policy error (fail-closed): ...` |
| Action purpose differs from the re-evaluated purpose | `Deny` ("policy changed ...") |
| Argument rule evaluated without arguments (tools/list) | rule does not match |
| Rule `deny` matched | `Deny`, learned choices cannot override |
| `ask` not approved | `Defer` (not permitting) |
| Unknown profile kind / anything unclassified | `ask` under balanced and strict |

No function panics: no indexing, no `unwrap`, all loops bounded by input length.

## Known divergences (documented, not hidden)

- `toml_edit` implements TOML 1.1; `tomllib` (3.13) is TOML 1.0. Some files Python
  rejects (for example multi-line inline tables) parse in Rust. The TOML error text
  after `invalid TOML:` differs.
- `~user` on POSIX needs the password database: Rust leaves it unexpanded.
- Windows `normcase` uses `LCMapStringEx`; Rust uses `to_lowercase`.
- `[llm] upstreams = "x"` crashes the oracle (`AttributeError`); Rust returns a
  `PolicyError`.
- Python `repr` printability is approximated for rare Unicode categories.

## Test plan

Unit tests per module; every case of `tests/gateway/test_policy_guardrails.py` that
touches policy; vectors under `conformance/vectors/policy/` generated from the oracle
by `conformance/gen/policy_from_oracle.py` (policy.py loaded by file path, stdlib only,
both `posix` and `nt` path flavours with a fixed environment) and replayed by
`crates/dos-decision/tests/policy_vectors.rs`.
