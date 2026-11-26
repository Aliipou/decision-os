# Conformance vectors and adapters (v1)

The vectors are the spec in executable form. Every implementation (the Python oracles,
the Rust crates, later the Lean model) ships an adapter; one runner checks them all.

## Vector files

`conformance/vectors/<area>/<name>.json`, one case per file, UTF-8, LF, JCS-canonical
is not required (they are read, not hashed). Existing files are append-only: a wrong
expected value is a spec change, not an edit.

```json
{
  "v": 1,
  "area": "jcs",
  "name": "rfc8785-3.2.2-numbers",
  "input": { "...": "area-specific" },
  "expected": { "...": "what the spec requires" },
  "oracle_expected": { "...": "optional: what the oracle does, when it diverges" },
  "gap": "optional: KNOWN_GAPS id this case closes, e.g. DM-2",
  "source": "where the case comes from (RFC section, oracle test, red-team finding)"
}
```

- `name` is unique within the area and equals the file name without `.json`.
- `expected` is always an object. A refusal is `{"error": "<code>"}` with a code from
  the area's spec; any other output is `{"ok": <value>}`.
- `oracle_expected` exists only for deliberate divergences (see `KNOWN_GAPS.md`). The
  oracle adapter is checked against `oracle_expected` when present, else `expected`;
  every other adapter is checked against `expected`.

## Adapter protocol

An adapter is an executable. It reads one JSON object per line on stdin and writes
exactly one JSON object per line on stdout, in the same order, then exits 0 at EOF.

- request: `{"area": "...", "name": "...", "input": {...}}`
- response: `{"name": "...", "output": {"ok": ...} | {"error": "<code>"} | {"unsupported": true}}`

`unsupported` is allowed only for areas the adapter does not implement yet; the
runner reports it and fails if `--require <area>` names that area.

Comparison is exact JSON equality after parsing (object key order ignored; numbers
compared as parsed values; strings by code points).

## Runner

`dos-conformance --adapter <cmd> [--area <a>]... [--require <a>]... [--oracle]`
runs every vector in the selected areas through the adapter and prints one line per
case (`ok`, `FAIL`, `unsupported`) and a summary. Exit 1 on any FAIL, on a missing or
extra response line, on a malformed response, or on `unsupported` in a required area.

## Fixed test keys

Deterministic signatures use the Ed25519 secret key of RFC 8032 section 7.1 TEST 1
(`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`). It is a test key
only and must never be accepted by a production key store.
