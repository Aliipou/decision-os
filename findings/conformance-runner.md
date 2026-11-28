# Red team: conformance-runner (branch task/conformance-runner, 9cbc137)

## First-pass hypotheses (written before reading design/ and status/)

Ranked by impact. "Pass-forging" = a wrong implementation gets exit 0.

| # | Hypothesis | Class |
|---|---|---|
| H1 | Vectors placed where REDTEAM.md says (`conformance/vectors/redteam/`) form an area `redteam` that no adapter implements and no manifest requires: every adapter answers `unsupported` and the run PASSES, so lock-in vectors check nothing. | pass-forging |
| H2 | More generally: any area not in a manifest's `required` passes with `unsupported` for every case; both manifests require only `selftest`; nothing ties "an area has vectors" to "the Rust adapter must support it". A Rust adapter that answers `unsupported` for everything except `selftest` passes the whole gate. | pass-forging |
| H3 | `run.sh --changed-since` (the local gate) exits 0 "nothing to run" where `--all` exits 2: non-ASCII vector file names (git quotes them, the sed does not match), a stray file directly under `conformance/vectors/`, a deleted area, a `.gitattributes` change. | gate skip |
| H4 | Number comparison: two lexemes with the same exact value compare unequal, or different values compare equal (exponent forms, -0, exponent with leading zeros, exponents near 10^15, many digits, trailing zeros in the fraction). | comparator |
| H5 | String comparison: escaped vs raw, surrogate pair escaped vs raw astral, lone surrogates, NFC/NFD; duplicate keys written with different escapes (`"a"` vs `"a"`) slip past the duplicate check. | comparator |
| H6 | Request re-serialisation (`json::write`) changes a value (round trip not identity), so the adapter is asked a different question than the vector states. | comparator |
| H7 | Memory / disk exhaustion by the adapter: every FAIL keeps the full `got` value (up to 16 MiB per case) and the JSON report writes all of them. | resource |
| H8 | Process handling: a grandchild that keeps pipes open hangs the runner, or survives the runner (orphan); on Windows handle inheritance makes a correct adapter that spawns a helper FAIL. | hang / portability |
| H9 | Adapter output steering the report: stderr echoed raw (with newlines) on FAIL can print a fake `result: PASS`; raw control/ESC bytes from a malformed line reach the terminal. | log spoofing |
| H10 | Timeouts: per-case sleeps just under the timeout blow the overall budget without being killed; an infinite stream of extra lines after the last response keeps the runner looping past the deadline. | hang |
| H11 | Line framing: infinite line without newline, huge lines, binary, CR variants, BOM, two responses on one line, responses for a different `name`, extra output after the last line, early exit 0. | protocol |
| H12 | Manifest attacks: `command` with `..` or absolute paths, `required: []`, `oracle: true` on a non-oracle adapter (it is then judged against `oracle_expected`). | config |
| H13 | Vector-file attacks: symlinks / junctions out of the tree, non-UTF-8 names, `.json` directories, FIFOs, huge files, BOM, CRLF, case collisions. | loader |
| H14 | Oracle adapter: a legitimate vector (integer with more than 4300 digits) makes Python's `json.loads` raise, the adapter exits 2 and every later case is MISSING (a whole-run refusal for one case). | adapter robustness |
| H15 | Zero-case areas or zero selected cases pass. | verdict |

Results for every hypothesis are in the tables at the end.
