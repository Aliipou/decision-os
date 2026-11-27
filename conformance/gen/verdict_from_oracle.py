"""Generate conformance/vectors/meet/*.json from the frozen oracle.

Each case is computed twice: by the oracle (decision_os_min.compose) and by an
independent model of spec/verdict.md written below. `expected` is the spec model;
when the oracle differs, its answer is recorded as `oracle_expected` and printed.

Vectors are append-only. An existing file with different content is an error, never
overwritten. A random differential (default 200000 strings) also runs the spec model
against the oracle's `normalize`; it writes nothing, it only fails loudly.

Run from anywhere:  python3 -B -P conformance/gen/verdict_from_oracle.py
Needs the oracle's import deps (cryptography). Does not write into oracle/.
"""

from __future__ import annotations

import itertools
import json
import random
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # never leave __pycache__ inside oracle/

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "oracle" / "decision-os-min"))

import importlib  # noqa: E402

# The package re-exports a `compose` FUNCTION, so import the module by its full name.
oracle = importlib.import_module("decision_os_min.compose")

OUT = ROOT / "conformance" / "vectors" / "meet"

# --- spec model (spec/verdict.md), independent of the oracle -----------------
WIRE = ["ALLOW", "LIMIT", "CONTAIN", "DEFER", "DENY"]  # least -> most restrictive


def spec_parse(s: str) -> str:
    return s if s in WIRE else "DENY"


def spec_meet(a: str, b: str) -> str:
    a, b = spec_parse(a), spec_parse(b)
    return a if WIRE.index(a) >= WIRE.index(b) else b


def spec_compose(vs: list[str]) -> str:
    out = "ALLOW"
    for v in vs:
        out = spec_meet(out, v)
    return out


# --- cases ------------------------------------------------------------------
RT1 = "oracle tests/test_redteam_composition.py"
PROPS = "oracle tests/test_compose_properties.py"

# (name, string, source). Every one is outside the vocabulary except where noted.
PARSE_CASES = [
    ("allow", "ALLOW", "spec wire string"),
    ("limit", "LIMIT", "spec wire string"),
    ("contain", "CONTAIN", "spec wire string"),
    ("defer", "DEFER", "spec wire string"),
    ("deny", "DENY", "spec wire string"),
    ("empty", "", PROPS + " off_lattice (empty text)"),
    ("space", " ", PROPS + " off_lattice"),
    ("lower-deny", "deny", RT1 + " _forging_plugin default verdict"),
    ("lower-allow", "allow", PROPS + " docstring: foreign vocabulary 'allow'"),
    ("lower-limit", "limit", "case variant"),
    ("lower-contain", "contain", "case variant"),
    ("lower-defer", "defer", "case variant"),
    ("title-allow", "Allow", "case variant"),
    ("mixed-allow", "aLLOW", "case variant"),
    ("title-deny", "Deny", "case variant"),
    ("permit", "permit", PROPS + " docstring: foreign vocabulary 'permit'"),
    ("permit-upper", "PERMIT", "foreign vocabulary (XACML)"),
    ("wat", "WAT", PROPS + " F1 counterexample"),
    ("allowed", "ALLOWED", "prefix match must not count"),
    ("allo", "ALLO", "truncation"),
    ("a", "A", "single letter"),
    ("trailing-space", "ALLOW ", "whitespace is not trimmed"),
    ("leading-space", " ALLOW", "whitespace is not trimmed"),
    ("trailing-newline", "ALLOW\n", "line-based transport residue"),
    ("trailing-crlf", "ALLOW\r\n", "Windows line ending residue"),
    ("leading-tab", "\tLIMIT", "whitespace is not trimmed"),
    ("contain-cr", "CONTAIN\r", "carriage return"),
    ("trailing-nul", "ALLOW\u0000", "C string truncation attack"),
    ("nul", "\u0000", "NUL only"),
    ("bom", "﻿ALLOW", "byte order mark prefix"),
    ("zwsp-suffix", "ALLOW​", "zero-width space suffix"),
    ("zwsp-prefix", "​ALLOW", "zero-width space prefix"),
    ("zwj-inside", "AL‍LOW", "zero-width joiner inside"),
    ("nbsp-suffix", "ALLOW ", "no-break space suffix"),
    ("line-separator", " ALLOW", "U+2028 prefix"),
    ("fullwidth-allow", "ＡＬＬＯＷ", "fullwidth lookalike (NFKC folds to ALLOW)"),
    ("fullwidth-limit-mix", "ＬIMIT", "partly fullwidth"),
    ("cyrillic-a", "АLLOW", "Cyrillic A homoglyph"),
    ("greek-alpha", "ΑLLOW", "Greek Alpha homoglyph"),
    ("cyrillic-contain", "СОNTAIN", "Cyrillic C and O homoglyphs"),
    ("dotted-i-limit", "LİMİT", "Turkish dotted capital I"),
    ("dotless-i-limit", "lımıt", "Turkish dotless i (upper() folds to LIMIT)"),
    ("combining-acute", "ALLOẂ", "combining mark suffix"),
    ("math-bold-allow", "\U0001d400\U0001d40b\U0001d40b\U0001d40e\U0001d416", "math bold lookalike"),
    ("quoted", "\"ALLOW\"", "JSON-quoted string"),
    ("list-like", "ALLOW,DENY", "list smuggling"),
    ("two-words", "ALLOW DENY", "two words"),
    ("concat", "ALLOWDENY", "concatenation"),
    ("null-text", "null", "JSON null as text"),
    ("none-text", "None", "Python None as text"),
    ("true-text", "true", "boolean as text"),
    ("zero", "0", "rank as text"),
    ("four", "4", "rank as text"),
    ("star", "*", "wildcard"),
    ("escaped-nul-text", "ALLOW\\u0000", "literal backslash escape text"),
]

COMPOSE_CASES = [
    ("empty", [], "compose([]) == ALLOW, the identity (oracle compose docstring)"),
    ("single-allow", ["ALLOW"], PROPS + " every element reachable"),
    ("single-limit", ["LIMIT"], PROPS + " every element reachable"),
    ("single-contain", ["CONTAIN"], PROPS + " every element reachable"),
    ("single-defer", ["DEFER"], PROPS + " every element reachable"),
    ("single-deny", ["DENY"], PROPS + " every element reachable"),
    ("single-off-lattice", ["deny"], RT1 + " fixed1"),
    ("single-empty-string", [""], "empty string verdict"),
    ("all-allow", ["ALLOW", "ALLOW", "ALLOW"], "identity"),
    ("allow-limit-contain", ["ALLOW", "LIMIT", "CONTAIN"], "permitting chain"),
    ("contain-limit-allow", ["CONTAIN", "LIMIT", "ALLOW"], "permutation of the above"),
    ("limit-contain", ["LIMIT", "CONTAIN"], "obligation non-claim: LIMIT and CONTAIN gives CONTAIN"),
    ("deny-last", ["ALLOW", "ALLOW", "DENY"], "one veto anywhere"),
    ("deny-first", ["DENY", "ALLOW", "ALLOW"], "one veto anywhere"),
    ("deny-middle", ["ALLOW", "DENY", "ALLOW"], "one veto anywhere"),
    ("defer-among-permitting", ["LIMIT", "DEFER", "CONTAIN"], "DEFER is not permitting"),
    ("off-lattice-with-allow", ["ALLOW", "WAT"], PROPS + " ALLOW with off-lattice is DENY"),
    ("off-lattice-first", ["WAT", "ALLOW"], PROPS + " F1 commutativity"),
    ("off-lattice-with-deny", ["WAT", "DENY"], PROPS + " F1 verbatim DENY"),
    ("lowercase-allow-only", ["allow", "allow"], "case variants never permit"),
    ("lookalike-in-chain", ["ALLOW", "АLLOW", "LIMIT"], "homoglyph in a chain"),
    ("nul-in-chain", ["LIMIT", "LIMIT\u0000"], "NUL suffix in a chain"),
    ("long-permitting", ["ALLOW", "LIMIT"] * 8, "16 permitting verdicts"),
    ("long-with-one-deny", ["ALLOW"] * 15 + ["DENY"], "16 verdicts, last one vetoes"),
]


def oracle_for(inp: dict) -> str:
    op = inp["op"]
    if op == "meet":
        return oracle.meet(inp["a"], inp["b"])
    if op == "parse":
        return oracle.normalize(inp["s"])
    if op == "compose":
        return oracle.compose(inp["verdicts"])
    raise ValueError(op)


def spec_for(inp: dict) -> str:
    op = inp["op"]
    if op == "meet":
        return spec_meet(inp["a"], inp["b"])
    if op == "parse":
        return spec_parse(inp["s"])
    if op == "compose":
        return spec_compose(inp["verdicts"])
    raise ValueError(op)


def build() -> list[dict]:
    cases = []
    for a, b in itertools.product(WIRE, WIRE):
        cases.append((f"meet-{a.lower()}-{b.lower()}", {"op": "meet", "a": a, "b": b},
                      "spec 5x5 meet table"))
    cases.append(("meet-offlattice-deny", {"op": "meet", "a": "WAT", "b": "DENY"},
                  PROPS + " F1: meet(x, DENY) == DENY verbatim"))
    cases.append(("meet-deny-offlattice", {"op": "meet", "a": "DENY", "b": "WAT"},
                  PROPS + " F1"))
    cases.append(("meet-allow-offlattice", {"op": "meet", "a": "ALLOW", "b": "allow"},
                  PROPS + " ALLOW with off-lattice is DENY"))
    cases.append(("meet-offlattice-offlattice", {"op": "meet", "a": "allow", "b": "permit"},
                  "two foreign dialects"))
    for name, s, src in PARSE_CASES:
        cases.append((f"parse-{name}", {"op": "parse", "s": s}, src))
    for name, vs, src in COMPOSE_CASES:
        cases.append((f"compose-{name}", {"op": "compose", "verdicts": vs}, src))

    out, seen = [], set()
    for name, inp, src in cases:
        if name in seen:
            raise SystemExit(f"duplicate vector name {name}")
        seen.add(name)
        want, got = spec_for(inp), oracle_for(inp)
        vec = {"v": 1, "area": "meet", "name": name, "input": inp,
               "expected": {"ok": want}}
        if got != want:
            vec["oracle_expected"] = {"ok": got}
            print(f"DIVERGENCE {name}: spec {want}, oracle {got}")
        vec["source"] = src
        out.append(vec)
    return out


def random_differential(n: int) -> None:
    rng = random.Random(20261126)
    pools = [
        lambda: rng.choice(WIRE),
        lambda: "".join(chr(rng.randint(32, 126)) for _ in range(rng.randint(0, 8))),
        lambda: "".join(chr(rng.randint(0, 0x10FFFF)) for _ in range(rng.randint(0, 4))),
        lambda: mutate(rng.choice(WIRE)),
    ]

    def mutate(w: str) -> str:
        i = rng.randint(0, len(w))
        c = rng.choice([" ", "\u0000", "​", "﻿", w[i - 1].lower() if i else "a"])
        return w[:i] + c + w[i:] if rng.random() < 0.5 else w[:i] + w[i + 1:]

    bad = 0
    for _ in range(n):
        s = rng.choice(pools)()
        if oracle.normalize(s) != spec_parse(s):
            bad += 1
            print(f"DIVERGENCE random parse {s!r}: oracle {oracle.normalize(s)}")
        t = rng.choice(pools)()
        if oracle.meet(s, t) != spec_meet(s, t):
            bad += 1
            print(f"DIVERGENCE random meet {s!r} {t!r}")
    if bad:
        raise SystemExit(f"{bad} random divergences")
    print(f"random differential: {n} parse + {n} meet cases, 0 divergences")


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200000
    OUT.mkdir(parents=True, exist_ok=True)
    written = same = 0
    for vec in build():
        text = json.dumps(vec, ensure_ascii=True, indent=2) + "\n"
        path = OUT / f"{vec['name']}.json"
        if path.exists():
            if path.read_text(encoding="utf-8") != text:
                raise SystemExit(f"{path} exists with different content (append-only)")
            same += 1
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        written += 1
    print(f"vectors: {written} written, {same} unchanged, total {written + same}")
    random_differential(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
