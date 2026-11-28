"""Conformance adapter for the decision-os-min oracle (spec/CONFORMANCE.md).

Reads one request per line on stdin, writes one response per line on stdout, in order,
and exits 0 at EOF. Run through ./adapter (python3 -I -B), never with -m and never from
inside oracle/: nothing is imported from the working directory and no bytecode is
written, so the frozen oracle tree stays untouched.

Areas:
  selftest  {"op": "echo", "value": v} -> {"ok": v};  {"op": "error", "code": c} -> {"error": c}
  meet      {"op": "meet", "a": x, "b": y}       -> {"ok": compose.meet(x, y)}
            {"op": "parse", "s": x}              -> {"ok": compose.normalize(x)}
            {"op": "compose", "verdicts": [...]} -> {"ok": compose.compose([...])}
Anything else answers {"unsupported": true}. Wrong input fields answer
{"error": "invalid_input"}, an unknown op {"error": "unknown_op"}, and an exception
raised by the oracle {"error": "oracle_exception"} (details on stderr).

`compose.py` is loaded by file path rather than through the package: the package
__init__ imports the kernel and needs `cryptography`, which the frozen full-gate CI job
does not install, while compose.py imports nothing internal (it says so). Same file,
same behaviour. Areas that need the kernel later can `import decision_os_min` (the
oracle directory is on sys.path, as with PYTHONPATH=oracle/decision-os-min).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

# Python refuses to parse or print an integer of more than 4300 digits. A legitimate echo
# vector with one must not take the adapter down for every later case (red team H14).
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

ROOT = Path(__file__).resolve().parents[3]
ORACLE = ROOT / "oracle" / "decision-os-min"
COMPOSE_PY = ORACLE / "decision_os_min" / "compose.py"
sys.path.insert(0, str(ORACLE))


def _load_compose():
    spec = importlib.util.spec_from_file_location("decision_os_min.compose", COMPOSE_PY)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {COMPOSE_PY}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if "decision_os_min" in sys.modules:
        raise ImportError("compose.py pulled in the decision_os_min package; load path changed")
    return module


compose = _load_compose()


class InvalidInput(Exception):
    pass


def _fields(inp, *keys):
    if not isinstance(inp, dict) or set(inp) != {"op", *keys}:
        raise InvalidInput
    return [inp[k] for k in keys]


def area_selftest(inp):
    op = inp.get("op") if isinstance(inp, dict) else None
    if op == "echo":
        (value,) = _fields(inp, "value")
        return {"ok": value}
    if op == "error":
        (code,) = _fields(inp, "code")
        if not isinstance(code, str) or not code:
            raise InvalidInput
        return {"error": code}
    if not isinstance(op, str):
        raise InvalidInput
    return {"error": "unknown_op"}


def area_meet(inp):
    op = inp.get("op") if isinstance(inp, dict) else None
    if op == "meet":
        a, b = _fields(inp, "a", "b")
        return {"ok": compose.meet(a, b)}
    if op == "parse":
        (s,) = _fields(inp, "s")
        return {"ok": compose.normalize(s)}
    if op == "compose":
        (verdicts,) = _fields(inp, "verdicts")
        if not isinstance(verdicts, list):
            raise InvalidInput
        return {"ok": compose.compose(verdicts)}
    if not isinstance(op, str):
        raise InvalidInput
    return {"error": "unknown_op"}


AREAS = {
    "selftest": area_selftest,
    "meet": area_meet,
}


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _no_constants(name):
    raise ValueError(f"non-JSON constant {name}")


def answer(line: str) -> str:
    req = json.loads(line, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    if not isinstance(req, dict) or set(req) != {"area", "name", "input"}:
        raise ValueError("request must be exactly {area, name, input}")
    name = req["name"]
    handler = AREAS.get(req["area"])
    if handler is None:
        output = {"unsupported": True}
    else:
        try:
            output = handler(req["input"])
        except InvalidInput:
            output = {"error": "invalid_input"}
        except Exception as e:  # the oracle raised: report it, keep the stream in sync
            print(f"oracle exception in {name}: {type(e).__name__}: {e}", file=sys.stderr)
            output = {"error": "oracle_exception"}
    try:
        return json.dumps({"name": name, "output": output}, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        print(f"unserializable output in {name}: {e}", file=sys.stderr)
        return json.dumps({"name": name, "output": {"error": "oracle_exception"}}, separators=(",", ":"))


def main() -> int:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    for raw in stdin:
        if not raw.endswith(b"\n"):
            print("adapter: request line without newline", file=sys.stderr)
            return 2
        try:
            line = raw.decode("utf-8")
            reply = answer(line)
        except (UnicodeDecodeError, ValueError) as e:
            print(f"adapter: malformed request: {e}", file=sys.stderr)
            return 2
        stdout.write(reply.encode("ascii") + b"\n")
        stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
