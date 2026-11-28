"""Generate conformance/vectors/policy/*.json from the frozen oracle.

The oracle's gateway/policy.py and gateway/engine.py are loaded by file path. policy.py
needs only the standard library. engine.py is executed with stub modules for its
kernel/store/UI imports, so `GatewayAuthorityPDP.evaluate` and `parse_action` run as
written; only `action_fingerprint` and the approval store are stubbed (the approval
answer is a vector input).

Path handling depends on `os.name` and the environment. Each case names a flavour
("posix" or "nt") and a fixed environment; the generator swaps policy.py's `os` for
that flavour and sets `os.environ` while the case runs. On a Windows host the "nt"
flavour uses the real C `ntpath`; "posix" uses `posixpath` (no `pwd`, so `~user` is
left alone). Environment names in posix cases are upper case, because a Windows host's
os.environ is case-insensitive.

Vectors are append-only: an existing file with different content is an error.

Run:  python -B -I conformance/gen/policy_from_oracle.py
Does not write into oracle/.
"""

from __future__ import annotations

import importlib.util
import json
import math
import ntpath
import os
import posixpath
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "oracle" / "decision-os-min" / "decision_os_min"
OUT = ROOT / "conformance" / "vectors" / "policy"
SRC = "oracle decision_os_min/gateway/policy.py"
SRC_ENGINE = "oracle decision_os_min/gateway/engine.py GatewayAuthorityPDP"


def load(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# --- load the oracle ---------------------------------------------------------
pkg = types.ModuleType("decision_os_min")
pkg.__path__ = [str(PKG)]
sys.modules["decision_os_min"] = pkg
gw = types.ModuleType("decision_os_min.gateway")
gw.__path__ = [str(PKG / "gateway")]
sys.modules["decision_os_min.gateway"] = gw

compose = load("decision_os_min.compose", PKG / "compose.py")
policy = load("decision_os_min.gateway.policy", PKG / "gateway" / "policy.py")


def stub(name: str, **attrs) -> None:
    m = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(m, k, v)
    sys.modules[name] = m


class _Any:
    def __init__(self, *a, **k):
        pass


stub("decision_os_min.authority_pdp", CanonicalAuthorityResult=dict)
stub("decision_os_min.execute", ExecutionRefused=Exception, Executor=_Any)
stub(
    "decision_os_min.kernel",
    Kernel=_Any,
    UnfingerprintablePayload=Exception,
    action_fingerprint=lambda a: "fp",
)
stub("decision_os_min.spentstore", SqliteSpentStore=_Any)
stub(
    "decision_os_min.gateway.approvals",
    APPROVED="approved",
    ApprovalStore=_Any,
    LearnedStore=_Any,
    ensure_dashboard=lambda *a, **k: None,
    notify=lambda *a, **k: None,
)
stub("decision_os_min.gateway.audit", LockedHashLog=_Any)
stub("decision_os_min.gateway.guardrails", Guardrails=_Any, redact_secrets=lambda s: s)
stub("decision_os_min.gateway.locking", file_lock=_Any)
stub("decision_os_min.gateway.paths", Home=_Any, write_private=lambda *a: None)
engine = load("decision_os_min.gateway.engine", PKG / "gateway" / "engine.py")

REAL_OS = policy.os

ENV_POSIX = {"HOME": "/home/alice", "PROJ": "/srv/proj", "EMPTY": ""}
ENV_NT = {
    "USERPROFILE": "C:\\Users\\Alice",
    "USERNAME": "Alice",
    "APPDATA": "C:\\Users\\Alice\\AppData\\Roaming",
    "PROJ": "D:\\proj",
}


class flavour:
    def __init__(self, name: str, env: dict[str, str]):
        self.name, self.env = name, env

    def __enter__(self):
        self.saved = dict(os.environ)
        os.environ.clear()
        os.environ.update(self.env)
        policy.os = types.SimpleNamespace(
            name=self.name, path=posixpath if self.name == "posix" else ntpath, environ=os.environ
        )

    def __exit__(self, *exc):
        policy.os = REAL_OS
        os.environ.clear()
        os.environ.update(self.saved)


def env_for(fl: str) -> dict[str, str]:
    return ENV_POSIX if fl == "posix" else ENV_NT


# --- result shapes -----------------------------------------------------------
def summary(p) -> dict:
    return {
        "mode": p.mode,
        "profile": p.profile,
        # JSON has no infinity: non-finite timeouts are written as Python repr text.
        "ask_timeout_seconds": t if math.isfinite(t := float(p.ask_timeout_seconds)) else repr(t),
        "hide_denied_tools": p.hide_denied_tools,
        "notify": p.notify,
        "open_dashboard": p.open_dashboard,
        "dashboard_port": int(p.dashboard_port),
        "guardrails": {
            "enabled": p.guardrails.enabled,
            "levels": [list(x) for x in p.guardrails.levels],
            "extra_protected_paths": list(p.guardrails.extra_protected_paths),
        },
        "rules": [
            {
                "index": r.index,
                "decision": r.decision,
                "client": r.client,
                "server": r.server,
                "tool": r.tool,
                "model": r.model,
                "args": [[k, list(v)] for k, v in r.args],
                "reason": r.reason,
                "redact": list(r.redact),
                "describe": r.describe(),
            }
            for r in p.rules
        ],
        "upstreams": [list(x) for x in p.upstreams],
        "revision": p.revision,
    }


def do_parse(inp: dict) -> dict:
    try:
        return {"ok": summary(policy.parse_policy(inp["text"]))}
    except policy.PolicyError as exc:
        msg = str(exc)
        if msg.startswith("policy.toml: invalid TOML: "):
            return {"error": "policy.invalid-toml"}
        return {"error": msg}


def do_evaluate(inp: dict) -> dict:
    p = policy.parse_policy(inp["policy"])
    with flavour(inp["flavor"], inp["env"]):
        m = policy.evaluate(
            p,
            client=inp["client"],
            server=inp["server"],
            tool=inp["tool"],
            model=inp["model"],
            args=inp["args"],
            hints=tuple(inp["hints"]),
            learned=inp["learned"],
        )
    return {
        "ok": {
            "decision": m.decision,
            "purpose": m.purpose,
            "reason": m.reason,
            "redact": list(m.redact),
            "source": m.source,
        }
    }


def do_classify(inp: dict) -> dict:
    return {"ok": policy.classify_tool(inp["name"], tuple(inp["hints"]))}


def do_normalize(inp: dict) -> dict:
    with flavour(inp["flavor"], inp["env"]):
        return {"ok": policy.normalize_path(inp["path"])}


def do_slug(inp: dict) -> dict:
    return {"ok": engine.slug(inp["name"])}


def do_pdp(inp: dict) -> dict:
    if inp["policy"] is None:
        p, err = None, inp["policy_error"]
    else:
        p, err = policy.parse_policy(inp["policy"]), None
    learned = inp["learned"]
    fake = types.SimpleNamespace(
        policy=p,
        policy_error=err,
        learned=types.SimpleNamespace(load=lambda: learned, revision=lambda: "r"),
        approvals=types.SimpleNamespace(is_approved=lambda fp: inp["approved"]),
    )
    pdp = engine.GatewayAuthorityPDP(fake)
    with flavour(inp["flavor"], inp["env"]):
        out = pdp.evaluate(inp["action"])
    return {"ok": {"verdict": out["verdict"], "reason": out["reason"]}}


OPS = {
    "parse": do_parse,
    "evaluate": do_evaluate,
    "classify": do_classify,
    "normalize_path": do_normalize,
    "slug": do_slug,
    "pdp": do_pdp,
}

# --- cases -------------------------------------------------------------------
CASES: list[tuple[str, dict, str]] = []


def case(name: str, inp: dict, source: str = SRC) -> None:
    CASES.append((name, inp, source))


# parse: the oracle's own rejection table, then every validation branch.
TEST_PG = "oracle tests/gateway/test_policy_guardrails.py"
for i, (bad, _) in enumerate(
    [
        ('mode = "loud"', "mode"),
        ("typo_setting = 1", "unknown setting"),
        ('[[rule]]\ntool = "x"', "decision"),
        ('[[rule]]\ntool = "x"\ndecision = "allow"\nwhen = 1', "unknown field"),
        ('[[rule]]\ntool = "x"\ndecision = "deny"\nredact = ["a"]', "redact"),
        ('[guardrails]\nprotected_paths = "maybe"', "guardrails.protected_paths"),
        ('[llm.upstreams]\nx = "ftp://nope"', "http"),
        ("this is not toml", "invalid TOML"),
    ],
    start=1,
):
    case(f"parse-oracle-reject-{i}", {"op": "parse", "text": bad}, TEST_PG)

for prof in policy.PROFILES:
    for mode in policy.MODES:
        case(
            f"parse-template-{prof}-{mode}",
            {"op": "parse", "text": policy.default_policy_text(prof, mode)},
            TEST_PG,
        )

PARSE = {
    "empty": "",
    "mode-observe": 'mode = "observe"',
    "mode-upper": 'mode = "ENFORCE"',
    "mode-int": "mode = 3",
    "mode-list": 'mode = ["enforce"]',
    "mode-quote-in-value": "mode = \"it's\"",
    "mode-bool": "mode = true",
    "mode-float": "mode = 1.5",
    "mode-table": "mode = { a = 1 }",
    "profile-bad": 'profile = "paranoid"',
    "profile-unicode": 'profile = "str\\u0131ct"',
    "unknown-two-sorted": "zeta = 1\nalpha = 2",
    "unknown-with-quote": "\"it's\" = 1",
    "timeout-zero": "ask_timeout_seconds = 0",
    "timeout-negative": "ask_timeout_seconds = -1",
    "timeout-float": "ask_timeout_seconds = 2.5",
    "timeout-int": "ask_timeout_seconds = 30",
    "timeout-bool": "ask_timeout_seconds = true",
    "timeout-string": 'ask_timeout_seconds = "10"',
    "timeout-nan": "ask_timeout_seconds = nan",
    "timeout-inf": "ask_timeout_seconds = inf",
    "port-zero": "dashboard_port = 0",
    "port-max": "dashboard_port = 65535",
    "port-over": "dashboard_port = 65536",
    "port-float": "dashboard_port = 80.0",
    "port-true": "dashboard_port = true",
    "port-false": "dashboard_port = false",
    "flag-notify-false": "notify = false",
    "flag-notify-string": 'notify = "no"',
    "flag-hide-int": "hide_denied_tools = 0",
    "flag-open-dashboard-false": "open_dashboard = false",
    "guardrails-not-table": "guardrails = 1",
    "guardrails-unknown": "[guardrails]\nfoo = 1\nbar = 2",
    "guardrails-enabled-false": "[guardrails]\nenabled = false",
    "guardrails-enabled-string": '[guardrails]\nenabled = "yes"',
    "guardrails-level-off": '[guardrails]\nrisky_commands = "off"\nsecret_files = "deny"',
    "guardrails-level-int": "[guardrails]\nsecret_files = 1",
    "guardrails-extra-ok": '[guardrails]\nextra_protected_paths = ["~/vault", "C:\\\\secret"]',
    "guardrails-extra-int": "[guardrails]\nextra_protected_paths = [1]",
    "guardrails-extra-string": '[guardrails]\nextra_protected_paths = "~/vault"',
    "rule-table-not-array": '[rule]\ndecision = "allow"',
    "rule-array-of-int": "rule = [1]",
    "rule-decision-upper": '[[rule]]\ndecision = "ALLOW"',
    "rule-decision-int": "[[rule]]\ndecision = 1",
    "rule-client-int": '[[rule]]\ndecision = "allow"\nclient = 1',
    "rule-model-list": '[[rule]]\ndecision = "allow"\nmodel = ["gpt"]',
    "rule-reason-bool": '[[rule]]\ndecision = "allow"\nreason = false',
    "rule-args-string": '[[rule]]\ndecision = "allow"\nargs = "x"',
    "rule-args-empty-list": '[[rule]]\ndecision = "allow"\nargs = { path = [] }',
    "rule-args-int": '[[rule]]\ndecision = "allow"\nargs = { path = 1 }',
    "rule-args-list-mixed": '[[rule]]\ndecision = "allow"\nargs = { path = ["a", 1] }',
    "rule-redact-string": '[[rule]]\ndecision = "allow"\nredact = "x"',
    "rule-redact-ok": '[[rule]]\ndecision = "ask"\ntool = "send"\nredact = ["body", "to"]',
    "rule-redact-empty-on-deny": '[[rule]]\ndecision = "deny"\nredact = []',
    "rule-second-bad": '[[rule]]\ndecision = "allow"\n[[rule]]\ndecision = "maybe"',
    "rule-unknown-two": '[[rule]]\ndecision = "allow"\nwhen = 1\nalso = 2',
    "rule-full": (
        '[[rule]]\nclient = "claude-code"\nserver = "github"\ntool = "create_*"\n'
        'model = "gpt-*"\nargs = { repo = ["me/*", "team/*"], branch = "main" }\n'
        'decision = "ask"\nreason = "review first"\n'
    ),
    "rule-describe-everything": '[[rule]]\ndecision = "allow"',
    "rule-describe-empty-model": '[[rule]]\ndecision = "allow"\nmodel = ""',
    "llm-not-table": "llm = 1",
    "llm-unknown": "[llm]\nproxies = {}",
    "llm-upstream-override": '[llm.upstreams]\nopenai = "https://proxy.example/v1///"',
    "llm-upstream-new": '[llm.upstreams]\nwork = "http://gw.example"',
    "llm-upstream-bad-name": '[llm.upstreams]\n"bad name" = "https://x"',
    "llm-upstream-bad-url-and-name": '[llm.upstreams]\n"bad name" = "ftp://x"',
    "llm-upstream-int": "[llm.upstreams]\nx = 1",
    "llm-upstream-upper-scheme": '[llm.upstreams]\nx = "HTTPS://x"',
    "llm-upstreams-empty-string": '[llm]\nupstreams = ""',
    "duplicate-key": 'mode = "enforce"\nmode = "observe"',
    "bad-toml-unclosed": "[guardrails",
}
for name, text in PARSE.items():
    case(f"parse-{name}", {"op": "parse", "text": text})

# classify
TEST_NAMES = [
    "read_file", "list_directory", "getIssue", "search_code", "browser_snapshot", "write_file",
    "create_pull_request", "run_command", "Bash", "delete_branch", "get_or_create_user", "frobnicate",
]
for n in TEST_NAMES:
    case(f"classify-oracle-{n}", {"op": "classify", "name": n, "hints": []}, TEST_PG)
for ci, (n, hints) in enumerate([
    ("frobnicate", ["hint:readonly"]),
    ("write_file", ["hint:readonly"]),
    ("read_file", ["hint:destructive"]),
    ("frobnicate", ["HINT:ReadOnly"]),
    ("frobnicate", ["hint:destructive", "hint:readonly"]),
    ("HTTPGet", []),
    ("getHTTPResponse", []),
    ("file2Write", []),
    ("READ_FILE", []),
    ("ReadFile", []),
    ("readfile", []),
    ("read-file", []),
    ("read.file", []),
    ("\u212aill", []),
    ("caf\u00e9_get", []),
    ("", []),
    ("x__ls__y", []),
    ("SHELL", []),
    ("tools/call", []),
    ("browser_navigate", []),
    ("browserClick", []),
    ("\u0130nfo", []),
]):
    tag = "".join(c if c.isascii() and c.isalnum() else "_" for c in n) or "empty"
    case(f"classify-{ci:02d}-{tag}",{"op": "classify", "name": n, "hints": hints})

# normalize_path
PATHS = [
    "~", "~/.ssh/id_rsa", "~alice/x", "~bob/x", "/etc/../etc/./passwd", "//net/share", "///abs",
    "./rel/../x", "../up", "a/b/../../..", "file:///etc/passwd", "file://~/x", "$HOME/x",
    "${HOME}/x", "$PROJ$PROJ", "${MISSING}/x", "$MISSING/x", "$", "${", "%USERPROFILE%\\x",
    "%MISSING%/x", "%%", "100%", "'%PROJ%'/x", "'$PROJ", "$$x", "C:\\Users\\Alice\\..\\Bob",
    "c:/x/./y", "C:x\\y", "\\\\server\\share\\a\\..\\b", "\\\\server", "/a//b///c/", "",
    "~/Projects/README.md", "%APPDATA%\\..\\Local", "$EMPTY/x", "/x/\u00c9t\u00e9",
]
for fl in ("posix", "nt"):
    for i, pth in enumerate(PATHS):
        case(
            f"normalize-{fl}-{i:02d}",
            {"op": "normalize_path", "path": pth, "flavor": fl, "env": env_for(fl)},
        )

# slug
for i, n in enumerate(["filesystem", " my server ", "a/b:c\\d", "a  //  b", "", "   ", "x\ty\nz", "\u3000x\u3000"]):
    case(f"slug-{i:02d}", {"op": "slug", "name": n}, SRC_ENGINE)

# evaluate
P_GITHUB = """
[[rule]]
server = "github"
tool = "*"
args = { repo = ["me/*", "team/public-*"] }
decision = "allow"

[[rule]]
server = "github"
decision = "deny"
"""
P_PATHS = """
[[rule]]
server = "filesystem"
tool = "write_file"
args = { path = "~/projects/*" }
decision = "allow"

[[rule]]
tool = "*delete*"
decision = "deny"
reason = "nothing gets deleted by an agent"

[[rule]]
client = "claude-code"
server = "llm"
tool = "Bash"
decision = "ask"

[[rule]]
tool = "send_*"
decision = "ask"
redact = ["token"]
"""
P_ARGS = """
[[rule]]
tool = "t"
args = { n = "4*", flag = "true", nothing = "null", obj = '{"a":1*', list = "[1,*", f = "1e+*" }
decision = "allow"
"""
P_ARGS_SINGLE = """
[[rule]]
tool = "num"
args = { n = "42" }
decision = "allow"

[[rule]]
tool = "flt"
args = { f = ["2.0", "1e-07", "Infinity", "NaN"] }
decision = "allow"

[[rule]]
tool = "b"
args = { v = ["true", "null"] }
decision = "allow"

[[rule]]
tool = "o"
args = { v = ['{"a":"\\u00e9","b":[1,2]}', '["x",{"k":null}]'] }
decision = "allow"

[[rule]]
tool = "case"
args = { v = "HELLO*" }
decision = "allow"

[[rule]]
tool = "set"
args = { v = ["[abc]x", "[!0-9]y", "[z-a]q", "a[b"] }
decision = "allow"
"""
P_MODEL = """
profile = "strict"

[[rule]]
model = "gpt-4*"
tool = "Bash"
decision = "deny"

[[rule]]
model = ""
tool = "Read"
decision = "allow"
"""
P_OPEN = 'profile = "open"\n[[rule]]\ntool = "rm"\ndecision = "deny"\n'
P_STRICT = 'profile = "strict"\n'
P_LEARN = '[[rule]]\ntool = "move_*"\ndecision = "ask"\n[[rule]]\ntool = "rm"\ndecision = "deny"\n'

EV = []  # (policy, client, server, tool, model, args, hints, learned)
for repo in ["me/x", "team/public-site", "other/x", "ME/X", "me", "team/public-", "me/x/y"]:
    EV.append((P_GITHUB, "c", "github", "create_issue", None, {"repo": repo}, [], {}))
EV += [
    (P_GITHUB, "c", "github", "create_issue", None, None, [], {}),
    (P_GITHUB, "c", "github", "create_issue", None, {}, [], {}),
    (P_GITHUB, "c", "github", "create_issue", None, {"repo": 5}, [], {}),
    (P_GITHUB, "c", "GitHub", "list_repos", None, {"repo": "me/y"}, [], {}),
    (P_GITHUB, "c", "gitlab", "list_repos", None, {}, [], {}),
    (P_GITHUB, "c", "gitlab", "push", None, {}, [], {}),
]
for pth in [
    "~/projects/a.txt", "/home/alice/projects/a/b.txt", "/home/alice/projects/../.ssh/id_rsa",
    "/home/alice/Projects/x", "~/projectsX", "file:///home/alice/projects/x", "projects/x",
    "C:\\Users\\Alice\\projects\\x", "c:/users/alice/projects/x", "$HOME/projects/x",
    "%USERPROFILE%\\projects\\x",
]:
    for fl in ("posix", "nt"):
        EV.append((P_PATHS, "c", "filesystem", "write_file", None, {"path": pth}, [], {}, fl))
EV += [
    (P_PATHS, "c", "filesystem", "write_file", None, {"path": ["~/projects/x"]}, [], {}),
    (P_PATHS, "c", "filesystem", "write_file", None, {"path": None}, [], {}),
    (P_PATHS, "c", "filesystem", "delete_file", None, {}, [], {"c|filesystem|delete_file": "allow"}),
    (P_PATHS, "c", "filesystem", "safeDeleteAll", None, {}, [], {}),
    (P_PATHS, "claude-code", "llm", "Bash", None, {"command": "ls"}, [], {}),
    (P_PATHS, "claude-code", "llm", "bash", None, {"command": "ls"}, [], {}),
    (P_PATHS, "cursor", "llm", "Bash", None, {"command": "ls"}, [], {}),
    (P_PATHS, "c", "mail", "send_email", None, {"token": "x"}, [], {}),
    (P_PATHS, "c", "mail", "send_email", None, {}, [], {"c|mail|send_email": "allow"}),
    (P_PATHS, "c", "mail", "send_email", None, {}, [], {"*|mail|send_email": "allow"}),
    (P_PATHS, "c", "mail", "send_email", None, {}, [], {"c|mail|send_email": "maybe", "*|mail|send_email": "deny"}),
    (P_PATHS, "c", "mail", "read_inbox", None, {}, [], {}),
    (P_PATHS, "c", "mail", "frobnicate", None, {}, [], {}),
    (P_PATHS, "c", "mail", "frobnicate", None, {}, ["hint:readOnly"], {}),
    (P_PATHS, "c", "mail", "read_inbox", None, {}, ["hint:destructive"], {}),
    (P_PATHS, "c", "mail", "read_inbox", None, {}, [], {"c|mail|read_inbox": "deny"}),
]
for n in [42, 4, 420, -4, 4.5, True, False, None, {"a": 1}, {"a": 10, "b": 2}, [1, 2], [2, 1], 1e16, 1.5e-7]:
    EV.append((P_ARGS, "c", "s", "t", None, {"n": n, "flag": True, "nothing": None, "obj": {"a": 1}, "list": [1, 2], "f": 1e20}, [], {}))
EV += [
    (P_ARGS_SINGLE, "c", "s", "num", None, {"n": 42}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "num", None, {"n": 42.0}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "num", None, {"n": "42"}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "flt", None, {"f": 2.0}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "flt", None, {"f": 2}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "flt", None, {"f": 1e-7}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "b", None, {"v": True}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "b", None, {"v": None}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "b", None, {"v": "TRUE"}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "o", None, {"v": {"b": [1, 2], "a": "\u00e9"}}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "o", None, {"v": ["x", {"k": None}]}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "case", None, {"v": "hello world"}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "case", None, {"v": "HeLLo"}, [], {}),
    (P_ARGS_SINGLE, "c", "s", "case", None, {"v": "say hello"}, [], {}),
]
for v in ["ax", "dx", "ay", "5y", "qq", "q", "a[b", "ab"]:
    EV.append((P_ARGS_SINGLE, "c", "s", "set", None, {"v": v}, [], {}))
for model in [None, "gpt-4o", "GPT-4-turbo", "gpt-3.5", ""]:
    EV.append((P_MODEL, "c", "llm", "Bash", model, {}, [], {}))
    EV.append((P_MODEL, "c", "llm", "Read", model, {}, [], {}))
EV += [
    (P_OPEN, "c", "s", "rm", None, {}, [], {"c|s|rm": "allow"}),
    (P_OPEN, "c", "s", "write_file", None, {}, [], {}),
    (P_STRICT, "c", "s", "read_file", None, {}, [], {}),
    (P_STRICT, "c", "s", "read_file", None, {}, [], {"c|s|read_file": "allow"}),
    (P_LEARN, "c", "fs", "move_file", None, {}, [], {}),
    (P_LEARN, "c", "fs", "move_file", None, {}, [], {"c|fs|move_file": "allow"}),
    (P_LEARN, "c", "fs", "move_file", None, {}, [], {"c|fs|move_file": "deny"}),
    (P_LEARN, "c", "fs", "rm", None, {}, [], {"c|fs|rm": "allow", "*|fs|rm": "allow"}),
    (P_LEARN, "c", "fs", "write_file", None, {}, [], {"*|fs|write_file": "allow"}),
    ("", "c", "s", "\u212aill_process", None, {}, [], {}),
    ("", "c", "s", "Stat\u0130stics", None, {}, [], {}),
]
for i, e in enumerate(EV):
    pol, client, server, tool, model, args, hints, learned = e[:8]
    fl = e[8] if len(e) > 8 else "posix"
    case(
        f"evaluate-{i:03d}",
        {
            "op": "evaluate",
            "policy": pol,
            "flavor": fl,
            "env": env_for(fl),
            "client": client,
            "server": server,
            "tool": tool,
            "model": model,
            "args": args,
            "hints": hints,
            "learned": learned,
        },
    )

# pdp
P_PDP = """
[[rule]]
tool = "write_file"
decision = "ask"

[[rule]]
tool = "rm"
decision = "deny"
"""


def act(tool, purpose, payload=None, labels=(), actor="agent:c"):
    return {
        "actor": actor,
        "tool": tool,
        "capability": f"tool:{tool}",
        "action_purpose": purpose,
        "data_labels": list(labels),
        "payload": payload,
        "nonce": "n",
    }


PDP = [
    (P_PDP, None, act("fs/write_file", "rule:1"), {}, False),
    (P_PDP, None, act("fs/write_file", "rule:1"), {}, True),
    (P_PDP, None, act("fs/write_file", "rule:2"), {}, True),
    (P_PDP, None, act("fs/write_file", None), {}, True),
    (P_PDP, None, act("fs/rm", "rule:2"), {}, True),
    (P_PDP, None, act("fs/rm", "rule:2"), {"c|fs|rm": "allow"}, True),
    (P_PDP, None, act("fs/read_file", "profile:balanced:read"), {}, False),
    (P_PDP, None, act("fs/frob", "profile:balanced:unknown"), {}, False),
    (P_PDP, None, act("fs/frob", "profile:balanced:read", labels=["hint:readonly"]), {}, False),
    (P_PDP, None, act("fs/write_file", "rule:1"), {"c|fs|write_file": "allow"}, False),
    (P_PDP, None, act("fs/write_file", "rule:1", actor="c"), {"c|fs|write_file": "allow"}, False),
    (P_PDP, None, act("fs/write_file", "rule:1", actor="agent:other"), {"c|fs|write_file": "allow"}, False),
    (P_PDP, None, act("nofolder", "profile:balanced:unknown"), {}, False),
    (P_PDP, None, act("a/b/c", "profile:balanced:unknown"), {}, False),
    ('mode = "observe"\n' + P_PDP, None, act("fs/rm", "rule:2"), {}, False),
    ('mode = "observe"\n' + P_PDP, None, act("fs/write_file", "rule:1"), {}, False),
    ('mode = "observe"\n' + P_PDP, None, act("fs/read_file", "profile:balanced:read"), {}, False),
    ('mode = "observe"\n' + P_PDP, None, act("fs/write_file", "rule:9"), {}, False),
    (None, "x.toml: invalid TOML: boom", act("fs/read_file", "profile:balanced:read"), {}, True),
    (
        '[[rule]]\nmodel = "gpt*"\ntool = "Bash"\ndecision = "deny"\n',
        None,
        act("llm/Bash", "rule:1", labels=["hint:x", "model:gpt-4o", "model:other"]),
        {},
        True,
    ),
    (
        '[[rule]]\ntool = "w"\nargs = { p = "/tmp/*" }\ndecision = "allow"\n',
        None,
        act("fs/w", "rule:1", payload={"p": "/tmp/x"}),
        {},
        False,
    ),
    (
        '[[rule]]\ntool = "w"\nargs = { p = "/tmp/*" }\ndecision = "allow"\n',
        None,
        act("fs/w", "rule:1", payload={"p": "/tmp/../etc/x"}),
        {},
        False,
    ),
    (
        '[[rule]]\ntool = "w"\nargs = { p = "/tmp/*" }\ndecision = "allow"\n',
        None,
        act("fs/w", "profile:balanced:write", payload={"p": "/etc/x"}),
        {},
        False,
    ),
]
for i, (pol, err, action, learned, approved) in enumerate(PDP):
    case(
        f"pdp-{i:02d}",
        {
            "op": "pdp",
            "policy": pol,
            "policy_error": err,
            "action": action,
            "learned": learned,
            "approved": approved,
            "flavor": "posix",
            "env": ENV_POSIX,
        },
        SRC_ENGINE,
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    names = set()
    written = same = 0
    for name, inp, source in CASES:
        assert name not in names, name
        names.add(name)
        expected = OPS[inp["op"]](inp)
        vec = {"v": 1, "area": "policy", "name": name, "input": inp, "expected": expected, "source": source}
        text = json.dumps(vec, ensure_ascii=True, indent=2) + "\n"
        path = OUT / f"{name}.json"
        if path.exists():
            if path.read_text(encoding="utf-8") != text:
                print(f"REFUSING to change existing vector {path.name}", file=sys.stderr)
                return 1
            same += 1
            continue
        path.write_text(text, encoding="utf-8", newline="\n")
        written += 1
    print(f"{len(CASES)} cases: {written} written, {same} unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
