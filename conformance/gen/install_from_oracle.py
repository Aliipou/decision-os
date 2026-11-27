#!/usr/bin/env python3
"""Generate conformance/vectors/install/*.json by running the frozen oracle installer.

Run from the repository root, never with a real HOME (every case gets its own
throwaway HOME, APPDATA, LOCALAPPDATA and XDG_CONFIG_HOME):

    PYTHONPATH=oracle/decision-os-min python3 -P conformance/gen/install_from_oracle.py

Nothing is written under oracle/ (no bytecode either). The vector format and the
normalization of the wrapped entry are specified in spec/install.md.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64  # noqa: E402
import copy  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import types  # noqa: E402
from pathlib import Path  # noqa: E402

from decision_os_min.gateway import clients, installer  # noqa: E402
from decision_os_min.gateway.paths import Home  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
ORACLE = REPO / "oracle" / "decision-os-min"
assert Path(installer.__file__).resolve().is_relative_to(ORACLE), installer.__file__
OUT = REPO / "conformance" / "vectors" / "install"

BIN = "/opt/decision-os/bin/decision-os"
BIN_WIN = "C:\\Program Files\\Decision OS\\decision-os.exe"
BIN_ODD = "/opt/dé cision \"os\"/decision-os"
HOME_PLACEHOLDER = "@DOS_HOME@"
MODULE = installer.MODULE
ENV_VARS = (
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME",
    "CODEX_HOME", "COPILOT_HOME", "DECISION_OS_HOME", "HOMEDRIVE", "HOMEPATH",
)

# ------------------------------------------------------------------ helpers


def lit(s: str) -> str:
    """A string as the oracle writes it, in JSON and in TOML (json.dumps, no ASCII escaping)."""
    return json.dumps(s, ensure_ascii=False)


SEP = r"(\s*,\s*)"
PREFIX_RX = re.compile(
    re.escape(lit("-P")) + SEP + re.escape(lit("-m")) + SEP + re.escape(lit(MODULE)) + SEP
    + re.escape(lit("--home")) + SEP + re.escape(lit(HOME_PLACEHOLDER)) + SEP
    + re.escape(lit("mcp-proxy")) + SEP
)


def normalize(data: bytes | None, home: str) -> bytes | None:
    """Oracle bytes -> the bytes the Rust installer must write (spec/install.md)."""
    if data is None:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    text = text.replace(lit(home), lit(HOME_PLACEHOLDER))
    text = PREFIX_RX.sub(
        lambda m: lit("mcp-proxy") + m.group(4) + lit("--home") + m.group(5)
        + lit(HOME_PLACEHOLDER) + m.group(6),
        text,
    )
    return text.encode("utf-8")


def blob(data: bytes | None) -> dict | None:
    if data is None:
        return None
    try:
        return {"text": data.decode("utf-8")}
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(data).decode("ascii")}


CODES = [
    ("(original restored byte for byte)", "restored-exact"),
    ("file contains comments", "jsonc"),
    ("not valid JSON", "invalid-json"),
    ("top level is not an object", "not-object"),
    ("verification failed: non-server content changed", "verify-failed"),
    ("args is not a list of strings; skipped", "args-not-strings"),
    ("wrapped entry has no original command", "no-original-command"),
    ("not valid TOML", "invalid-toml"),
    ("uses an inline transport table", "inline-transport"),
    ("wrap by hand", "not-plain-table"),
    ("could not locate its table", "table-not-found"),
    ("edit produced invalid TOML", "edit-invalid-toml"),
    ("verification failed", "verify-failed"),
]


def code(message: str) -> str | None:
    if not message:
        return None
    for needle, c in CODES:
        if needle in message:
            return c
    if message.startswith("[Errno"):
        return "read-error"
    raise SystemExit(f"unmapped oracle message: {message!r}")


def report(r: installer.FileReport) -> dict:
    return {
        "status": r.status,
        "wrapped": list(r.wrapped),
        "already": list(r.already),
        "plain": list(r.plain),
        "remote": list(r.remote),
        "unwrapped": list(r.unwrapped),
        "message": code(r.message),
    }


def set_env(user: Path) -> None:
    for v in ENV_VARS:
        os.environ.pop(v, None)
    os.environ["HOME"] = str(user)
    os.environ["USERPROFILE"] = str(user)
    os.environ["APPDATA"] = str(user / "AppData" / "Roaming")
    os.environ["LOCALAPPDATA"] = str(user / "AppData" / "Local")
    os.environ["XDG_CONFIG_HOME"] = str(user / ".config")


# ------------------------------------------------------------------ run cases

VECTORS: list[dict] = []


def run_case(
    name: str,
    *,
    client: str,
    path: str,
    before: bytes | None,
    steps: list[dict],
    project: bool = False,
    binary: str = BIN,
    mode: int | None = None,
    symlink: str | None = None,
    source: str,
    patch: dict | None = None,
) -> list[dict]:
    """Run the oracle on one config file through a list of steps.

    path is relative to the fake user directory, or to the project directory when
    project is set. A step is {"action", "dry_run", "force_jsonc"} or {"app_write": f}
    where f maps the current file bytes to what the app writes.
    """
    saved = {k: getattr(installer, k) for k in (patch or {})}
    for k, v in (patch or {}).items():
        setattr(installer, k, v)
    tmp = Path(tempfile.mkdtemp(prefix="dosgen-"))
    try:
        user = tmp / "user"
        user.mkdir()
        set_env(user)
        home = Home(user / ".decision-os")
        proj = tmp / "proj"
        base = proj if project else user
        target = base / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if before is not None:
            if symlink:
                real = user / symlink
                real.parent.mkdir(parents=True, exist_ok=True)
                real.write_bytes(before)
                target.symlink_to(real)
            else:
                target.write_bytes(before)
            if mode is not None:
                os.chmod(target, mode)
        out = []
        for st in steps:
            if "app_write" in st:
                cur = target.read_bytes()
                new = st["app_write"](cur)
                if mode is not None:
                    os.chmod(target, 0o644)
                target.write_bytes(new)
                if mode is not None:
                    os.chmod(target, mode)
                out.append({"app_write": blob(normalize(new, str(home.root)))})
                continue
            rec: dict = {}
            try:
                reps = installer.run(
                    home,
                    st["action"],
                    clients=[client],
                    project=proj if project else None,
                    dry_run=st.get("dry_run", False),
                    force_jsonc=st.get("force_jsonc", False),
                    python=binary,
                )
                mine = [r for r in reps if r.path == target]
                assert len(mine) == 1, (name, [str(r.path) for r in reps])
                rec["report"] = report(mine[0])
            except Exception as exc:  # the oracle crashed: recorded, never hidden
                rec["crash"] = type(exc).__name__
            data = target.read_bytes() if target.exists() else None
            rec["file"] = blob(normalize(data, str(home.root)))
            if symlink:
                rec["symlink"] = target.is_symlink()
            out.append(rec)
        return out
    finally:
        for k, v in saved.items():
            setattr(installer, k, v)
        for p in tmp.rglob("*"):
            try:
                os.chmod(p, 0o700 if p.is_dir() else 0o600, follow_symlinks=False)
            except (OSError, NotImplementedError):
                pass
        shutil.rmtree(tmp)


def vector(
    name: str,
    *,
    client: str,
    path: str,
    before: bytes | None,
    steps: list[dict],
    source: str,
    project: bool = False,
    binary: str = BIN,
    mode: int | None = None,
    symlink: str | None = None,
    rust: dict | None = None,
    rust_patch: dict | None = None,
    why: str | None = None,
) -> None:
    """Record one vector. rust (explicit step overrides by index) or rust_patch (oracle
    functions replaced by their spec'd versions) marks a deliberate divergence."""
    kw = dict(client=client, path=path, before=before, steps=steps, project=project,
              binary=binary, mode=mode, symlink=symlink, source=source)
    oracle = run_case(name, **kw)
    expected = copy.deepcopy(oracle)
    if rust_patch:
        expected = run_case(name, **kw, patch=rust_patch)
    if rust:
        for i, over in rust.items():
            base = {k: v for k, v in expected[i].items() if not ("report" in over and k == "crash")}
            expected[i] = {**base, **over}
    inp = {
        "kind": "run",
        "client": client,
        "project": project,
        "path": path,
        "binary": binary,
        "before": blob(before),
        "steps": [
            {"app_write": o["app_write"]} if "app_write" in s else
            {k: s.get(k, False) for k in ("action", "dry_run", "force_jsonc")} | {"action": s["action"]}
            for s, o in zip(steps, oracle)
        ],
    }
    if mode is not None:
        inp["mode"] = mode
    if symlink:
        inp["symlink_to"] = symlink
    vec = {"v": 1, "area": "install", "name": name, "input": inp,
           "expected": {"ok": {"steps": [strip_app(e) for e in expected]}}}
    for e, o in zip(expected, oracle):
        assert ("app_write" in e) == ("app_write" in o) and e.get("app_write") == o.get("app_write"), name
    if expected != oracle:
        assert why, f"{name}: divergence without a reason"
        vec["oracle_expected"] = {"ok": {"steps": [strip_app(e) for e in oracle]}}
        vec["divergence"] = why
    elif why:
        raise SystemExit(f"{name}: marked as divergence but Rust expects the oracle bytes")
    vec["source"] = source
    VECTORS.append(vec)


def strip_app(step: dict) -> dict:
    return {"app_write": True} if "app_write" in step else step


I = {"action": "install"}
U = {"action": "uninstall"}
S = {"action": "status"}


def dumps(obj, **kw) -> bytes:
    return json.dumps(obj, **kw).encode("utf-8")


def edit_json(fn, **dump):
    def f(cur: bytes) -> bytes:
        d = json.loads(cur.decode("utf-8"))
        fn(d)
        return json.dumps(d, **dump).encode("utf-8")
    return f


def append(extra: bytes):
    return lambda cur: cur + extra


# ------------------------------------------------------------------ fixtures (test_installer.py)

DESKTOP = {
    "mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/w"]},
        "github": {"command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"],
                   "env": {"GITHUB_TOKEN": "x"}},
        "linear": {"url": "https://mcp.linear.app/sse"},
    },
    "globalShortcut": "Ctrl+Space",
}
CLAUDE_CODE = {
    "numStartups": 7,
    "mcpServers": {"memory": {"type": "stdio", "command": "npx", "args": ["-y", "@mcp/memory"]}},
    "projects": {
        "/w/app": {"mcpServers": {"db": {"command": "uvx", "args": ["mcp-db"]}}, "allowedTools": []},
        "/w/empty": {"mcpServers": {}},
    },
}
VSCODE_JSONC = """{
  // my servers
  "servers": {
    "playwright": { "type": "stdio", "command": "npx", "args": ["@playwright/mcp@latest"], },
    "remote": { "type": "http", "url": "https://example.com/mcp" }
  },
  "inputs": []
}
"""
CODEX = """# Codex config
model = "gpt-5"

[mcp_servers.context7]
command = "npx"   # docs
args = [
  "-y",
  "@upstash/context7-mcp",
]

[mcp_servers.context7.env]
DEBUG = "1"

[mcp_servers."my-shell"]
command = "/usr/local/bin/shell-mcp"

[mcp_servers.remote]
url = "https://mcp.example.com/mcp"

[profiles.fast]
model = "gpt-5-mini"
"""
DESKTOP_PATH = ".config/Claude/claude_desktop_config.json"
T = "oracle tests/gateway/test_installer.py"


def later_edit(d):
    d["mcpServers"]["added-later"] = {"command": "node", "args": ["srv.js"]}
    d["globalShortcut"] = "Alt+Space"


def build() -> None:
    desk = dumps(DESKTOP, indent=2) + b"\n"
    vector("desktop-install-idempotent-restore", client="claude-desktop", path=DESKTOP_PATH,
           before=desk, steps=[I, I, U],
           source=f"{T}::test_install_wraps_every_stdio_server_and_keeps_everything_else")
    vector("desktop-app-edit-unwraps-entry-by-entry", client="claude-desktop", path=DESKTOP_PATH,
           before=desk, steps=[I, {"app_write": edit_json(later_edit)}, U],
           source=f"{T}::test_uninstall_after_the_app_edited_its_config_unwraps_entry_by_entry")
    cc = dumps(CLAUDE_CODE)
    vector("claude-code-projects-restore", client="claude-code", path=".claude.json",
           before=cc, steps=[I, I, S, U], source=f"{T}::test_install_wraps_every_stdio_server")
    vector("claude-code-projects-app-edit", client="claude-code", path=".claude.json", before=cc,
           steps=[I, {"app_write": edit_json(lambda d: d.update(numStartups=8), indent=2)}, U],
           source=f"{T} (claude-code shape, entry-by-entry)")
    cur = dumps({"mcpServers": {"fs": {"command": "npx -y fs-mcp"}}}, indent=4)
    vector("cursor-command-string-restore", client="cursor", path=".cursor/mcp.json", before=cur,
           steps=[I, U], source=f"{T}::test_cursor_command_string_and_codex_args_absent_round_trip")
    vector("cursor-command-string-app-edit-no-args-invented", client="cursor", path=".cursor/mcp.json",
           before=cur, steps=[I, {"app_write": append(b"\n")}, U],
           source=f"{T}::test_cursor_command_string_and_codex_args_absent_round_trip")
    vs = VSCODE_JSONC.encode()
    vector("vscode-jsonc-refused", client="vscode", path=".config/Code/User/mcp.json", before=vs,
           steps=[I, S, U], source=f"{T}::test_install_wraps_every_stdio_server (vscode manual)")
    vector("vscode-jsonc-forced-restores-comments", client="vscode", path=".config/Code/User/mcp.json",
           before=vs, steps=[{"action": "install", "force_jsonc": True}, U],
           source=f"{T}::test_force_jsonc_and_dry_run")
    vector("vscode-jsonc-forced-app-edit", client="vscode", path=".config/Code/User/mcp.json",
           before=vs, steps=[{"action": "install", "force_jsonc": True},
                             {"app_write": edit_json(lambda d: d.update(inputs=[1]), indent=2)}, U],
           source=f"{T}::test_force_jsonc_and_dry_run, then entry-by-entry")
    vector("dry-run-install-writes-nothing", client="claude-desktop", path=DESKTOP_PATH, before=desk,
           steps=[{"action": "install", "dry_run": True}, S], source=f"{T}::test_force_jsonc_and_dry_run")
    vector("dry-run-uninstall-writes-nothing", client="claude-desktop", path=DESKTOP_PATH, before=desk,
           steps=[I, {"action": "uninstall", "dry_run": True}, U], source="dry run of uninstall")
    codex = CODEX.encode()
    vector("codex-install-idempotent-restore", client="codex", path=".codex/config.toml", before=codex,
           steps=[I, I, S, U], source=f"{T}::test_install_wraps_every_stdio_server (codex)")
    vector("codex-app-edit-no-args-invented", client="codex", path=".codex/config.toml", before=codex,
           steps=[I, {"app_write": append(b"\n# touched\n")}, U],
           source=f"{T}::test_cursor_command_string_and_codex_args_absent_round_trip")
    pg = dumps({"mcpServers": {"pg": {"command": "uvx", "args": ["pg-mcp"]}}})
    for cid, rel, body in (
        ("claude-code", ".mcp.json", pg),
        ("cursor", ".cursor/mcp.json", pg),
        ("vscode", ".vscode/mcp.json", dumps({"servers": {"pg": {"type": "stdio", "command": "uvx", "args": ["pg-mcp"]}}}, indent=2)),
        ("gemini-cli", ".gemini/settings.json", dumps({"theme": "x", "mcpServers": {"pg": {"command": "uvx"}}}, indent=2) + b"\n"),
        ("kiro", ".kiro/settings/mcp.json", pg),
        ("codex", ".codex/config.toml", b'[mcp_servers.pg]\ncommand = "uvx"\nargs = ["pg-mcp"]\n'),
    ):
        vector(f"project-{cid}", client=cid, path=rel, before=body, project=True,
               steps=[I, U], source=f"{T}::test_project_install")
    # every other global client, one file each
    for cid, rel in (
        ("copilot", ".copilot/mcp-config.json"),
        ("windsurf", ".codeium/windsurf/mcp_config.json"),
        ("gemini-cli", ".gemini/settings.json"),
        ("lm-studio", ".lmstudio/mcp.json"),
        ("kiro", ".kiro/settings/mcp.json"),
        ("amazon-q", ".aws/amazonq/mcp.json"),
        ("cline", ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
        ("roo-code", ".config/Code - Insiders/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"),
    ):
        body = dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs"], "disabled": False,
                                            "autoApprove": []}}}, indent=2)
        vector(f"client-{cid}", client=cid, path=rel, before=body, steps=[I, U],
               source="oracle clients.py registry")

    # ---------------------------------------------------------------- JSON edge cases
    simple = {"mcpServers": {"a": {"command": "npx", "args": ["-y", "a"]}}}
    vector("json-bom-refused", client="claude-desktop", path=DESKTOP_PATH,
           before=b"\xef\xbb\xbf" + dumps(simple, indent=2), steps=[I, U], source="REDTEAM installer: BOM")
    crlf = dumps(DESKTOP, indent=2).replace(b"\n", b"\r\n") + b"\r\n"
    vector("json-crlf-restore", client="claude-desktop", path=DESKTOP_PATH, before=crlf, steps=[I, U],
           source="REDTEAM installer: CRLF")
    vector("json-crlf-app-edit", client="claude-desktop", path=DESKTOP_PATH, before=crlf,
           steps=[I, {"app_write": edit_json(later_edit, indent=2)}, U], source="REDTEAM installer: CRLF")
    tc = b'{\n  "mcpServers": {\n    "a": {"command": "npx", "args": ["a",],},\n  },\n}\n'
    vector("json-trailing-commas-refused", client="claude-desktop", path=DESKTOP_PATH, before=tc,
           steps=[I, U], source="REDTEAM installer: trailing commas")
    vector("json-trailing-commas-forced", client="claude-desktop", path=DESKTOP_PATH, before=tc,
           steps=[{"action": "install", "force_jsonc": True}, U], source="REDTEAM installer: trailing commas")
    cm = (b'/* header */\n{\n  "mcpServers": { // line\n    "a": {"command": "npx", /* why */ "args": ["//not", "/*no*/"]}\n'
          b'  },\n  "x": "http://u"\n}\n')
    vector("json-comments-forced-restore", client="claude-desktop", path=DESKTOP_PATH, before=cm,
           steps=[{"action": "install", "force_jsonc": True}, S, U], source="REDTEAM installer: comments")
    vector("json-comments-forced-app-edit", client="claude-desktop", path=DESKTOP_PATH, before=cm,
           steps=[{"action": "install", "force_jsonc": True}, {"app_write": append(b" ")},
                  {"action": "uninstall", "force_jsonc": True}], source="REDTEAM installer: comments")
    jsc = b'{\n  // c\n  "mcpServers": {"a": {"command": "npx", "args": ["x,}", "y, ]"]}}\n}\n'
    vector("json-jsonc-string-with-comma-brace", client="claude-desktop", path=DESKTOP_PATH, before=jsc,
           steps=[{"action": "install", "force_jsonc": True}, U],
           rust_patch={"strip_jsonc": strip_jsonc_fixed},
           why="the oracle's trailing-comma regex also edits string contents (\"x,}\" becomes \"x}\"); "
               "Rust removes only trailing commas outside strings",
           source="REDTEAM installer: comments; oracle strip_jsonc regex")
    dup = (b'{\n  "mcpServers": {\n    "a": {"command": "old", "args": []},\n    "b": {"command": "npx", "command": "uvx"},\n'
           b'    "a": {"command": "npx", "args": ["new"]}\n  },\n  "k": 1,\n  "k": 2\n}\n')
    vector("json-duplicate-keys", client="claude-desktop", path=DESKTOP_PATH, before=dup,
           steps=[I, U], source="REDTEAM installer: duplicate keys")
    vector("json-duplicate-keys-app-edit", client="claude-desktop", path=DESKTOP_PATH, before=dup,
           steps=[I, {"app_write": append(b"\n")}, U], source="REDTEAM installer: duplicate keys")
    vector("json-empty-file", client="claude-desktop", path=DESKTOP_PATH, before=b"", steps=[I, U],
           source="REDTEAM installer: empty file")
    vector("json-whitespace-only", client="claude-desktop", path=DESKTOP_PATH,
           before=" \n\t\r\n\x0b\x1c\u3000".encode(), steps=[I], source="oracle text.strip()")
    vector("json-invalid", client="claude-desktop", path=DESKTOP_PATH, before=b'{"mcpServers": {', steps=[I, U],
           source="REDTEAM installer: invalid JSON")
    vector("json-top-level-array", client="claude-desktop", path=DESKTOP_PATH, before=b"[1, 2]\n", steps=[I],
           source="oracle not-object")
    vector("json-missing-file", client="claude-desktop", path=DESKTOP_PATH, before=None, steps=[I, U],
           source="oracle missing")
    big = {"zzz": ["%06d" % i for i in range(20000)], "mcpServers": {}}
    for i in range(300):
        big["mcpServers"][f"s{i:03d}"] = {"command": "npx", "args": ["-y", f"pkg-{i}"], "env": {"N": str(i)}}
    vector("json-huge-file", client="claude-desktop", path=DESKTOP_PATH, before=dumps(big, indent=2) + b"\n",
           steps=[I, U], source="REDTEAM installer: huge file")
    uni = {"mcpServers": {"файлы": {"command": "npx", "args": ["ü"]}, "🔧 tools": {"command": "t"},
                          "名前": {"command": "n", "env": {"ключ": "значение"}}}}
    vector("json-unicode-server-names", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(uni, indent=2, ensure_ascii=False), steps=[I, {"app_write": append(b"\n")}, U],
           source="task: unicode server names")
    vector("json-unicode-escaped-input", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(uni, indent=2), steps=[I, U], source="\\u escapes are written back as UTF-8 by the oracle")
    odd = {"mcpServers": {"my server": {"command": "a"}, 'say "hi"': {"command": "b"},
                          "back\\slash": {"command": "c"}, "tab\tname": {"command": "d"}, "-": {"command": "e"}}}
    vector("json-server-names-spaces-quotes", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(odd, indent=2), steps=[I, {"app_write": append(b"\n")}, U],
           source="task: server names with spaces and quotes")
    dd = {"mcpServers": {"--": {"command": "npx", "args": ["-y", "srv"]}}}
    vector("json-server-named-double-dash", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(dd, indent=2), steps=[I, {"app_write": append(b"\n")}, U],
           rust_patch={"unwrap_args": unwrap_args_positional},
           why="the oracle unwraps after the first '--', which is the server name here, and writes "
               "command '--'; Rust parses the wrapped entry by position",
           source="REDTEAM installer: unwrapping; server named --")
    sp = {"mcpServers": {"a": {"command": "/opt/my tools/run server",
                               "args": ["--root", "/path with spaces", 'a"b', "", "-", "--", "--x=1", "ü", "\\\\srv\\share", "$HOME", "`x`"]}}}
    vector("json-args-with-spaces-and-dashes", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(sp, indent=2) + b"\n", steps=[I, {"app_write": append(b"\n")}, U],
           source="task: args with spaces")
    envb = {"mcpServers": {"a": {"command": "npx", "args": ["a"], "env": {"TOKEN": "t", "EMPTY": ""},
                                 "cwd": "/w", "type": "stdio", "timeout": 30, "alwaysAllow": ["x"]},
                           "b": {"env": {"A": "1"}, "args": ["first"], "command": "node"}}}
    vector("json-env-and-other-keys-preserved", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(envb, indent=2), steps=[I, {"app_write": append(b"\n")}, U],
           source="installer docstring: every other key is kept")
    dis = {"mcpServers": {"off": {"command": "npx", "args": ["off"], "disabled": True},
                          "on": {"command": "npx", "disabled": False}}}
    vector("json-disabled-entries", client="claude-desktop", path=DESKTOP_PATH, before=dumps(dis, indent=2),
           steps=[I, U], source="task: disabled entries")
    pre = {"mcpServers": {
        "old": {"command": "/usr/bin/python3", "args": ["-P", "-m", MODULE, "--home", "/home/old/.decision-os",
                "mcp-proxy", "--client", "claude-desktop", "--server", "old", "--", "npx", "-y", "old"],
                "env": {"K": "v"}},
        "older": {"command": "python", "args": ["-m", MODULE, "--home", "/h", "mcp-proxy", "--client",
                  "claude-desktop", "--server", "older", "--", "uvx", "older"]},
        "new": {"command": "npx", "args": ["new"]}}}
    vector("json-already-wrapped-by-python", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(pre, indent=2), steps=[I, S, U],
           source="RUST_REWRITE Phase 5: unwrap entries written by the Python gateway")
    pre_rust = {"mcpServers": {
        "w": {"command": BIN, "args": ["mcp-proxy", "--home", "/h", "--client", "claude-desktop", "--server",
                                        "w", "--", "npx", "w"]}}}
    vector("json-already-wrapped-by-rust", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(pre_rust, indent=2), steps=[I, U],
           rust={0: {"report": {"status": "unchanged", "wrapped": [], "already": ["w"], "plain": [], "remote": [],
                                "unwrapped": [], "message": None}, "file": blob(dumps(pre_rust, indent=2))},
                 1: {"report": {"status": "ok", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": ["w"], "message": None},
                     "file": blob(dumps({"mcpServers": {"w": {"command": "npx", "args": ["w"]}}}, indent=2))}},
           why="the oracle does not know the Rust shape and wraps the entry a second time; Rust "
               "reports it as already governed and unwraps it",
           source="spec/install.md wrapped entry shape")
    rem = {"mcpServers": {
        "u": {"url": "https://a"}, "h": {"type": "http", "url": "https://b"}, "s": {"type": "SSE", "command": "x"},
        "sh": {"type": "streamable-http", "command": "x"}, "t": {"transport": "Streamable_HTTP", "command": "x"},
        "e": {"type": "", "transport": "remote", "command": "x"}, "su": {"serverUrl": "https://c"},
        "hu": {"httpUrl": "https://d", "command": "x"}, "n": {"url": None, "command": "x"},
        "num": {"type": 1, "transport": "http", "command": "x"}, "ok": {"type": "stdio", "command": "x"}}}
    vector("json-remote-entries-untouched", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(rem, indent=2), steps=[I, S, U], source="installer is_remote")
    bad = {"mcpServers": {"s": {"command": "x", "args": "notalist"}, "n": {"command": "x", "args": [1]},
                          "c": {"command": ["x"]}, "e": {"command": ""}, "none": {"args": ["x"]},
                          "nul": {"command": "x", "args": None}, "str": "x", "null": None, "ok": {"command": "y"}}}
    vector("json-odd-entries", client="claude-desktop", path=DESKTOP_PATH, before=dumps(bad, indent=2),
           steps=[I, S, {"app_write": append(b"\n")}, U], source="installer _process_json skips")
    vector("json-servers-not-object", client="claude-desktop", path=DESKTOP_PATH,
           before=b'{"mcpServers": [{"command": "x"}], "servers": {"a": {"command": "x"}}}', steps=[I],
           source="installer _server_tables")
    vector("json-read-only-file", client="claude-desktop", path=DESKTOP_PATH, before=dumps(simple, indent=2),
           mode=0o444, steps=[I, U],
           rust={0: {"report": {"status": "error", "wrapped": ["a"], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "read-only"}, "file": blob(dumps(simple, indent=2))},
                 1: {"report": {"status": "unchanged", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": None}, "file": blob(dumps(simple, indent=2))}},
           why="the oracle replaces a read-only file through rename on POSIX (and crashes on Windows); "
               "Rust refuses on every OS and leaves the file untouched",
           source="REDTEAM installer: read-only files")
    vector("json-symlinked-file", client="claude-desktop", path=DESKTOP_PATH, before=dumps(simple, indent=2),
           symlink="dotfiles/claude.json", steps=[I, U],
           rust={0: {"symlink": True}, 1: {"symlink": True}},
           why="the oracle's rename replaces the symlink with a regular file, so the link is lost; "
               "Rust writes the link target and keeps the link",
           source="REDTEAM installer: symlinked files")
    nums = (b'{"n": [0, -0, 1, -1, 12345678901234567890123, 1.0, 1.50, -0.0, 0.1, 1e5, 1E-5, 2.5e-7, 1e16, 1e17,'
            b' 123456789012345678.0, 5e-324, 1.7976931348623157e308, 0.0001, 0.00001, 1e-400, 3.141592653589793,'
            b' 100, 1e2, 9007199254740993, 0.30000000000000004], "mcpServers": {"a": {"command": "x"}}}')
    vector("json-numbers-python-format", client="claude-desktop", path=DESKTOP_PATH, before=nums, steps=[I, U],
           source="Python float repr and int formatting")
    vector("json-infinity-overflow", client="claude-desktop", path=DESKTOP_PATH,
           before=b'{"n": 1e400, "mcpServers": {"a": {"command": "x"}}}', steps=[I, U],
           rust={0: {"report": {"status": "error", "wrapped": ["a"], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "non-finite-number"},
                     "file": blob(b'{"n": 1e400, "mcpServers": {"a": {"command": "x"}}}')},
                 1: {"report": {"status": "unchanged", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": None},
                     "file": blob(b'{"n": 1e400, "mcpServers": {"a": {"command": "x"}}}')}},
           why="the oracle writes 1e400 back as Infinity, which is not JSON and breaks the app; Rust refuses",
           source="Python json allow_nan")
    nan = b'{"n": NaN, "i": -Infinity, "mcpServers": {"a": {"command": "x"}}}'
    vector("json-nan-literal", client="claude-desktop", path=DESKTOP_PATH, before=nan, steps=[I, U],
           rust={0: {"report": {"status": "error", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "invalid-json"}, "file": blob(nan)},
                 1: {"report": {"status": "error", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "invalid-json"}, "file": blob(nan)}},
           why="NaN and Infinity are not JSON; the oracle parses them and writes them back, which "
               "the apps cannot read; Rust refuses the file as invalid JSON",
           source="Python json allow_nan")
    esc = '{"mcpServers": {"a": {"command": "x\\u0001\\b\\f\\n\\r\\t\\"\\\\\\/\\u007f\\u2028\\u00e9\\ud83d\\ude00"}}}'.encode()
    vector("json-string-escapes", client="claude-desktop", path=DESKTOP_PATH, before=esc, steps=[I, U],
           source="Python json.dumps ensure_ascii=False escapes")
    sur = b'{"mcpServers": {"a": {"command": "x", "env": {"K": "\\ud800"}}}}'
    vector("json-lone-surrogate", client="claude-desktop", path=DESKTOP_PATH, before=sur, steps=[I, U],
           rust={0: {"report": {"status": "error", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "invalid-json"}, "file": blob(sur)},
                 1: {"report": {"status": "error", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "invalid-json"}, "file": blob(sur)}},
           why="a lone surrogate cannot be written as UTF-8: the oracle crashes mid-write (leaving a temp "
               "file); Rust refuses the file as invalid JSON",
           source="REDTEAM installer: unicode")
    bad_utf8 = b'{"mcpServers": {"a": {"command": "\xff"}}}'
    vector("json-invalid-utf8", client="claude-desktop", path=DESKTOP_PATH, before=bad_utf8, steps=[I],
           rust={0: {"report": {"status": "error", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "invalid-utf8"}, "file": blob(bad_utf8)}},
           why="the oracle crashes with UnicodeDecodeError and aborts the whole run; Rust reports this file",
           source="REDTEAM installer: encodings")
    deep = b'{"x": ' + b"[" * 200 + b"]" * 200 + b', "mcpServers": {"a": {"command": "x"}}}'
    vector("json-deep-nesting", client="claude-desktop", path=DESKTOP_PATH, before=deep, steps=[I],
           rust={0: {"report": {"status": "error", "wrapped": [], "already": [], "plain": [], "remote": [],
                                "unwrapped": [], "message": "invalid-json"}, "file": blob(deep)}},
           why="serde_json refuses nesting deeper than 128 (stack safety); the oracle accepts it",
           source="REDTEAM installer: huge files")
    tab = b'{\n\t"mcpServers": {\n\t\t"a": {"command": "x", "args": []}\n\t},\n\t"e": {},\n\t"l": []\n}\n'
    vector("json-tab-indent", client="claude-desktop", path=DESKTOP_PATH, before=tab, steps=[I, U],
           source="installer _indent")
    odd_indent = b'{"x": 1,\n\n   "mcpServers": {\n "a": {"command": "x"}}}'
    vector("json-indent-detection-first-indented-line", client="claude-desktop", path=DESKTOP_PATH,
           before=odd_indent, steps=[I, U], source="installer _indent")
    mixed = b'{\n \t "mcpServers": {"a": {"command": "x"}}\n}'
    vector("json-indent-mixed-space-tab", client="claude-desktop", path=DESKTOP_PATH, before=mixed,
           steps=[I, U], source="installer _indent")
    nul = {"mcpServers": {"a": {"command": "npx", "args": None, "env": None}}}
    vector("json-args-null-app-edit", client="claude-desktop", path=DESKTOP_PATH, before=dumps(nul, indent=2),
           steps=[I, {"app_write": append(b"\n")}, U], source="installer uninstall keeps args null")
    noorig = {"mcpServers": {"a": {"command": BIN, "args": ["-m", MODULE, "mcp-proxy", "--"]}}}
    vector("json-wrapped-without-original-command", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(noorig, indent=2), steps=[I, U], source="installer unwrap_args ValueError")
    for b, tag in ((BIN_WIN, "windows-binary-path"), (BIN_ODD, "binary-path-unicode-quotes")):
        vector(f"json-{tag}", client="claude-desktop", path=DESKTOP_PATH, before=dumps(simple, indent=2),
               binary=b, steps=[I, {"app_write": append(b"\n")}, U], source="wrapper command is the caller's binary")
    vector("json-status-only", client="claude-desktop", path=DESKTOP_PATH, before=desk, steps=[S],
           source="installer status")
    two = {"mcpServers": {"a": {"command": "x"}}}
    vector("json-install-after-app-added-server", client="claude-desktop", path=DESKTOP_PATH,
           before=dumps(two, indent=2), steps=[I, {"app_write": edit_json(
               lambda d: d["mcpServers"].update(b={"command": "y"}), indent=2)}, I, U],
           source="installer State.wrote: second write after an app edit drops the exact backup")
    vector("json-uninstall-without-install", client="claude-desktop", path=DESKTOP_PATH, before=desk,
           steps=[U, U], source="uninstall with nothing wrapped")

    # ---------------------------------------------------------------- Codex TOML edge cases
    P = ".codex/config.toml"

    def cx(name, text, steps=(I, U), **kw):
        vector(f"codex-{name}", client="codex", path=P, before=text if isinstance(text, bytes) else text.encode(),
               steps=list(steps), **kw)

    cx("crlf-restore", CODEX.replace("\n", "\r\n"), source="REDTEAM installer: CRLF (TOML)")
    cx("crlf-app-edit", CODEX.replace("\n", "\r\n"), steps=(I, {"app_write": append(b"\r\n# x\r\n")}, U),
       source="REDTEAM installer: CRLF (TOML)")
    cx("no-trailing-newline", '[mcp_servers.a]\ncommand = "x"', steps=(I, {"app_write": append(b" ")}, U),
       source="installer _edit_codex_server newline")
    cx("args-before-command", '[mcp_servers.a]\nargs = ["1"] # a\nenv = { K = "v" }\ncommand = \'x\'\n',
       steps=(I, {"app_write": append(b"\n")}, U), source="installer _edit_codex_server spans")
    cx("multiline-args-comments", '[mcp_servers.a]\n  command = "x"\n  args = [ # c\n    "a", # d\n    \'b\',\n  ] # e\n  enabled = true\n',
       steps=(I, {"app_write": append(b"\n")}, U), source="installer _statement_end")
    cx("quoted-names", '[mcp_servers."my server"]\ncommand = "a"\n[mcp_servers.\'lit\']\ncommand = "b"\n'
       '[ mcp_servers . "ü" ] # c\ncommand = "c"\n', steps=(I, {"app_write": append(b"\n")}, U),
       source="installer _header_rx")
    cx("inline-table-server", '[mcp_servers]\na = { command = "x" }\n', steps=(I,), source="installer manual")
    cx("dotted-keys-server", 'mcp_servers.a.command = "x"\n', steps=(I,), source="installer manual")
    cx("command-not-string", '[mcp_servers.a]\ncommand = ["x"]\n[mcp_servers.b]\ncommand = "y"\n', steps=(I, U),
       source="installer inline-transport")
    cx("invalid-toml", '[mcp_servers.a\ncommand = "x"\n', steps=(I,), source="REDTEAM installer: invalid TOML")
    cx("bom", b"\xef\xbb\xbf" + CODEX.encode(), steps=(I,), source="REDTEAM installer: BOM (TOML)")
    cx("empty-file", "", steps=(I, U), source="installer codex empty")
    cx("no-servers", 'model = "x"\n', steps=(I,), source="installer codex no mcp_servers")
    cx("already-wrapped-by-python",
       '[mcp_servers.a]\ncommand = "/usr/bin/python3"\nargs = ["-P", "-m", "decision_os_min.gateway", "--home", "/h", '
       '"mcp-proxy", "--client", "codex", "--server", "a", "--", "npx", "a"]\n', steps=(I, S, U),
       source="RUST_REWRITE Phase 5: unwrap entries written by the Python gateway")
    cx("unicode-and-escapes", '[mcp_servers.a]\ncommand = "C:\\\\Tools\\\\srv.exe"\nargs = ["ü", "a\\"b", \'lit\\\\x\']\n',
       steps=(I, {"app_write": append(b"\n")}, U), source="installer _toml_str")
    cx("remote-only", '[mcp_servers.r]\nurl = "https://x"\ncommand = "x"\n', steps=(I, S), source="installer codex remote")
    cx("args-string", '[mcp_servers.a]\ncommand = "x"\nargs = "abc"\n', steps=(I,),
       rust={0: {"report": {"status": "unchanged", "wrapped": [], "already": [], "plain": [], "remote": [],
                            "unwrapped": [], "message": "args-not-strings"},
                 "file": blob(b'[mcp_servers.a]\ncommand = "x"\nargs = "abc"\n')}},
       why="the oracle turns args = \"abc\" into the arguments a, b, c; Rust skips the entry like the JSON path",
       source="installer list(args or [])")
    cx("wrapped-without-original-command", '[mcp_servers.a]\ncommand = "p"\nargs = ["-m", "decision_os_min.gateway", "mcp-proxy", "--"]\n',
       steps=(U,),
       rust={0: {"report": {"status": "unchanged", "wrapped": [], "already": [], "plain": [], "remote": [],
                            "unwrapped": [], "message": "no-original-command"},
                 "file": blob(b'[mcp_servers.a]\ncommand = "p"\nargs = ["-m", "decision_os_min.gateway", "mcp-proxy", "--"]\n')}},
       why="the oracle raises ValueError and aborts the run; Rust leaves the entry and reports it like the JSON path",
       source="installer unwrap_args in _process_codex")
    cx("app-added-server", '[mcp_servers.a]\ncommand = "x"\n',
       steps=(I, {"app_write": append(b'\n[mcp_servers.b]\ncommand = "y"\n')}, I, U),
       source="installer State.wrote (TOML)")
    cx("subtables-and-arrays-of-tables", '[mcp_servers.a]\ncommand = "x"\n[mcp_servers.a.env]\nK = "v"\n'
       '[[profiles]]\nname = "p"\n[mcp_servers.b]\ncommand = "y"\nargs = []\n',
       steps=(I, {"app_write": append(b"\n")}, U), source="installer _edit_codex_server end of table")


def strip_jsonc_fixed(text: str) -> str:
    """The spec'd JSONC stripper: comments and trailing commas, both outside strings only."""
    out, i, n, in_str, esc = [], 0, len(text), False, False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    s = "".join(out)
    res, in_str, esc = [], False, False
    for k, c in enumerate(s):
        if in_str:
            res.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            rest = s[k + 1:].lstrip()
            if rest[:1] in ("}", "]"):
                continue
        res.append(c)
    return "".join(res)


def unwrap_args_positional(args: list) -> tuple:
    """The spec'd unwrap for the oracle shape: by position, so a server named -- round-trips."""
    a = list(args)
    if a[:1] == ["-P"]:
        a = a[1:]
    if (len(a) >= 10 and a[0] == "-m" and a[1] == MODULE and a[2] == "--home" and a[4] == "mcp-proxy"
            and a[5] == "--client" and a[7] == "--server" and a[9] == "--"):
        rest = a[10:]
    else:
        rest = args[args.index("--") + 1:]
    if not rest:
        raise ValueError("wrapped entry has no original command")
    return rest[0], list(rest[1:])


# ------------------------------------------------------------------ registry vectors


def registry_case(name: str, platform: str, env: dict[str, str], files: list[str], source: str) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="dosreg-"))
    saved_os, saved_sys = clients.os, clients.sys
    try:
        root = str(tmp)
        for v in ENV_VARS:
            os.environ.pop(v, None)
        for k, v in env.items():
            os.environ[k] = v.replace("<root>", root)
        for f in files:
            p = tmp / f.replace("<root>/", "")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("{}")
        # only the registry sees the other platform; pathlib keeps the host's path class
        clients.os = types.SimpleNamespace(name="nt" if platform == "windows" else "posix", environ=os.environ)
        clients.sys = types.SimpleNamespace(platform={"windows": "win32", "macos": "darwin", "linux": "linux"}[platform])
        out = {}
        for c in clients.CLIENTS:
            out[c.id] = {
                "name": c.name,
                "fmt": c.fmt,
                "paths": [str(p).replace(root, "<root>") for p in c.paths()],
                "project": [list(p) for p in c.project],
                "restart_hint": c.restart_hint,
            }
    finally:
        clients.os, clients.sys = saved_os, saved_sys
        shutil.rmtree(tmp)
    VECTORS.append({
        "v": 1, "area": "install", "name": name,
        "input": {"kind": "registry", "os": platform, "env": env, "files": files},
        "expected": {"ok": {"clients": out}},
        "source": source,
    })


def build_registry() -> None:
    base = {"HOME": "<root>/u", "USERPROFILE": "<root>/u"}
    full = base | {"APPDATA": "<root>/u/AppData/Roaming", "LOCALAPPDATA": "<root>/u/AppData/Local",
                   "XDG_CONFIG_HOME": "<root>/u/.config"}
    src = "oracle clients.py"
    registry_case("registry-linux", "linux", full, [], src)
    registry_case("registry-linux-no-xdg", "linux", base | {"XDG_CONFIG_HOME": ""}, [], src)
    registry_case("registry-linux-custom-xdg", "linux", base | {"XDG_CONFIG_HOME": "<root>/xdg"}, [], src)
    registry_case("registry-macos", "macos", full, [], src)
    registry_case("registry-windows", "windows", full, [], src)
    registry_case("registry-windows-no-appdata", "windows", base, [], src)
    registry_case("registry-windows-msix", "windows", full, [
        "<root>/u/AppData/Local/Packages/Claude_b1/LocalCache/Roaming/Claude/claude_desktop_config.json",
        "<root>/u/AppData/Local/Packages/Claude_a2/LocalCache/Roaming/Claude/claude_desktop_config.json",
        "<root>/u/AppData/Local/Packages/Other_c3/LocalCache/Roaming/Claude/claude_desktop_config.json",
        "<root>/u/AppData/Local/Packages/Claude_noconfig/LocalCache/Roaming/Claude/other.json",
    ], src + " _claude_desktop MSIX glob")
    registry_case("registry-codex-copilot-home", "linux", full | {"CODEX_HOME": "~/cx", "COPILOT_HOME": "<root>/cp"},
                  [], src + " CODEX_HOME / COPILOT_HOME with expanduser")


def write_vectors() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    names = set()
    for vec in VECTORS:
        assert vec["name"] not in names, vec["name"]
        names.add(vec["name"])
        (OUT / f"{vec['name']}.json").write_text(
            json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(VECTORS)} vectors written to {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    build()
    build_registry()
    write_vectors()
