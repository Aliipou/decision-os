"""Decision OS agent guard: the rules the agents cannot talk their way around.

Claude Code runs this from hooks (see .claude/settings.json and the `hooks`
block of each agent in .claude/agents/). It reads the hook event JSON on stdin.

    guard.py pre  [--role R]   PreToolUse on Edit|Write|MultiEdit|NotebookEdit
    guard.py bash [--role R]   PreToolUse on Bash
    guard.py post [--role R]   PostToolUse on Edit|Write|MultiEdit
    guard.py stop [--role R]   Stop (SubagentStop for agents)

Exit 0 allows. Exit 2 blocks, and the message on stderr goes back to the agent.
Hooks catch mistakes early; scripts/check-protected.sh in CI catches the rest,
including anything written through the shell in a way this script cannot see.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ----------------------------------------------------------------- policy

# Nobody edits these through a tool. Ali changes them by hand.
FROZEN = (
    "oracle/",
    ".claude/",
    "docs/agents/",
    "CLAUDE.md",
    "RUST_REWRITE.md",
    "scripts/gate-fast.sh",
    "scripts/check-protected.sh",
    ".github/CODEOWNERS",
    ".github/workflows/protected.yml",
)
# Existing files here are append-only history: add new files, never change old ones.
APPEND_ONLY = ("conformance/vectors/", "findings/")
# Formal statements may only change through an architect-approved spec change.
FORMAL_EXT = (".lean", ".tla")
FORMAL_STATEMENT = re.compile(
    r"\b(theorem|lemma|axiom|INVARIANT|THEOREM|PROPERTY|ASSUME|Spec\s*==|Inv\w*\s*==)\b"
)

ROLE_WRITES: dict[str, tuple[str, ...] | None] = {
    "implementer": ("crates/", "tests/", "conformance/", "fuzz/", "benches/", "examples/",
                    "design/", "status/", "Cargo.toml", "Cargo.lock"),
    "red-team": ("tests/redteam/", "conformance/vectors/redteam/", "fuzz/", "findings/", "status/"),
    "verifier": ("reports/", "status/"),
}
FIRST_USER_READS: tuple[str, ...] = ()
FIRST_USER_NO_READ: tuple[str, ...] = ()

CLIENT_CONFIGS = (
    ".decision-os", ".claude.json", ".cursor/mcp.json", ".codex/config.toml",
    ".gemini/settings.json", ".codeium/windsurf/mcp_config.json", ".copilot/mcp-config.json",
    ".lmstudio/mcp.json", ".kiro/settings/mcp.json", ".aws/amazonq/mcp.json",
    "claude_desktop_config.json", "Code/User/mcp.json", "cline_mcp_settings.json",
    "mcp_settings.json",
)

WEAKENING = [
    (re.compile(r"#\[\s*ignore"), "a test marked #[ignore]"),
    (re.compile(r"@pytest\.mark\.(skip|xfail)|pytest\.(skip|xfail)\("), "a skipped or xfail Python test"),
    (re.compile(r"#!?\[\s*allow\s*\(\s*clippy::"), "a clippy lint switched off"),
    (re.compile(r"#!?\[\s*allow\s*\(\s*(unsafe_code|warnings)"), "a safety lint switched off"),
    (re.compile(r"\bverify\s*\((?!\s*\))"), "Ed25519 verify() instead of verify_strict()",),
]
CORE_ONLY = [
    (re.compile(r"\bunsafe\b"), "`unsafe` in a core crate"),
    (re.compile(r"\.unwrap\(\)|\.expect\(|\bpanic!\(|\btodo!\(|\bunimplemented!\("),
     "a possible panic in a core crate (unwrap/expect/panic/todo)"),
]
CORE_CRATES = ("crates/dos-core/", "crates/dos-pep/")

GATED_ROLES_FULL = {"implementer"}
GATED_ROLES_LINT = {"red-team"}


# ----------------------------------------------------------------- helpers

def deny(msg: str) -> None:
    sys.stderr.write(f"decision-os guard: {msg}\n")
    sys.exit(2)


def norm(p: str) -> str:
    return p.replace("\\", "/")


def repo_root(path: Path) -> Path | None:
    """The git work tree containing `path` (worktrees have a .git file)."""
    cur = path if path.is_dir() else path.parent
    for d in (cur, *cur.parents):
        if (d / ".git").exists():
            return d
    return None


def rel_in_repo(file_path: str, cwd: str) -> tuple[Path | None, str | None]:
    p = Path(file_path)
    if not p.is_absolute():
        p = Path(cwd) / p
    p = Path(os.path.normpath(str(p)))
    root = repo_root(p)
    if root is None:
        return None, None
    try:
        return root, norm(str(p.relative_to(root)))
    except ValueError:
        return None, None


def under(rel: str, prefixes: tuple[str, ...]) -> bool:
    for pre in prefixes:
        if pre.endswith("/"):
            if rel.startswith(pre):
                return True
        elif rel == pre:
            return True
    return False


def real_home_config(abs_path: str) -> bool:
    homes = {os.environ.get("HOME"), os.environ.get("USERPROFILE")}
    p = norm(os.path.normpath(abs_path))
    for h in filter(None, homes):
        h = norm(os.path.normpath(h)).rstrip("/") + "/"
        if p.startswith(h):
            tail = p[len(h):]
            if any(tail == c or tail.startswith(c + "/") or tail.endswith("/" + c) for c in CLIENT_CONFIGS):
                return True
    return False


def edit_texts(tool_input: dict) -> tuple[str, str]:
    """(old, new) text of an Edit/MultiEdit/Write."""
    if "edits" in tool_input:  # MultiEdit
        olds = "\n".join(e.get("old_string", "") for e in tool_input["edits"])
        news = "\n".join(e.get("new_string", "") for e in tool_input["edits"])
        return olds, news
    if "content" in tool_input:
        return "", tool_input.get("content") or ""
    return tool_input.get("old_string", "") or "", tool_input.get("new_string", "") or ""


def added_lines(old: str, new: str) -> list[str]:
    before = set(old.splitlines())
    return [ln for ln in new.splitlines() if ln not in before]


# ----------------------------------------------------------------- checks

def check_pre(ev: dict, role: str) -> None:
    ti = ev.get("tool_input") or {}
    fp = ti.get("file_path") or ti.get("notebook_path") or ""
    if not fp:
        return
    cwd = ev.get("cwd") or os.getcwd()
    abs_fp = fp if os.path.isabs(fp) else os.path.join(cwd, fp)
    if real_home_config(abs_fp):
        deny(f"{fp} is a real app config or Decision OS state on this machine. "
             "Work only in a throwaway HOME (set HOME and USERPROFILE to a temp folder).")
    root, rel = rel_in_repo(fp, cwd)
    if rel is None:
        return  # outside any repo: scratch space
    if under(rel, FROZEN):
        deny(f"{rel} is frozen (oracle, agent rules, gates). Only Ali edits it. "
             "If it must change, stop and write ESCALATION.md.")
    exists = (root / rel).exists()
    if exists and under(rel, APPEND_ONLY):
        deny(f"{rel} already exists and {rel.split('/')[0]}/ is append-only. Add a new file. "
             "Changing an expected value is a spec change: stop and escalate.")
    if exists and rel.endswith(FORMAL_EXT):
        old, new = edit_texts(ti)
        if "content" in ti or FORMAL_STATEMENT.search(old):
            deny(f"{rel}: theorem, invariant and property statements are not edited by agents. "
                 "Proofs may change; statements change only through an approved spec change.")
    allowed = ROLE_WRITES.get(role, ())
    if role and allowed is not None and not under(rel, allowed):
        deny(f"the {role} role does not write {rel}. It writes only: {', '.join(allowed)}.")


def check_read(ev: dict, role: str) -> None:
    if role != "first-user":
        return
    ti = ev.get("tool_input") or {}
    target = ti.get("file_path") or ti.get("path") or ""
    if not target:
        return
    _, rel = rel_in_repo(target, ev.get("cwd") or os.getcwd())
    if rel is None:
        return
    if rel in ("", "."):
        deny("the first user reads the docs, not the repository tree. Start from README.md.")
    if under(rel, FIRST_USER_NO_READ) or not under(rel, FIRST_USER_READS):
        deny(f"the first user only reads what a real user sees (README, docs/, installers). Not {rel}.")


SHELL_WRITE = re.compile(
    r"(>>?|\bsed\s+-i|\bperl\s+-[a-z]*i|\brm\b|\bmv\b|\bcp\b|\btee\b|\btruncate\b|"
    r"\bgit\s+(checkout|restore|rm|mv|apply|am)\b|\bchmod\b|\bln\b|Set-Content|Out-File|Remove-Item)"
)
PROTECTED_IN_SHELL = re.compile(
    r"(^|[\s'\"=/])(oracle/|\.claude/|docs/agents/|CLAUDE\.md|RUST_REWRITE\.md|"
    r"scripts/gate-|scripts/check-protected|conformance/vectors/)"
)
INSTALL_CMD = re.compile(
    r"(decision-os(\.exe)?|decision_os_min\.gateway)\s+(--home\s+\S+\s+)?(install|uninstall)\b"
    r"|\binstall\.sh\b|\binstall\.ps1\b|Install-DecisionOS\.cmd"
)
THROWAWAY_HOME = re.compile(r"\b(HOME|USERPROFILE)=|\$env:USERPROFILE\s*=|--throwaway-home")


def check_bash(ev: dict, role: str) -> None:
    cmd = (ev.get("tool_input") or {}).get("command") or ""
    if re.search(r"\bgit\s+push\b.*(\s--force\b|\s-f\b|--force-with-lease)", cmd):
        deny("force-push is not allowed. Ask the orchestrator.")
    if re.search(r"--no-verify\b", cmd):
        deny("--no-verify skips the checks that keep this project honest.")
    if re.search(r"\bgit\s+push\b[^\n;&|]*\b(main|master)\b", cmd) and role:
        deny("agents do not push to main; the main session merges after the verifier approves.")
    if role in ("verifier", "red-team") and re.search(r"\bgit\s+(commit|push|merge|rebase)\b", cmd):
        deny(f"the {role} role does not change history.")
    if role and re.search(r"\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f)", cmd):
        deny("destructive git cleanup can delete other agents' work. Ask the orchestrator.")
    if SHELL_WRITE.search(cmd) and PROTECTED_IN_SHELL.search(cmd):
        deny("this shell command looks like it writes to a frozen or append-only path. "
             "Read with cat/rg is fine; writes go through the rules in docs/agents/WORKFLOW.md.")
    if INSTALL_CMD.search(cmd) and not THROWAWAY_HOME.search(cmd):
        deny("installer runs must use a throwaway HOME, or they rewrite this machine's real "
             "app configs. Prefix with HOME=<tmp> USERPROFILE=<tmp> (and APPDATA/LOCALAPPDATA/"
             "XDG_CONFIG_HOME under it).")


def check_post(ev: dict, role: str) -> None:
    ti = ev.get("tool_input") or {}
    fp = ti.get("file_path") or ""
    if not fp:
        return
    _, rel = rel_in_repo(fp, ev.get("cwd") or os.getcwd())
    if rel is None:
        return
    old, new = edit_texts(ti)
    added = "\n".join(added_lines(old, new))
    hits = []
    is_test = "/tests/" in f"/{rel}" or rel.startswith("tests/") or "_test" in rel or "test_" in rel
    for rx, what in WEAKENING:
        if what.startswith("Ed25519") and "ed25519" not in (new + old).lower():
            continue
        if rx.search(added):
            hits.append(what)
    if under(rel, CORE_CRATES) and not is_test:
        for rx, what in CORE_ONLY:
            if rx.search(added):
                hits.append(what)
    removed_asserts = sum(1 for ln in old.splitlines() if re.search(r"\bassert", ln)) - \
        sum(1 for ln in new.splitlines() if re.search(r"\bassert", ln))
    if is_test and removed_asserts > 0:
        hits.append(f"{removed_asserts} assertion(s) removed from a test")
    if hits:
        deny(f"possible weakening in {rel}: " + "; ".join(hits) + ". If this is truly needed, "
             "revert it now and raise it in your handoff for the architect (THINKING.md section 9).")


def check_stop(ev: dict, role: str) -> None:
    if role not in GATED_ROLES_FULL | GATED_ROLES_LINT:
        return
    root = repo_root(Path(ev.get("cwd") or os.getcwd()))
    if root is None or not (root / "scripts" / "gate-fast.sh").exists():
        return
    mode = "lint" if role in GATED_ROLES_LINT else "fast"
    try:
        r = subprocess.run(["bash", "scripts/gate-fast.sh", mode], cwd=root, capture_output=True,
                           text=True, timeout=1500)
        ok, out = r.returncode == 0, (r.stdout + r.stderr)[-4000:]
    except (OSError, subprocess.TimeoutExpired) as exc:
        ok, out = False, f"gate could not run: {exc}"
    if ok:
        return
    if ev.get("stop_hook_active"):
        # Already sent back once and still red: let it stop, but say so plainly.
        print(json.dumps({"systemMessage": f"Agent ({role}) stopped with RED gates:\n{out}"}))
        sys.exit(0)
    deny(f"gates are red, so this task is not done. Fix them, or if you cannot, say so "
         f"in your handoff with the output below.\n{out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["pre", "read", "bash", "post", "stop"])
    ap.add_argument("--role", default="")
    a = ap.parse_args()
    try:
        ev = json.load(sys.stdin)
    except ValueError:
        deny("hook received no event JSON; refusing (fail closed).")
    {"pre": check_pre, "read": check_read, "bash": check_bash, "post": check_post,
     "stop": check_stop}[a.mode](ev, a.role)
    sys.exit(0)


if __name__ == "__main__":
    main()
