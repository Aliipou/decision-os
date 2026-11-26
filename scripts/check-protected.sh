#!/usr/bin/env bash
# The backstop behind the hooks: whatever an agent did, through a tool or the
# shell, this fails if a frozen path changed or an append-only file was edited
# or deleted on this branch. Runs in both gates and in CI.
set -uo pipefail
root="$(git rev-parse --show-toplevel)" || exit 1
cd "$root"
base="$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main 2>/dev/null || true)"
fail=0

# The agent kit itself. Ali changes these directly on main, never on a branch.
kit=(.claude docs/agents CLAUDE.md RUST_REWRITE.md .github/CODEOWNERS .github/workflows/protected.yml scripts/gate-fast.sh scripts/check-protected.sh)
append_only=(conformance/vectors findings)

changed() {  # committed changes on this branch plus uncommitted ones
  { [ -n "$base" ] && git diff --name-status "$base" -- "$@"; git diff --name-status HEAD -- "$@"; } | sort -u
}

if [ -z "$base" ]; then
  echo "note: no main branch to compare with; checking uncommitted changes only"
fi

out="$(changed "${kit[@]}")"
if [ -n "$out" ]; then
  echo "agent-kit files changed on this branch (only Ali changes these, on main):"
  echo "$out"
  fail=1
fi

out="$(changed "${append_only[@]}" | grep -E '^(M|D|R)' || true)"
if [ -n "$out" ]; then
  echo "append-only files were modified, deleted or renamed (add new files instead):"
  echo "$out"
  fail=1
fi

# The oracle is frozen from the moment it is tagged (end of Phase 0).
# Before the first tag, Phase 0 is importing it. After that, only a branch named
# oracle-change/* may touch it, and CODEOWNERS makes that PR need Ali's review.
branch="$(git rev-parse --abbrev-ref HEAD)"
tag="$(git tag --list 'oracle-v*' --sort=-v:refname | head -n 1)"
if [ -z "$tag" ]; then
  echo "note: no oracle-v* tag yet (Phase 0 bootstrap); oracle/ not checked"
elif [[ "$branch" == oracle-change/* ]]; then
  echo "note: $branch may change oracle/; the PR needs Ali's review (CODEOWNERS)"
elif ! git diff --quiet "$tag" -- oracle/ || [ -n "$(git status --porcelain -- oracle/)" ]; then
  echo "oracle/ differs from $tag (frozen). Oracle changes need a branch named oracle-change/* and Ali's review."
  fail=1
fi

[ $fail -eq 0 ] && echo "protected paths: unchanged"
exit $fail
