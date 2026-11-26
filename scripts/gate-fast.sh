#!/usr/bin/env bash
# Fast gate: must be green before an agent may finish (run by the Stop hook).
#   scripts/gate-fast.sh fast   lint + tests of changed crates + changed conformance areas
#   scripts/gate-fast.sh lint   lint only (red team: its new tests are meant to fail)
# Adapts to what exists, and says out loud what it skipped.
set -uo pipefail
mode="${1:-fast}"
root="$(git rev-parse --show-toplevel)" || exit 1
cd "$root"
log="$(mktemp)"
fail=0

run() {
  local name="$1"; shift
  if "$@" >"$log" 2>&1; then
    echo "ok       $name"
  else
    echo "FAIL     $name"
    tail -n 40 "$log"
    fail=1
  fi
}
skip() { echo "skipped  $1"; }

base="$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main 2>/dev/null || true)"

if [ -f Cargo.toml ]; then
  run "cargo fmt" cargo fmt --all -- --check
  run "cargo clippy" cargo clippy --workspace --all-targets --quiet -- -D warnings
  if [ "$mode" != "lint" ]; then
    crates=""
    if [ -n "$base" ]; then
      crates="$( { git diff --name-only "$base" -- crates/; git diff --name-only -- crates/; } \
                 | cut -d/ -f2 | sort -u | tr '\n' ' ')"
    fi
    if [ -n "${crates// /}" ]; then
      args=""; for c in $crates; do [ -d "crates/$c" ] && args="$args -p $c"; done
      run "cargo test ($crates)" cargo test --quiet $args
    else
      run "cargo test (workspace)" cargo test --workspace --quiet
    fi
    if [ -x conformance/run.sh ]; then
      run "conformance (changed areas)" conformance/run.sh --changed-since "${base:-HEAD}"
    else
      skip "conformance (conformance/run.sh not present yet)"
    fi
  fi
else
  skip "cargo checks (no Cargo workspace yet)"
fi

run "protected paths unchanged" bash scripts/check-protected.sh

rm -f "$log"
exit $fail
