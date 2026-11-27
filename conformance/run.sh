#!/usr/bin/env bash
# Conformance entry point (gate and CI). Builds the runner and the Rust adapter, then
# runs the selected vector areas through every adapter in conformance/adapters/.
#
#   conformance/run.sh --all                    every area, every adapter
#   conformance/run.sh --changed-since <rev>    areas whose vectors changed since <rev>
#                                               (all areas if the runner, an adapter,
#                                               a crate, the oracle or the spec changed)
#   options: --adapter <name> (only that adapter), --json-dir <dir> (one report each)
#
# Each adapter directory must hold manifest.json ({"v":1,"command":[...],"required":[...],
# "oracle":bool}, see crates/dos-conformance/src/manifest.rs); a directory without one
# is an error, never skipped. An area an adapter answers "unsupported" passes unless the
# manifest lists it in "required". Exit 0 only if every adapter run passed.
set -uo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "conformance: not in a git checkout" >&2; exit 2; }
cd "$root" || exit 2

mode=""; base=""; only=""; json_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --all) mode=all ;;
    --changed-since) mode=changed; base="${2:-}"; [ -n "$base" ] || { echo "conformance: --changed-since needs a revision" >&2; exit 2; }; shift ;;
    --adapter) only="${2:-}"; [ -n "$only" ] || { echo "conformance: --adapter needs a name" >&2; exit 2; }; shift ;;
    --json-dir) json_dir="${2:-}"; [ -n "$json_dir" ] || { echo "conformance: --json-dir needs a directory" >&2; exit 2; }; shift ;;
    *) echo "conformance: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$mode" ] || mode=all

vectors=conformance/vectors
areas=()
if [ "$mode" = changed ]; then
  git rev-parse --verify --quiet "$base^{commit}" >/dev/null || { echo "conformance: unknown revision $base" >&2; exit 2; }
  # Committed and uncommitted changes since base, plus untracked files.
  changed="$( { git diff --name-only "$base" --; git ls-files --others --exclude-standard; } | sort -u)"
  if printf '%s\n' "$changed" | grep -qE '^(crates/|conformance/(run\.sh|adapters/)|oracle/|spec/|Cargo\.(toml|lock)$|rust-toolchain\.toml$)'; then
    mode=all
    echo "conformance: runner, adapters, crates, oracle or spec changed since $base; running all areas"
  else
    while IFS= read -r a; do
      [ -n "$a" ] && [ -d "$vectors/$a" ] && areas+=("$a")
    done < <(printf '%s\n' "$changed" | sed -n "s#^$vectors/\([^/]*\)/.*#\1#p" | sort -u)
    if [ ${#areas[@]} -eq 0 ]; then
      echo "conformance: no vector area changed since $base; nothing to run"
      exit 0
    fi
    echo "conformance: changed areas: ${areas[*]}"
  fi
fi

echo "conformance: building runner and Rust adapter"
if ! cargo build --quiet --locked -p dos-conformance -p dos-core-adapter --bins; then
  echo "conformance: build failed" >&2
  exit 1
fi

area_args=()
for a in "${areas[@]+"${areas[@]}"}"; do area_args+=(--area "$a"); done
[ -z "$json_dir" ] || mkdir -p "$json_dir" || exit 2

fail=0; ran=0
for dir in conformance/adapters/*/; do
  name="$(basename "$dir")"
  [ -z "$only" ] || [ "$name" = "$only" ] || continue
  ran=$((ran + 1))
  echo
  echo "=== adapter $name"
  if [ ! -f "$dir/manifest.json" ]; then
    echo "conformance: $dir has no manifest.json" >&2
    fail=1
    continue
  fi
  json_args=()
  [ -z "$json_dir" ] || json_args=(--json "$json_dir/$name.json")
  if ! cargo run --quiet --locked -p dos-conformance --bin dos-conformance -- \
      --manifest "$dir/manifest.json" --vectors "$vectors" \
      "${area_args[@]+"${area_args[@]}"}" "${json_args[@]+"${json_args[@]}"}"; then
    echo "conformance: adapter $name FAILED"
    fail=1
  fi
done

if [ "$ran" -eq 0 ]; then
  echo "conformance: no adapter ran${only:+ (no adapter named $only)}" >&2
  exit 1
fi
echo
if [ $fail -eq 0 ]; then echo "conformance: all adapters passed"; else echo "conformance: FAILED"; fi
exit $fail
