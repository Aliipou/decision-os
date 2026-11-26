#!/bin/sh
# Run a hook script with whichever Python 3 this machine has
# (python3 on macOS and Linux; python or py on Windows under Git Bash).
# No Python means no guard, so the hook fails closed.
dir="$(cd "$(dirname "$0")" && pwd)"
script="$1"
shift
for py in python3 python py; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    exec "$py" "$dir/$script" "$@"
  fi
done
echo "decision-os guard: Python 3.9+ not found, so the safety hooks cannot run. Install Python 3." >&2
exit 2
