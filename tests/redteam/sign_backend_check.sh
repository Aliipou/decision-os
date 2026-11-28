#!/usr/bin/env bash
# Red team (findings/sign.md, F2): is curve25519-dalek built with the Fiat backend
# in every build that ships dos-core? Exit 1 if any build uses another backend.
# Usage: tests/redteam/sign_backend_check.sh   (from the repo root, Linux/WSL)
set -u
root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
fail=0
check() { # name, log
  local cfg
  cfg="$(grep -E 'Running .*--crate-name curve25519_dalek ' "$2" | grep -o 'curve25519_dalek_backend=[^ ]*' | head -1)"
  if grep -q -- '--crate-name fiat_crypto' "$2"; then
    echo "ok    $1: fiat"
  else
    echo "FAIL  $1: not fiat (${cfg:-no backend cfg})"; fail=1
  fi
}
(cd "$root" && CARGO_TARGET_DIR="$tmp/a" cargo build -p dos-core --release -v >"$tmp/a.log" 2>&1)
check "workspace release build" "$tmp/a.log"
(cd "$root" && RUSTFLAGS=-Dwarnings CARGO_TARGET_DIR="$tmp/b" cargo build -p dos-core --release -v >"$tmp/b.log" 2>&1)
check "workspace build with RUSTFLAGS set (common in CI)" "$tmp/b.log"
mkdir -p "$tmp/down/src"
cat >"$tmp/down/Cargo.toml" <<EOF
[package]
name = "rt-downstream"
version = "0.0.0"
edition = "2024"
[dependencies]
dos-core = { path = "$root/crates/dos-core" }
[workspace]
EOF
echo 'pub fn k(b: &[u8; 32]) -> bool { dos_core::sign::VerifyingKey::from_bytes(b).is_ok() }' >"$tmp/down/src/lib.rs"
(cd "$tmp/down" && CARGO_TARGET_DIR="$tmp/c" cargo +1.96.0 build -v >"$tmp/c.log" 2>&1)
check "downstream crate depending on dos-core" "$tmp/c.log"
rm -rf "$tmp"
exit $fail
