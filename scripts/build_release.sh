#!/usr/bin/env bash
# Build a clean release binary for distribution.
#
# Release binaries must not leak the build machine. Two things do that:
#   1. Symbol/debug info  -> handled by `strip = true` in Cargo.toml.
#   2. Source paths embedded by panic locations (e.g. registry paths
#      under $HOME/.cargo) -> remapped here with --remap-path-prefix.
# The remap uses the current $HOME, so it works on any builder's machine
# without hardcoding a username or home directory into the tree.
#
# Usage: ./scripts/build_release.sh [--features ebpf]
# Output: target/release/ahr-endpoint (verified below to contain no
# $HOME path strings).
set -euo pipefail
cd "$(dirname "$0")/.."

export RUSTFLAGS="--remap-path-prefix ${HOME}=."
cargo build --release "$@"

BIN="target/release/ahr-endpoint"
if strings "$BIN" | grep -qF "$HOME"; then
    echo "ERROR: release binary still contains build-machine paths under $HOME" >&2
    strings "$BIN" | grep -F "$HOME" | head -5 >&2
    exit 1
fi
echo "OK: $BIN contains no $HOME path strings"
sha256sum "$BIN"
