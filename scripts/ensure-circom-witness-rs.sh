#!/usr/bin/env bash
# Fetch circom-witness-rs 0.3.0 into the cargo registry so pools'
# prepare-witness-graph-crate.sh can copy it. That script's `cargo fetch` on
# cli/witness-graph does nothing: the crate is a path dep that does not exist yet.
set -euo pipefail

SRC="${CARGO_HOME:-$HOME/.cargo}/registry/src/index.crates.io-1949cf8c6b5b557f/circom-witness-rs-0.3.0"
if [[ -d "$SRC" ]]; then
  echo "circom-witness-rs 0.3.0 already in cargo registry"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/Cargo.toml" <<'EOF'
[package]
name = "fetch-circom-witness-rs"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
circom-witness-rs = "=0.3.0"
EOF
mkdir -p "$tmp/src"
echo "fn main() {}" >"$tmp/src/main.rs"
echo "BEGIN cargo fetch circom-witness-rs 0.3.0"
cargo fetch --manifest-path "$tmp/Cargo.toml"
echo "END cargo fetch circom-witness-rs 0.3.0"
if [[ ! -d "$SRC" ]]; then
  echo "circom-witness-rs 0.3.0 still missing at $SRC after cargo fetch" >&2
  ls -d "${CARGO_HOME:-$HOME/.cargo}/registry/src/"index.crates.io-*/circom-witness-rs-0.3.0 2>/dev/null >&2 || true
  exit 1
fi
