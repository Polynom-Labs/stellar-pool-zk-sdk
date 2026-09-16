#!/usr/bin/env bash
# Per-shape fingerprint: templates in the pools submodule that the shape uses,
# generated main contents, shape params, and production ptau.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POOLS="${POOLS_DIR:-$ROOT/soroban-privacy-pools}"
PTAU_PATH="${PTAU_PATH:-$ROOT/ptau/pot20_final.ptau}"
SHAPES_JSON="${SHAPES_JSON:-$ROOT/shapes.json}"
SHAPE_ID="${1:-}"
KIND="${2:-direct}"

if [[ -z "$SHAPE_ID" ]]; then
  echo "usage: scripts/zk-circuits-fingerprint.sh <shape-id> [direct|delegated]" >&2
  exit 1
fi

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

tmp="$(mktemp)"
generated="$(mktemp)"
trap 'rm -f "$tmp" "$generated"' EXIT

"$ROOT/scripts/generate-circuit-main.sh" \
  --shapes-json "$SHAPES_JSON" \
  --shape "$SHAPE_ID" \
  --kind "$KIND" \
  --out "$generated" >/dev/null

{
  printf 'shape %s kind %s\n' "$SHAPE_ID" "$KIND"
  printf 'ptau %s\n' "$(hash_file "$PTAU_PATH") $PTAU_PATH"
  printf 'generated %s\n' "$(hash_file "$generated")"
  if [[ "$KIND" == "delegated" ]]; then
    list=(
      "$POOLS/circuits/transaction.circom"
      "$POOLS/circuits/transaction_delegated.circom"
      "$POOLS/circuits/withdraw.circom"
      "$POOLS/circuits/withdraw_delegated.circom"
      "$POOLS/circuits/withdraw_v3_direct.circom"
      "$POOLS/circuits/delegated_authorization.circom"
      "$POOLS/circuits/v3_note.circom"
      "$POOLS/circuits/deposit.circom"
      "$POOLS/circuits/commitment.circom"
      "$POOLS/circuits/accounting.circom"
      "$POOLS/circuits/audit_encryption.circom"
      "$POOLS/circuits/output_note_encryption.circom"
      "$POOLS/circuits/encryption.circom"
      "$POOLS/circuits/merkleProof.circom"
      "$POOLS/circuits/poseidon255.circom"
      "$POOLS/circuits/poseidon255_constants.circom"
      "$POOLS/circuits/poseidon_chain.circom"
      "$POOLS/circuits/domain_separators.circom"
      "$POOLS/circuits/derived_escrow.circom"
      "$POOLS/circuits/fcomparators.circom"
    )
  else
    list=(
      "$POOLS/circuits/transaction.circom"
      "$POOLS/circuits/withdraw.circom"
      "$POOLS/circuits/deposit.circom"
      "$POOLS/circuits/commitment.circom"
      "$POOLS/circuits/accounting.circom"
      "$POOLS/circuits/audit_encryption.circom"
      "$POOLS/circuits/output_note_encryption.circom"
      "$POOLS/circuits/encryption.circom"
      "$POOLS/circuits/poseidon_chain.circom"
      "$POOLS/circuits/merkleProof.circom"
      "$POOLS/circuits/poseidon255.circom"
      "$POOLS/circuits/poseidon255_constants.circom"
      "$POOLS/circuits/domain_separators.circom"
      "$POOLS/circuits/derived_escrow.circom"
      "$POOLS/circuits/fcomparators.circom"
    )
  fi
  for path in "${list[@]}"; do
    if [[ ! -f "$path" ]]; then
      echo "missing fingerprinted template $path" >&2
      exit 1
    fi
    printf '%s  %s\n' "$(hash_file "$path")" "${path#"$POOLS"/}"
  done
} | LC_ALL=C sort >"$tmp"

hash_file "$tmp"
