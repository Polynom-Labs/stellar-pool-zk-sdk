#!/usr/bin/env bash
# Compile + Groth16 keygen + proving artifacts for one published stem.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POOLS="${POOLS_DIR:-$ROOT/soroban-privacy-pools}"
PTAU_PATH="${PTAU_PATH:-$ROOT/ptau/pot20_final.ptau}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT/artifacts}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
GENERATED_DIR="${GENERATED_DIR:-$ROOT/generated}"
SHAPES_JSON="${SHAPES_JSON:-$ROOT/shapes.json}"

SHAPE_ID="${1:-}"
KIND="${2:-direct}"
if [[ -z "$SHAPE_ID" ]]; then
  echo "usage: scripts/build-shape.sh <shape-id> [direct|delegated]" >&2
  exit 1
fi

stem="$("$ROOT/scripts/zk-shape-stems.sh" | awk -F '\t' -v id="$SHAPE_ID" -v kind="$KIND" '$1==id && $2==kind {print $3; exit}')"
if [[ -z "$stem" ]]; then
  echo "unknown shape $SHAPE_ID kind $KIND" >&2
  exit 1
fi

mkdir -p "$GENERATED_DIR" "$OUTPUT_DIR" "$BUILD_DIR"
out="$GENERATED_DIR/${stem}.circom"
"$ROOT/scripts/generate-circuit-main.sh" \
  --shapes-json "$SHAPES_JSON" \
  --shape "$SHAPE_ID" \
  --kind "$KIND" \
  --out "$out"

make -C "$POOLS" compile \
  MAIN_CIRCOM="$out" \
  CIRCOM_INCLUDE="$POOLS/circuits" \
  BUILD_DIR="$BUILD_DIR" \
  STEM="$stem"

make -C "$POOLS" keygen \
  MAIN_CIRCOM="$out" \
  CIRCOM_INCLUDE="$POOLS/circuits" \
  BUILD_DIR="$BUILD_DIR" \
  OUTPUT_DIR="$OUTPUT_DIR" \
  PTAU_PATH="$PTAU_PATH" \
  STEM="$stem"

"$ROOT/scripts/ensure-circom-witness-rs.sh"

# circom-witness-rs only passes CIRCOMLIB as -l. Put the generated main next to
# pool templates so `include "transaction.circom"` resolves.
witness_src="$POOLS/circuits/${stem}.circom"
if [[ "$witness_src" != "$out" ]]; then
  cp "$out" "$witness_src"
  cleanup_witness_src=1
else
  cleanup_witness_src=0
fi
trap 'if [[ "${cleanup_witness_src:-0}" -eq 1 ]]; then rm -f "$witness_src"; fi' EXIT

make -C "$POOLS" witness-graph \
  MAIN_CIRCOM="$witness_src" \
  CIRCOM_INCLUDE="$POOLS/circuits" \
  OUTPUT_DIR="$OUTPUT_DIR" \
  STEM="$stem"

if [[ "$cleanup_witness_src" -eq 1 ]]; then
  rm -f "$witness_src"
  cleanup_witness_src=0
fi

make -C "$POOLS" export-proving-keys \
  MAIN_CIRCOM="$out" \
  BUILD_DIR="$BUILD_DIR" \
  OUTPUT_DIR="$OUTPUT_DIR" \
  STEM="$stem"

echo "BEGIN built $stem END"
