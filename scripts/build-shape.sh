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

make -C "$POOLS" witness-graph \
  MAIN_CIRCOM="$out" \
  CIRCOM_INCLUDE="$POOLS/circuits" \
  OUTPUT_DIR="$OUTPUT_DIR" \
  STEM="$stem"

make -C "$POOLS" export-proving-keys \
  MAIN_CIRCOM="$out" \
  BUILD_DIR="$BUILD_DIR" \
  OUTPUT_DIR="$OUTPUT_DIR" \
  STEM="$stem"

echo "BEGIN built $stem END"
