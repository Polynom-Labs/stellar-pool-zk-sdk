#!/usr/bin/env bash
# Generate a circom main file for a published Transaction / TransactionDelegated shape.
# Reads stellar-pool-zk-sdk/shapes.json unless flags override the numeric params.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHAPES_JSON="${SHAPES_JSON:-$ROOT/shapes.json}"
SHAPE_ID=""
KIND="direct"
OUT=""
TREE_DEPTH=""
N_INS=""
N_OUTS=""
PUBLIC_N_INPUTS=""
PUBLIC_N_OUTPUTS=""
N_AUDIT_SLOTS=""
NOTE_AUDIT_LEN=""
NOTE_OUTPUT_LEN=""
STEM=""

usage() {
  cat >&2 <<'EOF'
Usage: scripts/generate-circuit-main.sh --shape <id> --kind direct|delegated --out <path>

Options:
  --shapes-json <path>   default: ./shapes.json
  --shape <id>           id from shapes.json (e.g. 2x2, 6x6)
  --kind direct|delegated
  --out <path>           output .circom path
  --stem <name>          override output component filename stem (informational)
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shapes-json) SHAPES_JSON="$2"; shift 2 ;;
    --shape) SHAPE_ID="$2"; shift 2 ;;
    --kind) KIND="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --stem) STEM="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$SHAPE_ID" && -n "$OUT" ]] || usage
[[ "$KIND" == "direct" || "$KIND" == "delegated" ]] || {
  echo "--kind must be direct or delegated" >&2
  exit 1
}
[[ -f "$SHAPES_JSON" ]] || { echo "missing $SHAPES_JSON" >&2; exit 1; }

eval "$(python3 - "$SHAPES_JSON" "$SHAPE_ID" "$KIND" <<'PY'
import json, sys
path, shape_id, kind = sys.argv[1:4]
with open(path, encoding="utf-8") as handle:
    data = json.load(handle)
match = next((item for item in data.get("shapes", []) if item.get("id") == shape_id), None)
if match is None:
    raise SystemExit(f"shape id {shape_id!r} not in {path}")
stem = match["stem"]
if kind == "delegated":
    stem = "main_delegated" if stem == "main" else f"{stem}_delegated"
values = {
    "TREE_DEPTH": data.get("treeDepth", match.get("treeDepth", 20)),
    "N_INS": match["nIns"],
    "N_OUTS": match["nOuts"],
    "PUBLIC_N_INPUTS": match["publicNInputs"],
    "PUBLIC_N_OUTPUTS": match["publicNOutputs"],
    "N_AUDIT_SLOTS": match["nAuditSlots"],
    "NOTE_AUDIT_LEN": match.get("noteAuditLen", data.get("noteAuditLen")),
    "NOTE_OUTPUT_LEN": match.get("noteOutputLen", data.get("noteOutputLen")),
    "STEM": stem,
}
for key, value in values.items():
    if value is None:
        raise SystemExit(f"missing {key} for shape {shape_id}")
    print(f"{key}={value}")
PY
)"

mkdir -p "$(dirname "$OUT")"

if [[ "$KIND" == "delegated" ]]; then
  include='transaction_delegated.circom'
  template='TransactionDelegated'
else
  include='transaction.circom'
  template='Transaction'
fi

params="${TREE_DEPTH}, ${N_INS}, ${N_OUTS}, ${PUBLIC_N_INPUTS}, ${PUBLIC_N_OUTPUTS}, ${N_AUDIT_SLOTS}, ${NOTE_AUDIT_LEN}, ${NOTE_OUTPUT_LEN}"

if [[ "$PUBLIC_N_INPUTS" == "0" && "$PUBLIC_N_OUTPUTS" == "0" ]]; then
  public_block='stateRoot,
    withdrawAddressHi,
    withdrawAddressLo,
    escrowRecipientHi,
    escrowRecipientLo,
    sweepOutputOwnerPubX,
    sweepOutputOwnerPubY'
else
  public_block='stateRoot,
    withdrawAddressHi,
    withdrawAddressLo,
    escrowRecipientHi,
    escrowRecipientLo,
    sweepOutputOwnerPubX,
    sweepOutputOwnerPubY,
    publicWithdrawnAssets,
    publicDepositedAssets,
    publicDeposits,
    publicWithdrawals'
fi

cat >"$OUT" <<EOF
pragma circom 2.2.0;

include "${include}";

component main {public [
    ${public_block}
]} = ${template}(${params});
EOF

echo "wrote $OUT (stem=${STEM} kind=${KIND} ${template}(${params}))"
