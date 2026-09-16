#!/usr/bin/env bash
# List published stems from shapes.json as: shape_id<TAB>kind<TAB>stem
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHAPES_JSON="${SHAPES_JSON:-$ROOT/shapes.json}"
python3 - "$SHAPES_JSON" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
for shape in data.get("shapes", []):
    base = shape["stem"]
    delegated = "main_delegated" if base == "main" else f"{base}_delegated"
    print(f"{shape['id']}\tdirect\t{base}")
    print(f"{shape['id']}\tdelegated\t{delegated}")
PY
