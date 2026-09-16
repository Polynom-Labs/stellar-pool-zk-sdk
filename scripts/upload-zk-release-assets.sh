#!/usr/bin/env bash
# Upload rebuilt VK + proving files for the current GitHub release tag.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT/artifacts}"
PLAN="${OUTPUT_DIR}/zk-rebuild-plan.json"
TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: scripts/upload-zk-release-assets.sh <release-tag>" >&2
  exit 1
fi
if [[ ! -f "$PLAN" ]]; then
  echo "missing $PLAN" >&2
  exit 1
fi

files="$(python3 - "$PLAN" "$OUTPUT_DIR" <<'PY'
import json, os, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
output_dir = sys.argv[2]
names = []
for stem, meta in plan["circuits"].items():
    if not meta.get("rebuild"):
        continue
    for name in (
        f"{stem}.graph.bin",
        f"{stem}.r1cs.gz",
        f"{stem}_proving_key.bin",
        f"{stem}_verification_key.json",
    ):
        path = os.path.join(output_dir, name)
        if not os.path.isfile(path):
            raise SystemExit(f"missing {path}")
        names.append(path)
print("\n".join(names))
PY
)"
if [[ -z "$files" ]]; then
  echo "no rebuilt artifacts to attach"
  exit 0
fi
# shellcheck disable=SC2086
gh release upload "$TAG" $files --clobber
