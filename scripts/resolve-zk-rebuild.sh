#!/usr/bin/env bash
# Compare per-shape fingerprints to the CDN manifest and decide what to rebuild.
# Writes artifacts/zk-rebuild-plan.json and GitHub outputs: rebuild_stems, version, manifest_json
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_VERSION="${ZK_PACKAGE_VERSION:-}"
CDN_ORIGIN="${ZK_ARTIFACT_CDN_ORIGIN:-}"
BUCKET="${DO_SPACES_BUCKET:-}"
REGION="${DO_SPACES_REGION:-}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT/artifacts}"

if [[ -z "$PACKAGE_VERSION" ]]; then
  PACKAGE_VERSION="$(python3 -c 'import json; print(json.load(open("'"$ROOT"'/client-sdk/package.json"))["version"])')"
fi
PACKAGE_VERSION="${PACKAGE_VERSION#v}"
CDN_ORIGIN="${CDN_ORIGIN%/}"

mkdir -p "$OUTPUT_DIR"

fetch_json() {
  curl -fsS --max-time 30 "$1" || true
}

manifest_url=""
if [[ -n "$CDN_ORIGIN" ]]; then
  manifest_url="${CDN_ORIGIN}/stellar/circuits-manifest.json"
elif [[ -n "$BUCKET" && -n "$REGION" ]]; then
  manifest_url="https://${BUCKET}.${REGION}.digitaloceanspaces.com/stellar/circuits-manifest.json"
fi

existing="$(mktemp)"
trap 'rm -f "$existing"' EXIT
if [[ -n "$manifest_url" ]]; then
  fetch_json "$manifest_url" >"$existing" || true
fi
if [[ ! -s "$existing" ]]; then
  echo '{}' >"$existing"
fi

plan="$OUTPUT_DIR/zk-rebuild-plan.json"
SUBMODULE_COMMIT="${ZK_SUBMODULE_COMMIT:-}"
if [[ -z "$SUBMODULE_COMMIT" && -d "$ROOT/soroban-privacy-pools/.git" ]]; then
  SUBMODULE_COMMIT="$(git -C "$ROOT/soroban-privacy-pools" rev-parse HEAD)"
elif [[ -z "$SUBMODULE_COMMIT" && -f "$ROOT/.gitmodules" ]]; then
  SUBMODULE_COMMIT="$(git -C "$ROOT" submodule status soroban-privacy-pools | awk '{print $1}' | tr -d '-+')"
fi

python3 - "$ROOT" "$existing" "$PACKAGE_VERSION" "$plan" "$CDN_ORIGIN" "${ZK_BOOTSTRAP_FROM_VERSION:-0.10.0}" "$SUBMODULE_COMMIT" <<'PY'
import json, os, subprocess, sys, urllib.error, urllib.request
root, existing_path, package_version, plan_path, cdn_origin, bootstrap_ver, submodule_commit = sys.argv[1:]
cdn_origin = cdn_origin.rstrip("/")
bootstrap_ver = bootstrap_ver.lstrip("v")
with open(existing_path, encoding="utf-8") as handle:
    try:
        existing = json.load(handle)
    except json.JSONDecodeError:
        existing = {}
circuits = existing.get("circuits") if isinstance(existing.get("circuits"), dict) else {}
manifest_empty = not circuits
stems = subprocess.check_output(
    [os.path.join(root, "scripts/zk-shape-stems.sh")],
    cwd=root,
    text=True,
)

def object_exists(stem, version):
    if not cdn_origin:
        return False
    url = f"{cdn_origin}/stellar/{version}/{stem}.graph.bin"
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return 200 <= getattr(resp, "status", 200) < 400
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False

rebuild = []
mapping = {}
for line in stems.splitlines():
    if not line.strip():
        continue
    shape_id, kind, stem = line.split("\t")
    fingerprint = subprocess.check_output(
        [os.path.join(root, "scripts/zk-circuits-fingerprint.sh"), shape_id, kind],
        cwd=root,
        text=True,
    ).strip()
    previous = circuits.get(stem) if isinstance(circuits.get(stem), dict) else {}
    prev_fp = previous.get("fingerprint")
    prev_ver = previous.get("version")
    if prev_fp == fingerprint and isinstance(prev_ver, str) and prev_ver.strip():
        mapping[stem] = {
            "version": prev_ver.strip().lstrip("v"),
            "fingerprint": fingerprint,
            "kind": kind,
            "shapeId": shape_id,
            "rebuild": False,
        }
    elif manifest_empty and object_exists(stem, bootstrap_ver):
        mapping[stem] = {
            "version": bootstrap_ver,
            "fingerprint": fingerprint,
            "kind": kind,
            "shapeId": shape_id,
            "rebuild": False,
            "bootstrap": True,
        }
    else:
        rebuild.append(stem)
        mapping[stem] = {
            "version": package_version,
            "fingerprint": fingerprint,
            "kind": kind,
            "shapeId": shape_id,
            "rebuild": True,
        }
plan = {
    "packageVersion": package_version,
    "rebuildStems": rebuild,
    "circuits": mapping,
}
if submodule_commit:
    plan["submoduleCommit"] = submodule_commit
manifest = {
    "packageVersion": package_version,
    "circuits": {
        stem: {
            "version": meta["version"],
            "fingerprint": meta["fingerprint"],
            "kind": meta["kind"],
            "shapeId": meta.get("shapeId"),
        }
        for stem, meta in mapping.items()
    },
}
if submodule_commit:
    manifest["submoduleCommit"] = submodule_commit
manifest_path = os.path.join(os.path.dirname(plan_path), "circuits-manifest.json")
with open(plan_path, "w", encoding="utf-8") as handle:
    json.dump(plan, handle, indent=2, sort_keys=True)
    handle.write("\n")
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write("\n")
print("rebuild_stems=" + ",".join(rebuild))
print("version=" + package_version)
print("rebuild=" + ("true" if rebuild else "false"))
PY

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  python3 - "$plan" >>"$GITHUB_OUTPUT" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
print("rebuild_stems=" + ",".join(plan.get("rebuildStems") or []))
print("version=" + plan["packageVersion"])
print("rebuild=" + ("true" if plan.get("rebuildStems") else "false"))
print("publish_artifacts=" + ("true" if plan.get("rebuildStems") else "false"))
PY
fi
