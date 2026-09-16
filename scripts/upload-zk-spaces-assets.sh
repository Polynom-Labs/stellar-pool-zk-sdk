#!/usr/bin/env bash
# Upload rebuilt proving + verification artifacts for listed stems and merge circuits-manifest.json.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT/artifacts}"
PLAN="${1:-$OUTPUT_DIR/zk-rebuild-plan.json}"
BUCKET="${DO_SPACES_BUCKET:-}"
REGION="${DO_SPACES_REGION:-}"
ENDPOINT="${DO_SPACES_ENDPOINT:-}"

if [[ -z "$BUCKET" || -z "$REGION" ]]; then
  echo "DO_SPACES_BUCKET and DO_SPACES_REGION are required" >&2
  exit 1
fi
if [[ -z "${AWS_ACCESS_KEY_ID:-}" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  echo "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required" >&2
  exit 1
fi
if [[ -z "$ENDPOINT" ]]; then
  ENDPOINT="https://${REGION}.digitaloceanspaces.com"
fi
if [[ ! -f "$PLAN" ]]; then
  echo "missing rebuild plan $PLAN" >&2
  exit 1
fi

export AWS_DEFAULT_REGION="$REGION"
export AWS_EC2_METADATA_DISABLED=true
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required

if ! aws s3api put-bucket-cors \
  --bucket "$BUCKET" \
  --endpoint-url "$ENDPOINT" \
  --cors-configuration "file://${ROOT}/scripts/zk-spaces-cors.json"; then
  echo "WARN: could not set bucket CORS" >&2
fi

python3 - "$PLAN" "$OUTPUT_DIR" "$BUCKET" "$ENDPOINT" "$ROOT" <<'PY'
import json, os, subprocess, sys
plan_path, output_dir, bucket, endpoint, root = sys.argv[1:]
plan = json.load(open(plan_path, encoding="utf-8"))
circuits = plan["circuits"]

def artifact_names(stem):
    return [
        f"{stem}.graph.bin",
        f"{stem}.r1cs.gz",
        f"{stem}_proving_key.bin",
        f"{stem}_verification_key.json",
    ]

def content_type(name):
    if name.endswith(".r1cs.gz"):
        return "application/gzip"
    if name.endswith(".json"):
        return "application/json"
    return "application/octet-stream"

for stem, meta in circuits.items():
    if not meta.get("rebuild"):
        continue
    version = meta["version"]
    prefix = f"stellar/{version}"
    for name in artifact_names(stem):
        path = os.path.join(output_dir, name)
        if not os.path.isfile(path):
            raise SystemExit(f"missing artifact {path}")
        dest = f"s3://{bucket}/{prefix}/{name}"
        print(f"BEGIN upload {name} -> {dest}")
        subprocess.check_call(
            [
                "aws", "s3", "cp", path, dest,
                "--endpoint-url", endpoint,
                "--acl", "public-read",
                "--cache-control", "public, max-age=31536000, immutable",
                "--content-type", content_type(name),
                "--only-show-errors",
            ]
        )
        print(f"END upload {name}")

manifest = {
    "packageVersion": plan["packageVersion"],
    "circuits": {
        stem: {
            "version": meta["version"],
            "fingerprint": meta["fingerprint"],
            "kind": meta["kind"],
            "shapeId": meta.get("shapeId"),
        }
        for stem, meta in circuits.items()
    },
}
if os.environ.get("ZK_SUBMODULE_COMMIT"):
    manifest["submoduleCommit"] = os.environ["ZK_SUBMODULE_COMMIT"]
manifest_path = os.path.join(output_dir, "circuits-manifest.json")
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write("\n")
dest = f"s3://{bucket}/stellar/circuits-manifest.json"
subprocess.check_call(
    [
        "aws", "s3", "cp", manifest_path, dest,
        "--endpoint-url", endpoint,
        "--acl", "public-read",
        "--cache-control", "max-age=60, must-revalidate",
        "--content-type", "application/json",
        "--only-show-errors",
    ]
)
print(f"uploaded manifest {dest}")
PY
