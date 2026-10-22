#!/usr/bin/env bash
set -euo pipefail

# Assembles every domain's Rego (opa/*/policy/*.rego) plus a single merged
# complytime-mapping.json into one project-wide conftest OCI bundle and pushes
# it. One bundle per target is what complyctl's opa provider expects
# (opa_bundle_ref is a per-target variable).
# Requires: conftest, jq, logged in (`docker login quay.io`).
# Usage: ./scripts/publish-opa-bundle.sh <oci-ref>

REF="${1:?usage: $0 <oci-ref>}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
mkdir -p "${STAGE}/policy"

shopt -s nullglob

# Collect every domain's Rego, failing loudly on a filename collision.
for rego in "${REPO_ROOT}"/opa/*/policy/*.rego; do
  dest="${STAGE}/policy/$(basename "${rego}")"
  if [[ -e "${dest}" ]]; then
    echo "ERROR: duplicate Rego filename $(basename "${rego}") across domains; rename one." >&2
    exit 1
  fi
  cp "${rego}" "${dest}"
done

# Merge every domain's complytime-mapping.json into one (concatenate entries).
mappings=( "${REPO_ROOT}"/opa/*/policy/complytime-mapping.json )
if (( ${#mappings[@]} == 0 )); then
  echo "ERROR: no opa/*/policy/complytime-mapping.json found." >&2
  exit 1
fi
jq -s '{version: "1", mappings: (map(.mappings) | add)}' \
  "${mappings[@]}" >"${STAGE}/policy/complytime-mapping.json"

cd "${STAGE}"
conftest push "${REF}"

echo "Published ${REF}"
echo "Update .complytime/complytime.yaml's opa_bundle_ref target variable to match if this differs from what's there."
