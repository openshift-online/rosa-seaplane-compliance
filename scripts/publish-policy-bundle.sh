#!/usr/bin/env bash
set -euo pipefail

# Pushes gemara/change-management/{controls,policy}.yaml as one OCI artifact.
# Requires: oras, logged in (`oras login quay.io`).
# Usage: ./scripts/publish-policy-bundle.sh <oci-ref>

REF="${1:?usage: $0 <oci-ref>}"
SRC_DIR="$(cd "$(dirname "$0")/../gemara/change-management" && pwd)"

oras push "${REF}" \
  "${SRC_DIR}/controls.yaml:application/vnd.gemara.catalog.v1+yaml" \
  "${SRC_DIR}/policy.yaml:application/vnd.gemara.policy.v1+yaml"

echo "Published ${REF}"
echo "Update complytime.yaml's policies[].url to match if this differs from what's there."
