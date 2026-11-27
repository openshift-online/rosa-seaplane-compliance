#!/usr/bin/env bash
set -euo pipefail

# Pushes gemara/<domain>/{controls,policy}.yaml as one OCI artifact.
# Requires: oras. Log in first if the target registry needs auth
# (e.g. `oras login your-registry.example.com`).
#
# An "http://" prefix on the ref opts into plain-HTTP (for a local/insecure
# registry — see docs/credentials.md), mirroring the same convention
# complyctl itself uses for policies[].url.
# Usage: ./scripts/publish-policy-bundle.sh <domain> <oci-ref>

DOMAIN="${1:?usage: $0 <domain> <oci-ref>}"
INPUT_REF="${2:?usage: $0 <domain> <oci-ref>}"
SRC_DIR="$(cd "$(dirname "$0")/../gemara/${DOMAIN}" && pwd)"

REF="${INPUT_REF}"
ORAS_FLAGS=()
if [[ "${REF}" == http://* ]]; then
  REF="${REF#http://}"
  ORAS_FLAGS+=(--plain-http)
fi

# Relative paths only: oras rejects absolute ones as "insecure" without
# --disable-path-validation.
cd "${SRC_DIR}"
oras push "${ORAS_FLAGS[@]}" "${REF}" \
  "controls.yaml:application/vnd.gemara.catalog.v1+yaml" \
  "policy.yaml:application/vnd.gemara.policy.v1+yaml"

echo "Published ${INPUT_REF}"
echo "Update .complytime/complytime.yaml's policies[].url to match if this differs from what's there."
