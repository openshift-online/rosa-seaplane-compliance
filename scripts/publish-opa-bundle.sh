#!/usr/bin/env bash
set -euo pipefail

# Pushes opa/change-management/policy/ (Rego + complytime-mapping.json) as a
# conftest OCI bundle. Requires: conftest, logged in (`docker login quay.io`).
# Usage: ./scripts/publish-opa-bundle.sh <oci-ref>

REF="${1:?usage: $0 <oci-ref>}"
BUNDLE_DIR="$(cd "$(dirname "$0")/../opa/change-management" && pwd)"

cd "${BUNDLE_DIR}"
conftest push "${REF}"

echo "Published ${REF}"
echo "Update .complytime/complytime.yaml's opa_bundle_ref target variable to match if this differs from what's there."
