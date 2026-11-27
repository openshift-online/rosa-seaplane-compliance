#!/usr/bin/env bash
set -euo pipefail

# Assembles every domain's Rego (opa/*/policy/*.rego) plus a single merged
# complytime-mapping.json into one project-wide complypack (evaluator opa) and
# pushes it with `complypack pack`. complyctl keeps one complypack per
# evaluator, so all domains ship together.
#
# complypack.yaml (repo root) supplies the evaluator, version, gemara sources
# and platform schemas; `pack` validates the policies against them first.
# Unit tests (*_test.rego) are not shipped; tests/run.sh runs them.
#
# Requires: complypack, jq. Log in first if the target registry needs auth.
#
# An "http://" prefix on the ref opts into plain-HTTP (for a local/insecure
# registry -- see docs/credentials.md), mirroring the same convention
# complyctl itself uses for policies[].url.
# Usage: ./scripts/publish-complypack.sh <oci-ref>

INPUT_REF="${1:?usage: $0 <oci-ref>}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REF="${INPUT_REF}"
PACK_FLAGS=()
if [[ "${REF}" == http://* ]]; then
  REF="${REF#http://}"
  PACK_FLAGS+=(--plain-http)
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

shopt -s nullglob

# Collect every domain's Rego (excluding unit tests), failing loudly on a
# filename collision.
for rego in "${REPO_ROOT}"/opa/*/policy/*.rego; do
  base="$(basename "${rego}")"
  case "${base}" in *_test.rego) continue ;; esac
  dest="${STAGE}/${base}"
  if [[ -e "${dest}" ]]; then
    echo "ERROR: duplicate Rego filename ${base} across domains; rename one." >&2
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
  "${mappings[@]}" >"${STAGE}/complytime-mapping.json"

cd "${REPO_ROOT}"
complypack pack "${STAGE}" "${REF}" "${PACK_FLAGS[@]}"

echo "Published ${INPUT_REF}"
echo "Update .complytime/complytime.yaml's complypacks url to match if this differs from what's there."
