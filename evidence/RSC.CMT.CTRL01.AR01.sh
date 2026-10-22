#!/usr/bin/env bash
set -euo pipefail

# Requires: gh (authenticated via GITHUB_TOKEN env var), jq.

AR_ID="$(basename "$0" .sh)"
REPO="${RSC_REPO:-openshift-online/rosa-seaplane}"
BASE_REF="${RSC_BASE_REF:-main}"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
OUT_DIR="${EVIDENCE_DIR}/${AR_ID}"
OUT_FILE="${OUT_DIR}/evidence.json"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh CLI reads it for API auth)." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

RAW="$(gh api "repos/${REPO}/branches/${BASE_REF}/protection")"

jq --arg repo "${REPO}" \
  --arg branch "${BASE_REF}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{generated_at: $generated_at, repository: $repo, branch: $branch, protection: .}' \
  <<<"${RAW}" >"${OUT_FILE}"

echo "Wrote branch protection snapshot to ${OUT_FILE}" >&2
