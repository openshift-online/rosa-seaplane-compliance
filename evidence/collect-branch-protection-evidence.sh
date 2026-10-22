#!/usr/bin/env bash
set -euo pipefail

# Captures a raw, timestamped snapshot of the default branch's protection
# settings for RSC.CMT.CTRL01.AR01, independent of whatever the ampel
# provider does internally (unverified whether its own EvaluationLog output
# carries raw evidence; see README "Known gaps"). This gives
# scripts/generate_rtm.py a concrete, digestable file to reference regardless.
#
# Requires: gh (authenticated via GITHUB_TOKEN env var), jq.

REPO="${RSC_REPO:-openshift-online/rosa-seaplane}"
BASE_REF="${RSC_BASE_REF:-main}"
OUT_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
# Named by requirement ID so scripts/generate_rtm.py can find it and compute
# a digest for the RTM's evidence_reference column.
OUT_FILE="${OUT_DIR}/RSC.CMT.CTRL01.AR01.json"

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
