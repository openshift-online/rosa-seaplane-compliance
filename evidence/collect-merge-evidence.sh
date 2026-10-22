#!/usr/bin/env bash
set -euo pipefail

# Collects the merge-practice evidence for RSC.CMT.CTRL01.AR02, the "did the
# gate actually hold" check run by the opa provider against
# opa/change-management/policy/merge_review.rego. Writes a flattened JSON
# document; complyctl's opa provider points conftest at the directory this
# script writes into (see complytime.yaml's `input_path` target variable).
#
# Requires: gh (authenticated via GITHUB_TOKEN env var; gh reads it
# automatically, no `gh auth login` needed), jq.
#
# Orders by UPDATED_AT (GitHub has no MERGED_AT sort) and filters by
# mergedAt within the first 100 results. Add pagination if merge volume ever
# exceeds that per window.

REPO="${RSC_REPO:-openshift-online/rosa-seaplane}"
BASE_REF="${RSC_BASE_REF:-main}"
WINDOW_DAYS="${RSC_WINDOW_DAYS:-30}"
OUT_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
# Named by requirement ID so scripts/generate_rtm.py can find it and compute
# a digest for the RTM's evidence_reference column.
OUT_FILE="${OUT_DIR}/RSC.CMT.CTRL01.AR02.json"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh CLI reads it for GraphQL auth)." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

OWNER="${REPO%%/*}"
NAME="${REPO##*/}"

RAW="$(gh api graphql -f query='
  query($owner: String!, $name: String!, $baseRefName: String!) {
    repository(owner: $owner, name: $name) {
      pullRequests(states: MERGED, baseRefName: $baseRefName, first: 100,
                    orderBy: {field: UPDATED_AT, direction: DESC}) {
        nodes {
          number
          mergedAt
          author { login }
          reviewDecision
          mergedBy { login }
          commits(last: 1) {
            nodes { commit { statusCheckRollup { state } } }
          }
        }
      }
    }
  }' -f owner="${OWNER}" -f name="${NAME}" -f baseRefName="${BASE_REF}")"

jq --arg repo "${REPO}" \
  --arg base_ref "${BASE_REF}" \
  --argjson window_days "${WINDOW_DAYS}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '
  ($window_days * 86400) as $window_seconds
  | (now - $window_seconds | gmtime | strftime("%Y-%m-%dT%H:%M:%SZ")) as $cutoff
  | {
      generated_at: $generated_at,
      repository: $repo,
      base_ref: $base_ref,
      window_days: $window_days,
      pull_requests: [
        .data.repository.pullRequests.nodes[]
        | select(.mergedAt >= $cutoff)
        | {
            number: .number,
            merged_at: .mergedAt,
            author: .author.login,
            merged_by: .mergedBy.login,
            review_decision: (.reviewDecision // "NONE"),
            status_check_state: (.commits.nodes[0].commit.statusCheckRollup.state // "NONE")
          }
      ]
    }
  ' <<<"${RAW}" >"${OUT_FILE}"

echo "Wrote $(jq '.pull_requests | length' "${OUT_FILE}") merged PR(s) to ${OUT_FILE}" >&2
