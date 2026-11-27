#!/usr/bin/env bash
set -euo pipefail

# Requires: aws CLI, uv, python3 (PyYAML), jq, and the sibling checkouts rosa-seaplane and
# rosa-seaplane-internal (see docs/credentials.md). No GitHub access is needed.
# One evidence file per cluster of the environment (RSC_ENV, default integration; the
# clusters, the account whose metrics API is read and the lookback window are listed under
# `deployment: health:` in config/environments/<env>.yaml), plus a manifest; see
# evidence/lib/collect.sh and aws.sh.
#
# Evidence per cluster: whether the applications the deployment tool manages are
# synchronized and healthy, and whether any stayed unhealthy for the whole lookback window
# (default 30 minutes). See lib/argocd_health.py for the exact rules and their limits, and
# schemas/deployment-health.cue. Read-only: signed GET queries against the platform's
# metrics API through the account's read-only profile (never an admin profile); no cluster
# access is used or needed.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)/lib"
source "${LIB_DIR}/collect.sh"
source "${LIB_DIR}/aws.sh"

rsc_aws_reexec "$0"

# The clusters whose workloads are health-checked. An environment without a health block
# is an error, never a guess: the collection then finds no target and fails.
rsc_list_targets() {
  python3 "${RSC_ROOT}/scripts/environment.py" --clusters "${RSC_ENV:-integration}"
}

collect_target() {
  local cluster="$1" out="$2" health account profile
  health="$(python3 "${RSC_ROOT}/scripts/environment.py" --health "${RSC_ENV:-integration}")" || return 1
  account="$(jq -r .account <<<"${health}")"
  profile="$(rsc_aws_ro_profile "${account}")"
  python3 "${LIB_DIR}/argocd_health.py" --ar "${AR_ID}" --target "${cluster}" --profile "${profile}" \
    --region "$(rsc_aws_regions | cut -d, -f1)" \
    --lookback-minutes "$(jq -r .lookback_minutes <<<"${health}")" \
    --freshness-seconds "$(jq -r .freshness_seconds <<<"${health}")" \
    --step-seconds "$(jq -r .step_seconds <<<"${health}")" >"${out}" || return 1
}

rsc_collect_all
