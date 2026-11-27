#!/usr/bin/env bash
set -euo pipefail

# Requires: aws CLI, gh (GITHUB_TOKEN), uv, python3 (PyYAML), jq, and the sibling
# checkouts rosa-seaplane and rosa-seaplane-internal (see docs/credentials.md).
# One evidence file per deployment pipeline of the environment (RSC_ENV, default
# integration; the pipelines and their account are listed under `deployment:` in
# config/environments/<env>.yaml), plus a manifest; see evidence/lib/collect.sh and aws.sh.
#
# EVENT collector for ONE UTC day (RSC_DATE, default yesterday; see lib/day_window.py).
# Evidence per pipeline: whether every change merged to the deployed branch on that day was
# applied by a successful run, and whether the head is deployed (the head and the latest run
# are the present, so a backfill does not judge them). A day with no merge passes. See
# lib/deployment_pipeline.py for the method and its limits, and schemas/deployment-pipeline.cue. Read-only: the pipeline's account is read through its
# read-only profile (never an admin profile), the repository through gh.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)/lib"
source "${LIB_DIR}/collect.sh"
source "${LIB_DIR}/aws.sh"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh reads the merged pull requests and the branch head)." >&2
  exit 1
fi

rsc_day_window || exit 1
rsc_aws_reexec "$0"

# The deployment pipelines of the environment. An environment without a deployment block
# is an error, never a guess: the collection then finds no target and fails.
rsc_list_targets() {
  python3 "${RSC_ROOT}/scripts/environment.py" --pipelines "${RSC_ENV:-integration}"
}

collect_target() {
  local pipeline="$1" out="$2" dep account profile
  dep="$(python3 "${RSC_ROOT}/scripts/environment.py" --deployment "${RSC_ENV:-integration}")" || return 1
  account="$(jq -r --arg p "${pipeline}" '.pipelines[] | select(.name == $p) | .account' <<<"${dep}")"
  [[ -n "${account}" ]] || { echo "pipeline ${pipeline} is not in the environment's deployment block" >&2; return 1; }
  profile="$(rsc_aws_ro_profile "${account}")"
  python3 "${LIB_DIR}/deployment_pipeline.py" --ar "${AR_ID}" --target "${pipeline}" --profile "${profile}" \
    --region "$(rsc_aws_regions | cut -d, -f1)" \
    --repository "$(jq -r .repository <<<"${dep}")" --branch "$(jq -r '.branch // ""' <<<"${dep}")" \
    --lag-minutes "$(jq -r .allowed_lag_minutes <<<"${dep}")" \
    --date "${DAY_DATE}" >"${out}" || return 1
}

rsc_collect_all
