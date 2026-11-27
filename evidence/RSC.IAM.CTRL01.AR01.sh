#!/usr/bin/env bash
set -euo pipefail

# Requires: aws CLI, uv, jq, python3 (PyYAML), and the sibling checkouts
# rosa-seaplane and rosa-seaplane-internal (see docs/credentials.md).
# One evidence file per AWS account of the environment (RSC_ENV, default
# integration), plus a manifest; see evidence/lib/collect.sh and aws.sh.
#
# Evidence per account: the IAM credential report, normalized (see
# schemas/principal-credentials.cue and lib/iam_credential_report.py). Read-only: it
# only generates and reads the credential report, through the read-only profile.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)/lib"
source "${LIB_DIR}/collect.sh"
source "${LIB_DIR}/aws.sh"

rsc_aws_reexec "$0"

rsc_list_targets() { rsc_aws_accounts; }

collect_target() {
  local account="$1" out="$2" profile state="" report i
  profile="$(rsc_aws_ro_profile "${account}")"
  # AWS builds the report asynchronously, and at most once every four hours.
  for i in $(seq 1 "${RSC_CREDENTIAL_REPORT_TRIES:-20}"); do
    state="$(aws --profile "${profile}" iam generate-credential-report --query State --output text)" || return 1
    [[ "${state}" == "COMPLETE" ]] && break
    sleep "${RSC_CREDENTIAL_REPORT_SLEEP:-3}"
  done
  [[ "${state}" == "COMPLETE" ]] || { echo "credential report not ready (state ${state})" >&2; return 1; }
  report="$(aws --profile "${profile}" iam get-credential-report --output json)" || return 1
  python3 "${LIB_DIR}/iam_credential_report.py" --ar "${AR_ID}" --target "${account}" <<<"${report}" >"${out}" || return 1
}

rsc_collect_all
