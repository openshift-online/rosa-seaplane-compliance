#!/usr/bin/env bash
set -euo pipefail

# Requires: aws CLI, uv, python3 (PyYAML), Prowler at the pinned version (README,
# one-time setup; found through $RSC_PROWLER or `prowler` on PATH), and the sibling
# checkouts rosa-seaplane and rosa-seaplane-internal (see docs/credentials.md).
# One evidence file per AWS account of the environment (RSC_ENV, default
# integration), plus a manifest; see evidence/lib/collect.sh and aws.sh.
#
# Evidence per account: the results of the Prowler checks chosen in
# config/prowler/checks.yaml (with the reason for each), normalized by
# lib/prowler_findings.py (see schemas/prowler-findings.cue). Prowler runs only through
# the read-only profile, for the environment's regions, and its raw output is
# discarded: only the fields the policy needs are kept.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)/lib"
source "${LIB_DIR}/collect.sh"
source "${LIB_DIR}/aws.sh"

rsc_aws_reexec "$0"

rsc_list_targets() { rsc_aws_accounts; }

collect_target() {
  local account="$1" out="$2" profile
  profile="$(rsc_aws_ro_profile "${account}")"
  python3 "${LIB_DIR}/prowler_findings.py" --ar "${AR_ID}" --target "${account}" --profile "${profile}" \
    --regions "$(rsc_aws_regions)" >"${out}" || return 1
}

rsc_collect_all
