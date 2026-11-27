#!/usr/bin/env bash
set -euo pipefail

# Requires: aws CLI, uv, python3 (PyYAML), and the sibling checkouts rosa-seaplane
# and rosa-seaplane-internal (see docs/credentials.md).
# One evidence file per AWS account of the environment (RSC_ENV, default
# integration), plus a manifest; see evidence/lib/collect.sh and aws.sh.
#
# EVENT collector for ONE UTC day (RSC_DATE, default yesterday; see lib/day_window.py).
# Evidence per account: whether any long-term access key authenticated on that day, found by
# asking CloudTrail for the events of each existing key and cross-checking IAM's last-used
# record. A day with no key or no event is a complete, empty collection and passes. See
# lib/iam_key_usage.py for the method and its limits (the keys listed are those that exist
# now), and schemas/principal-key-usage.cue.
# Read-only: list, get and lookup calls through the read-only profile only.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)/lib"
source "${LIB_DIR}/collect.sh"
source "${LIB_DIR}/aws.sh"

rsc_day_window || exit 1
rsc_aws_reexec "$0"

rsc_list_targets() { rsc_aws_accounts; }

collect_target() {
  local account="$1" out="$2" profile
  profile="$(rsc_aws_ro_profile "${account}")"
  python3 "${LIB_DIR}/iam_key_usage.py" --ar "${AR_ID}" --target "${account}" --profile "${profile}" \
    --date "${DAY_DATE}" --regions "$(rsc_aws_regions)" >"${out}" || return 1
}

rsc_collect_all
