# Helpers for collectors whose targets are AWS accounts; sourced, not executed.
# Use together with collect.sh.
#
# AWS access follows the platform's own dev scripts and never touches
# ~/.aws/config: scripts/aws_access.py builds a temporary AWS config from the
# account snapshot and logs in with the SAML helper. A collector calls
# `rsc_aws_reexec "$0"` first, which re-runs it inside that temporary config, and
# then uses ONLY the read-only profile `rsc-<account>-ro` (never an admin profile).

# Re-run the calling collector inside the temporary AWS config (once).
rsc_aws_reexec() {
  if [[ -z "${RSC_AWS_READY:-}" ]]; then
    exec python3 "${RSC_ROOT}/scripts/aws_access.py" exec --env "${RSC_ENV:-integration}" -- env RSC_AWS_READY=1 "$1"
  fi
}

# Logical account names of the selected environment (never IDs).
rsc_aws_accounts() {
  python3 "${RSC_ROOT}/scripts/environment.py" --accounts "${RSC_ENV:-integration}"
}

# The regions of the selected environment, comma separated (us-east-1 is added by
# collectors that need it).
rsc_aws_regions() {
  python3 "${RSC_ROOT}/scripts/environment.py" --regions "${RSC_ENV:-integration}"
}

# The read-only profile for a logical account.
rsc_aws_ro_profile() { echo "rsc-$1-ro"; }
