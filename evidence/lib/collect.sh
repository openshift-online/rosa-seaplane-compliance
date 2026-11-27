# Shared by the evidence collectors; sourced, not executed (so the entrypoint,
# which runs every executable file directly under evidence/, skips it).
#
# A collector defines `collect_repo <owner/name> <out-file>` (or `collect_target
# <name> <out-file>` when its targets are not repositories, e.g. AWS accounts, in
# which case it also defines `rsc_list_targets`; see evidence/lib/aws.sh) (write one JSON
# evidence document, exit non-zero on failure). It runs where `set -e` is
# ignored, so guard every command with `|| return 1` and then calls
# `rsc_collect_all`. That runs it for every repository in config/scope.yaml,
# writing:
#   $EVIDENCE_DIR/<AR>/<repo-name>.json  one evidence file per repository
#   $EVIDENCE_DIR/<AR>/manifest.json     per-target status for coverage
#
# One repository failing never stops the others: it is recorded in the
# manifest as `error` so that missing scope is visible and is never confused
# with a failing check. Needs AR_ID, EVIDENCE_DIR, jq and python3 (PyYAML).

RSC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RSC_ROOT="$(cd "${RSC_LIB_DIR}/../.." && pwd)"

# Repositories to collect from: RSC_REPOS (space separated) overrides
# config/scope.yaml, for one-off runs and tests.
rsc_repos() {
  if [[ -n "${RSC_REPOS:-}" ]]; then
    tr ' ' '\n' <<<"${RSC_REPOS}"
  else
    python3 -c '
import sys, yaml
print("\n".join(yaml.safe_load(open(sys.argv[1]))["github-repositories"]))
' "${RSC_SCOPE_FILE:-${RSC_ROOT}/config/scope.yaml}"
  fi
}

# The repository's default branch, unless RSC_BASE_REF pins one.
rsc_default_branch() {
  if [[ -n "${RSC_BASE_REF:-}" ]]; then echo "${RSC_BASE_REF}"; else gh api "repos/$1" --jq .default_branch; fi
}

# The UTC day an EVENT collector covers (see day_window.py): RSC_DATE, default yesterday.
# Sets DAY_DATE, DAY_START, DAY_END (half-open) and DAY_BACKFILL (true/false), or exits
# non-zero with the reason. State collectors never call this: they judge the present.
rsc_day_window() {
  local day
  day="$(python3 "${RSC_LIB_DIR}/day_window.py")" || return 1
  DAY_DATE="$(jq -r .covers_date <<<"${day}")"
  DAY_START="$(jq -r .start <<<"${day}")"
  DAY_END="$(jq -r .end <<<"${day}")"
  DAY_BACKFILL="$(jq -r .backfill <<<"${day}")"
}

# Run a command, retrying a few times: GitHub's API returns transient 5xx
# (e.g. HTTP 502/504) on heavy GraphQL queries, and sometimes a truncated
# response ("unexpected end of JSON input") or a dropped connection. Anything else,
# 4xx included, fails at once.
rsc_retry() {
  local attempt out rc=0 errf
  errf="$(mktemp)"
  for attempt in 1 2 3; do
    # Capture the status on the same line: `rc=$?` after an `if` reads 0.
    out="$("$@" 2>"${errf}")" && { rm -f "${errf}"; printf '%s' "${out}"; return 0; }
    rc=$?
    grep -q -E 'HTTP 5[0-9][0-9]|unexpected end of JSON input|unexpected EOF|connection reset|i/o timeout|TLS handshake timeout' "${errf}" || break
    sleep $((attempt * 2))
  done
  cat "${errf}" >&2
  rm -f "${errf}"
  return "${rc}"
}

# Prow's Tide merge requirements for a repository, normalized (see
# prow_tide_gate.py), read from the Prow config repo (openshift/release).
# A missing config file means "no Tide gate"; any other failure (auth, rate
# limit, 5xx) is an error, never "no gate".
RSC_PROW_CONFIG_REPO="${RSC_PROW_CONFIG_REPO:-openshift/release}"
RSC_PROW_CONFIG_DIR="${RSC_PROW_CONFIG_DIR:-core-services/prow/02_config}"

rsc_prow_config_file() {
  local path="$1" errf out
  errf="$(mktemp)"
  if out="$(rsc_retry gh api "repos/${RSC_PROW_CONFIG_REPO}/contents/${path}" -H 'Accept: application/vnd.github.raw' 2>"${errf}")"; then
    printf '%s' "${out}"
  elif grep -q "HTTP 404" "${errf}"; then
    :
  else
    cat "${errf}" >&2; rm -f "${errf}"; return 1
  fi
  rm -f "${errf}"
}

rsc_tide_gate() {
  local repo="$1" branch="$2" owner="${1%%/*}" name="${1##*/}" tmp files=() cfg path gate
  tmp="$(mktemp -d)"
  for path in "${RSC_PROW_CONFIG_DIR}/${owner}/${name}/_prowconfig.yaml" "${RSC_PROW_CONFIG_DIR}/${owner}/_prowconfig.yaml"; do
    cfg="$(rsc_prow_config_file "${path}")" || { rm -rf "${tmp}"; return 1; }
    if [[ -n "${cfg}" ]]; then
      printf '%s\n' "${cfg}" >"${tmp}/${#files[@]}.yaml"
      files+=("${tmp}/${#files[@]}.yaml")
    fi
  done
  gate="$(python3 "${RSC_LIB_DIR}/prow_tide_gate.py" "${repo}" "${branch}" "${files[@]}")" || { rm -rf "${tmp}"; return 1; }
  rm -rf "${tmp}"
  printf '%s' "${gate}"
}

# The targets to collect from. Repositories by default; an AWS collector overrides it.
rsc_list_targets() { rsc_repos; }

# The status check contexts a repository's branch protection REQUIRES on a branch,
# as JSON: {"protected": bool, "contexts": [sorted unique names]}. Both the classic
# `contexts` list and the newer `checks[].context` entries are read.
# "Branch not protected" (404) is not an error: it means no required checks (AR01
# is the check that reports the missing protection). Any other failure (auth, rate
# limit, 5xx, unknown repository) is an error, never "no required checks".
rsc_required_checks() {
  local repo="$1" branch="$2" raw errf
  errf="$(mktemp)"
  if raw="$(rsc_retry gh api "repos/${repo}/branches/${branch}/protection" 2>"${errf}")"; then
    rm -f "${errf}"
    jq -c '{protected: true,
            contexts: ([(.required_status_checks.contexts // [])[],
                        ((.required_status_checks.checks // [])[] | .context)] | unique)}' <<<"${raw}"
  elif grep -q "Branch not protected" "${errf}"; then
    rm -f "${errf}"
    printf '%s' '{"protected":false,"contexts":[]}'
  else
    cat "${errf}" >&2
    rm -f "${errf}"
    return 1
  fi
}

rsc_collect_all() {
  local out_dir="${EVIDENCE_DIR}/${AR_ID}" repo name err targets="[]" ok=0 failed=0 collect_fn=collect_repo
  declare -F collect_target >/dev/null && collect_fn=collect_target
  mkdir -p "${out_dir}"
  # Evidence from a previous run must not survive into this one.
  find "${out_dir}" -maxdepth 1 -name '*.json' -delete

  while IFS= read -r repo; do
    [[ -n "${repo}" ]] || continue
    name="${repo##*/}"
    if err="$("${collect_fn}" "${repo}" "${out_dir}/${name}.json" 2>&1 >/dev/null)"; then
      targets="$(jq --arg n "${repo}" '. + [{name: $n, status: "collected"}]' <<<"${targets}")"
      ok=$((ok + 1))
    else
      rm -f "${out_dir}/${name}.json"
      # First line only: enough to tell auth from not-found, short enough to be safe.
      targets="$(jq --arg n "${repo}" --arg e "$(head -n 1 <<<"${err}" | cut -c1-200)" \
        '. + [{name: $n, status: "error", error: $e}]' <<<"${targets}")"
      failed=$((failed + 1))
      echo "WARN: ${AR_ID}: could not collect ${repo}: $(head -n 1 <<<"${err}")" >&2
    fi
  done < <(rsc_list_targets)

  # No assessment_requirement key: the Rego packages judge every JSON file under
  # input_path, and the manifest is not evidence about any repository.
  # An event collector also says which day it covered (DAY_DATE, see rsc_day_window).
  jq -n --arg ar "${AR_ID}" --arg env "${RSC_ENV:-integration}" --arg day "${DAY_DATE:-}" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson targets "${targets}" \
    '{ar: $ar, environment: $env, generated_at: $at, targets: $targets}
     + (if $day != "" then {covers_date: $day} else {} end)' >"${out_dir}/manifest.json"

  echo "${AR_ID}: collected ${ok} target(s), ${failed} error(s); manifest at ${out_dir}/manifest.json" >&2
  [[ "${ok}" -gt 0 ]] || { echo "ERROR: ${AR_ID}: no target could be collected." >&2; return 1; }
}
