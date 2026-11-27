#!/usr/bin/env bash
set -euo pipefail

# Explain why an assessment requirement (AR) failed: for every evidence file the
# collector wrote for it, print what the policy denies, and list any target the
# collector could not reach. The scan itself records only one result and one
# message per AR, so this is where the per-target reasons are.
#
#   ./scripts/why.sh RSC.CMT.CTRL01.AR02
#
# Needs a local conftest and a previous `make run-local`. Reads only local files.

AR="${1:?usage: $0 <AR id, e.g. RSC.CMT.CTRL01.AR02>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
DIR="${RSC_EVIDENCE_DIR:-evidence/output}/${AR}"

if [[ ! -d "${DIR}" ]]; then
  echo "No evidence for ${AR} in ${DIR}. Run 'make run-local' first, or check the AR id." >&2
  exit 1
fi
if ! command -v conftest >/dev/null 2>&1; then
  echo "conftest is not installed (go install github.com/open-policy-agent/conftest@latest)." >&2
  exit 1
fi

policy_args=()
for d in opa/*/policy; do policy_args+=(-p "${d}"); done

echo "== ${AR}: targets the collector could not reach"
if [[ -f "${DIR}/manifest.json" ]]; then
  jq -r '.targets[] | select(.status != "collected") | "  \(.name): \(.status) \(.error // "")"' "${DIR}/manifest.json" | { grep . || echo "  none"; }
else
  echo "  no manifest.json (the collector did not finish)"
fi

echo
echo "== ${AR}: what the policy denies, per evidence file"
total=0
shopt -s nullglob
for f in "${DIR}"/*.json; do
  [[ "$(basename "${f}")" == "manifest.json" ]] && continue
  # conftest exits non-zero when it denies; the denials are what we want.
  msgs="$(conftest test "${f}" "${policy_args[@]}" --all-namespaces --output json 2>/dev/null \
    | jq -r '.[].failures[]?.msg' || true)"
  if [[ -n "${msgs}" ]]; then
    n="$(wc -l <<<"${msgs}" | tr -d ' ')"
    total=$((total + n))
    echo "-- $(basename "${f}" .json): ${n} denial(s)"
    sed 's/^/   /' <<<"${msgs}"
  else
    echo "-- $(basename "${f}" .json): no denials"
  fi
done
echo
echo "${total} denial(s) in total."
