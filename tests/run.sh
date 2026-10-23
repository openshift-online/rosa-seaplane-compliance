#!/usr/bin/env bash
set -euo pipefail

# Policy test suite, run through a pinned conftest container so the repo needs
# no local conftest install. Requires podman or docker.
#   - Rego unit tests (conftest verify) for RSC.CMT.CTRL01.AR02.
#   - Pass/fail fixtures run through the real policy (conftest test).
#   - AR01 (ampel) is stubbed; see the note at the end.
#
# Overrides: CONFTEST_IMAGE pins the image; CONFTEST_BIN=conftest uses a local
# binary instead of the container.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

OPA_POLICY="opa/change-management/policy"
AR02_FIX="tests/fixtures/RSC.CMT.CTRL01.AR02"
# Match the conftest version baked into containers/complyctl/Containerfile.
CONFTEST_IMAGE="${CONFTEST_IMAGE:-docker.io/openpolicyagent/conftest:v0.68.2}"

if [[ -n "${CONFTEST_BIN:-}" ]]; then
  conftest() { "${CONFTEST_BIN}" "$@"; }
else
  runtime=""
  for r in podman docker; do
    if command -v "${r}" >/dev/null 2>&1; then runtime="${r}"; break; fi
  done
  if [[ -z "${runtime}" ]]; then
    echo "ERROR: need podman or docker (or set CONFTEST_BIN to a local conftest)." >&2
    exit 1
  fi
  conftest() { "${runtime}" run --rm -v "${ROOT}:/project:ro" -w /project "${CONFTEST_IMAGE}" "$@"; }
fi

echo "== Rego unit tests =="
conftest verify -p "${OPA_POLICY}"

echo
echo "== AR02 fixture (compliant) must pass =="
conftest test "${AR02_FIX}/pass.json" -p "${OPA_POLICY}" --all-namespaces

echo
echo "== AR02 fixture (violations) must fail =="
if conftest test "${AR02_FIX}/fail.json" -p "${OPA_POLICY}" --all-namespaces >/dev/null 2>&1; then
  echo "FAIL: violations fixture was not denied" >&2
  exit 1
fi
echo "OK: violations correctly denied"

echo
echo "== AR01 (ampel) =="
echo "SKIP: not wired yet. AR01 is checked by ampel's builtin github/branch-rules"
echo "      spec against the live repo, so there is no authored policy to unit-test."
echo "      Fixtures staged at tests/fixtures/RSC.CMT.CTRL01.AR01/{pass,fail}.json."

echo
echo "All implemented tests passed."
