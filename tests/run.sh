#!/usr/bin/env bash
set -euo pipefail

# Policy test suite, run through a pinned conftest container so the repo needs
# no local conftest install. Requires podman or docker.
#   - Rego unit tests (conftest verify) for every assessment requirement.
#   - Pass/fail fixtures run through the real policy (conftest test), with
#     every package evaluating every fixture as the opa provider does.
#
# Overrides: CONFTEST_IMAGE pins the image; CONFTEST_BIN=conftest uses a local
# binary instead of the container.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

# Prefer the local .venv (see requirements.txt) unless PYTHON is set.
if [[ -z "${PYTHON:-}" && -x .venv/bin/python ]]; then PYTHON=.venv/bin/python; fi

# Every domain's Rego: opa/<domain>/policy.
POLICY_ARGS=()
for d in opa/*/policy; do POLICY_ARGS+=(-p "${d}"); done
# Match the conftest version baked into containers/complyctl/Containerfile.
CONFTEST_IMAGE="${CONFTEST_IMAGE:-docker.io/openpolicyagent/conftest:v0.71.1}"

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
conftest verify "${POLICY_ARGS[@]}"

echo
for fix in tests/fixtures/*/; do
  AR="$(basename "${fix}")"
  echo "== ${AR} fixture (compliant) must pass =="
  conftest test "tests/fixtures/${AR}/pass.json" "${POLICY_ARGS[@]}" --all-namespaces

  echo
  echo "== ${AR} fixture (violations) must fail =="
  if conftest test "tests/fixtures/${AR}/fail.json" "${POLICY_ARGS[@]}" --all-namespaces >/dev/null 2>&1; then
    echo "FAIL: ${AR} violations fixture was not denied" >&2
    exit 1
  fi
  echo "OK: violations correctly denied"
  echo
done

echo
echo "== complypack: contract validation and fixture schema checks =="
if ! command -v complypack >/dev/null 2>&1; then
  echo "SKIP: complypack not installed (go install github.com/complytime/complypack/cmd/complypack@latest)."
else
  # Each Rego file declares its platform schema in a "# platform: <name>"
  # header and the AR it judges in its `applies` rule.
  for REGO in opa/*/policy/*.rego; do
    case "${REGO}" in *_test.rego) continue ;; esac
    PLATFORM="$(sed -n 's/^# platform: //p' "${REGO}")"
    AR="$(sed -n 's/.*input\.assessment_requirement == "\(.*\)"$/\1/p' "${REGO}")"
    if [[ -z "${PLATFORM}" || -z "${AR}" ]]; then
      echo "FAIL: ${REGO} needs a '# platform:' header and an 'applies' rule on assessment_requirement" >&2
      exit 1
    fi
    SCHEMA="${PLATFORM}=file://${ROOT}/schemas/${PLATFORM}.cue"
    complypack validate-policy "${REGO}" --platform "${PLATFORM}" --schema "${SCHEMA}" --format text
    for f in pass fail; do
      complypack test-policy "${REGO}" --platform "${PLATFORM}" --schema "${SCHEMA}" \
        --test-data "tests/fixtures/${AR}/${f}.json" --format text
    done
  done
fi

echo
echo "== Python unit tests =="
"${PYTHON:-python3}" -I -m unittest discover -s tests/python -p 'test_*.py'

echo
echo "All implemented tests passed."
