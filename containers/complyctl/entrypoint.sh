#!/usr/bin/env bash
set -euo pipefail

# Assumes CWD is the repo root (complytime.yaml, evidence/, scripts/,
# mappings/ as siblings), true both in the container (WORKDIR /workspace)
# and locally via `make run-local`.

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set, required by both the ampel provider" >&2
  echo "(branch-protection reads) and evidence/collect-merge-evidence.sh (gh api)." >&2
  exit 1
fi

if [[ -z "${RSC_EVIDENCE_DIR:-}" ]]; then
  echo "ERROR: RSC_EVIDENCE_DIR must be set to an ABSOLUTE path (opa-provider" >&2
  echo "requirement); complytime.yaml's opa input_path references it directly." >&2
  exit 1
fi

echo "==> Collecting AR01 branch-protection evidence (gh api)"
./evidence/collect-branch-protection-evidence.sh

echo "==> Collecting AR02 merge-practice evidence (gh api)"
./evidence/collect-merge-evidence.sh

echo "==> complyctl get"
complyctl get

echo "==> complyctl doctor (non-fatal; surfaces provider/prereq issues in logs)"
complyctl doctor --format text || true

echo "==> complyctl scan"
complyctl scan rosa-seaplane --format oscal,sarif,pretty

echo "==> Reporting KSI / NIST coverage"
python3 scripts/report.py \
  --mapping mappings/change-management-to-ksi.mapping.yaml \
  --mapping mappings/change-management-to-nist.mapping.yaml
