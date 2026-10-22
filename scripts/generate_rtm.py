#!/usr/bin/env python3
"""Generate a certification-specific Requirements Traceability Matrix (RTM).

One CSV per Gemara MappingDocument (one per certification). Each row states
which certification requirement a control satisfies and how it's evidenced,
from this repo's own source data. Structural and stable between scans: no
pass/fail result (that lives in the EvaluationLog / coverage report).

Usage:
    python3 scripts/generate_rtm.py \\
        --mapping mappings/change-management-to-ksi.mapping.yaml \\
        --policy gemara/change-management/policy.yaml \\
        --out rtm/change-management-to-ksi.csv
"""
import argparse
import csv
import os

import yaml

FIELDNAMES = [
    "requirement_id",
    "relationship",
    "our_requirement_id",
    "evidence_method",
    "rationale",
    "notes",
]


def load_evidence_methods(policy_path: str) -> dict:
    """requirement-id -> evaluation-method description(s), from a Gemara Policy."""
    with open(policy_path) as f:
        policy = yaml.safe_load(f)
    methods = {}
    for plan in policy.get("adherence", {}).get("assessment-plans", []):
        req_id = plan.get("requirement-id")
        descriptions = [m.get("description", "") for m in plan.get("evaluation-methods", [])]
        methods[req_id] = " / ".join(d for d in descriptions if d)
    return methods


def build_rows(mapping_path: str, evidence_methods: dict) -> list:
    with open(mapping_path) as f:
        mapdoc = yaml.safe_load(f)
    rows = []
    for m in mapdoc.get("mappings", []):
        source = m["source"]
        for t in m.get("targets", []):
            rows.append(
                {
                    "requirement_id": t["entry-id"],
                    "relationship": m.get("relationship", ""),
                    "our_requirement_id": source,
                    "evidence_method": evidence_methods.get(source, ""),
                    "rationale": t.get("rationale", ""),
                    "notes": t.get("remarks", ""),
                }
            )
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mapping", required=True, help="One Gemara MappingDocument YAML (one certification).")
    ap.add_argument("--policy", required=True, help="Gemara Policy YAML providing evidence-method descriptions.")
    ap.add_argument("--out", required=True, help="Output CSV path.")
    args = ap.parse_args()

    evidence_methods = load_evidence_methods(args.policy)
    rows = build_rows(args.mapping, evidence_methods)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} row(s) to {args.out}")


if __name__ == "__main__":
    main()
