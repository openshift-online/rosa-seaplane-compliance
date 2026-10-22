#!/usr/bin/env python3
"""Roll up a complyctl EvaluationLog against Gemara MappingDocuments.

Prints MET / NOT MET per mapping target (KSI, NIST control, ...). MET only
when every assessment-requirement mapped to it passed. Auto-discovers the
latest EvaluationLog under --scan-dir; pass --evaluation-log to override.
"""
import argparse
import collections
import glob
import os
import sys

import yaml


def find_latest_evaluation_log(scan_dir: str) -> str:
    candidates = glob.glob(os.path.join(scan_dir, "**", "*evaluation-log*.y*ml"), recursive=True)
    if not candidates:
        candidates = glob.glob(os.path.join(scan_dir, "**", "*.yaml"), recursive=True)
        candidates += glob.glob(os.path.join(scan_dir, "**", "*.yml"), recursive=True)
    if not candidates:
        sys.exit(
            f"No EvaluationLog found under {scan_dir!r}. Run `complyctl scan` first. "
            "If one exists under a name this script doesn't recognize, pass "
            "--evaluation-log <path> explicitly."
        )
    return max(candidates, key=os.path.getmtime)


def load_assessment_results(log_path: str) -> dict:
    with open(log_path) as f:
        log = yaml.safe_load(f)
    results = {}
    for ev in log.get("evaluations", []):
        for al in ev.get("assessment-logs", []):
            req_id = al.get("requirement", {}).get("entry-id")
            if req_id:
                results[req_id] = al.get("result", "Not Run")
    return results


def rollup_mapping(mapping_path: str, results: dict) -> list:
    with open(mapping_path) as f:
        mapdoc = yaml.safe_load(f)
    rollup = collections.defaultdict(list)
    for m in mapdoc.get("mappings", []):
        for t in m.get("targets", []):
            rollup[t["entry-id"]].append(results.get(m["source"], "Not Run"))
    rows = []
    for target, target_results in sorted(rollup.items()):
        met = all(r == "Passed" for r in target_results)
        rows.append((target, "MET" if met else "NOT MET", target_results))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--mapping",
        action="append",
        required=True,
        help="Path to a Gemara MappingDocument YAML; repeatable.",
    )
    ap.add_argument(
        "--scan-dir",
        default=".complytime/scan",
        help="Directory to search for the latest EvaluationLog (default: .complytime/scan).",
    )
    ap.add_argument(
        "--evaluation-log",
        default=None,
        help="Explicit EvaluationLog path (skips auto-discovery under --scan-dir).",
    )
    args = ap.parse_args()

    log_path = args.evaluation_log or find_latest_evaluation_log(args.scan_dir)
    print(f"Using EvaluationLog: {log_path}\n")
    results = load_assessment_results(log_path)

    for mapping_path in args.mapping:
        print(f"=== {os.path.basename(mapping_path)} ===")
        rows = rollup_mapping(mapping_path, results)
        if not rows:
            print("  (no mappings found)")
        for target, status, target_results in rows:
            print(f"  {target:16} {status:8} {target_results}")
        print()


if __name__ == "__main__":
    main()
