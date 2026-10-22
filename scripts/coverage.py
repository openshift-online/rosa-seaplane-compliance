#!/usr/bin/env python3
"""Report certification coverage: which of a certification's required
requirements our assessment requirements (ARs) cover, and which are still open.

Structural, not pass/fail: diffs our Gemara MappingDocument(s) against a
certification's required-requirement baseline. No scan / EvaluationLog needed.
"""
import argparse

import yaml


def load_baseline(path: str) -> tuple:
    """(ordered required IDs, metadata) from a baseline YAML."""
    with open(path) as f:
        b = yaml.safe_load(f)
    required = list(dict.fromkeys(b.get("required", [])))
    return required, b


def load_covered(mapping_paths: list) -> dict:
    """target entry-id -> set of our AR ids that map to it, across mappings."""
    covered = {}
    for path in mapping_paths:
        with open(path) as f:
            mapdoc = yaml.safe_load(f)
        for m in mapdoc.get("mappings", []):
            for t in m.get("targets", []):
                covered.setdefault(t["entry-id"], set()).add(m["source"])
    return covered


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--baseline", required=True, help="Certification baseline YAML (the required set).")
    ap.add_argument("--mapping", action="append", required=True, help="Gemara MappingDocument YAML; repeatable.")
    args = ap.parse_args()

    required, meta = load_baseline(args.baseline)
    covered_map = load_covered(args.mapping)

    covered = [r for r in required if r in covered_map]
    missing = [r for r in required if r not in covered_map]
    extras = sorted(set(covered_map) - set(required))

    label = f"{meta.get('target', '?')} coverage ({meta.get('certification', '?')})"
    print(f"{label}: {len(covered)}/{len(required)} covered\n")
    print(f"COVERED ({len(covered)}):")
    print("  " + (", ".join(sorted(covered)) or "(none)"))
    print(f"\nNOT COVERED ({len(missing)}):")
    print("  " + (", ".join(sorted(missing)) or "(none)"))
    if extras:
        print(f"\nMAPPED BUT NOT IN BASELINE ({len(extras)}); baseline may be stale:")
        print("  " + ", ".join(extras))


if __name__ == "__main__":
    main()
