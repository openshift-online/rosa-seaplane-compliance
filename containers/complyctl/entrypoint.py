#!/usr/bin/env python3
"""Container entrypoint: collect evidence, then run complyctl scan.

Runs every executable file in evidence/ (any language), each named by the AR
FQDN it serves; the AR's text is looked up in gemara/*/controls.yaml for the log
line. Assumes CWD is the repo root (true in the container at WORKDIR /workspace
and locally via `make run-local`).
"""
import os
import subprocess
import sys
from pathlib import Path

import yaml

EVIDENCE_DIR = Path("evidence")
CATALOG_GLOB = "gemara/*/controls.yaml"


def require_env(name: str, why: str) -> None:
    if not os.environ.get(name):
        sys.exit(f"ERROR: {name} must be set; {why}")


def ar_texts() -> dict:
    """AR id -> its assessment-requirement text, across every control catalog."""
    texts = {}
    for catalog in Path().glob(CATALOG_GLOB):
        doc = yaml.safe_load(catalog.read_text()) or {}
        for control in doc.get("controls", []):
            for ar in control.get("assessment-requirements", []):
                texts[ar["id"]] = " ".join((ar.get("text") or "").split())
    return texts


def run(cmd: list, check: bool = True) -> None:
    print(f"==> {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=check)


def main() -> None:
    require_env("GITHUB_TOKEN", "required by the ampel evaluator and the evidence collectors (gh api).")
    require_env("RSC_EVIDENCE_DIR", "the opa evaluator's input_path in .complytime/complytime.yaml references it directly.")

    texts = ar_texts()
    collectors = sorted(
        p for p in EVIDENCE_DIR.iterdir() if p.is_file() and os.access(p, os.X_OK)
    )
    for collector in collectors:
        fqdn = collector.stem
        text = texts.get(fqdn)
        label = f"{fqdn} ({text})" if text else fqdn
        print(f"==> Collecting evidence for {label}", flush=True)
        subprocess.run([str(collector.resolve())], check=True)

    run(["complyctl", "get"])
    run(["complyctl", "doctor", "--format", "text"], check=False)
    run(["complyctl", "scan", "rosa-seaplane", "--format", "oscal,sarif,pretty"])


if __name__ == "__main__":
    main()
