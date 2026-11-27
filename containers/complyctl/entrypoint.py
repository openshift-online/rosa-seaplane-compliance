#!/usr/bin/env python3
"""Container entrypoint: collect evidence, then run complyctl scan.

Runs every executable file in evidence/ (any language), each named by the AR
FQDN it serves; the AR's text is looked up in gemara/*/controls.yaml for the log
line. Assumes CWD is the repo root (true in the container at WORKDIR /workspace
and locally via `make run-local`).
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

# evidence/lib is under the working directory (/workspace in the container, the repo root locally).
sys.path[:0] = [str(Path.cwd() / "evidence/lib"), str(Path(__file__).resolve().parents[2] / "evidence/lib")]
import day_window  # noqa: E402

EVIDENCE_DIR = Path("evidence")
CATALOG_GLOB = "gemara/*/controls.yaml"
POLICY_GLOB = "gemara/*/policy.yaml"


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


def policy_ids() -> list:
    """complyctl policy IDs: one per control domain (gemara/<domain>/policy.yaml)."""
    return sorted(p.parent.name for p in Path().glob(POLICY_GLOB))


def policy_ars() -> list:
    """Every AR the policies assess, across all domains."""
    ars = []
    for policy in sorted(Path().glob(POLICY_GLOB)):
        doc = yaml.safe_load(policy.read_text()) or {}
        for plan in doc.get("adherence", {}).get("assessment-plans", []):
            ars.append(plan["requirement-id"])
    return ars


def missing_evidence(ars: list, evidence_dir: Path) -> list:
    """ARs with no evidence file that declares itself evidence for that AR.

    The Rego packages only judge evidence carrying their own
    assessment_requirement, so an AR with no evidence yields no denials and
    would look like a pass. It must fail the run instead.
    """
    missing = []
    for ar in ars:
        found = False
        for f in sorted((evidence_dir / ar).glob("*.json")):
            try:
                found = json.loads(f.read_text()).get("assessment_requirement") == ar
            except (ValueError, AttributeError):
                found = False
            if found:
                break
        if not found:
            missing.append(ar)
    return missing


def reset_generation_cache(workspace: Path = Path(".complytime")) -> None:
    """Make complyctl regenerate the opa scan configuration before the next scan.

    The opa provider stores ONE generated scan configuration per target INPUT PATH
    (complytime-providers internal/genindex TargetKey), not per policy or per
    target id. All our policies read the same evidence directory, so each policy's
    generation overwrites the previous one's. complyctl's own per-policy cache
    still says "up to date", so from the second run on it skips regenerating and
    the provider scans a policy with whichever configuration was written last:
    change-management would evaluate identity-access's requirements. Clearing both
    caches before each scan forces generate-then-scan for that policy, in order.
    Remove this once the provider keys its generated state by policy.
    """
    for sub in ("generation", "opa/generated"):
        shutil.rmtree(workspace / sub, ignore_errors=True)


def fix_the_day(environ: dict = None, now=None) -> dict:
    """Decide ONCE which UTC day the event collectors cover and tell them all (RSC_DATE), so a run that
    crosses midnight cannot split between two days. Default yesterday; refused when the day is not
    complete, is too old, has not settled (RSC_SETTLE_MINUTES, RSC_ALLOW_EARLY=1) or is a backfill: this
    entrypoint scans the present, and a past day is collected by `make daily DATE=...`."""
    environ = os.environ if environ is None else environ
    try:
        day = day_window.resolve(environ.get("RSC_DATE"), now,
                                 int(environ.get("RSC_SETTLE_MINUTES") or day_window.DEFAULT_SETTLE_MINUTES),
                                 allow_early=environ.get("RSC_ALLOW_EARLY") == "1")
    except (day_window.DayError, ValueError) as e:
        sys.exit(f"ERROR: {e}")
    if day["backfill"]:
        sys.exit(f"ERROR: {day['covers_date']} is a past day, so it is a backfill: the state checks and the scan would "
                 "judge the present, not that day. Use `make daily DATE=...` to collect a past day.")
    environ["RSC_DATE"] = day["covers_date"]
    return day


def run(cmd: list, check: bool = True) -> None:
    print(f"==> {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=check)


def main() -> None:
    require_env("GITHUB_TOKEN", "required by the evidence collectors (gh api).")
    require_env("RSC_EVIDENCE_DIR", "the opa evaluator's input_path in .complytime/complytime.yaml references it directly.")

    env_name = os.environ.get("RSC_ENV", "integration")
    if not Path(f"config/environments/{env_name}.yaml").is_file():
        sys.exit(f"ERROR: unknown RSC_ENV {env_name!r}; expected a file in config/environments/.")

    day = fix_the_day()
    print(f"==> The event checks cover the UTC day {day['covers_date']} (the state checks judge now)", flush=True)

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

    missing = missing_evidence(policy_ars(), Path(os.environ["RSC_EVIDENCE_DIR"]))
    if missing:
        sys.exit(
            "ERROR: no evidence collected for " + ", ".join(missing)
            + "; refusing to scan, since missing evidence would look like a pass."
        )

    run(["complyctl", "get"])
    run(["complyctl", "doctor", "--format", "text"], check=False)
    # No target name: scans every target configured for the policy.
    # check=False: complyctl exits non-zero when any AR fails, which is a
    # finding to report, not a pipeline error.
    for policy_id in policy_ids():
        reset_generation_cache()
        run(
            ["complyctl", "scan", "--policy-id", policy_id, "--format", "oscal,sarif,pretty"],
            check=False,
        )


if __name__ == "__main__":
    main()
