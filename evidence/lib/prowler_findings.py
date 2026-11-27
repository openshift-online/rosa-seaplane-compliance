#!/usr/bin/env python3
"""Run the Prowler checks for one assessment requirement in one account, and
normalize the result into prowler-findings evidence.

    prowler_findings.py --ar <AR id> --target <logical account name> \\
        --profile <read-only profile> --regions us-east-1[,..] [--prowler PATH]

Which checks run, and the one Prowler version allowed, come from
config/prowler/checks.yaml (with the reasons). Prints the evidence document
described in schemas/prowler-findings.cue.

Safeguards, so that nothing reads as a pass that should not:
  * only a read-only profile (name ending "-ro") is accepted;
  * the Prowler version must equal the pinned one, read from the installed package
    (not from `prowler --version`, which calls out to GitHub);
  * a failed Prowler run is an error (no evidence file), never an empty result;
  * output that is missing or unreadable gives complete=false;
  * the raw output (account IDs, ARNs, compliance text) is never kept: only the
    fields in the schema, with 12-digit numbers masked, and the temporary output
    directory is removed.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
CHECKS_FILE = ROOT / "config/prowler/checks.yaml"
ID_RE = re.compile(r"[0-9]{12}")
DETAIL_MAX = 300


class ProwlerError(RuntimeError):
    pass


def mask(text) -> str:
    return ID_RE.sub("<account>", str(text if text is not None else ""))


def load_checks(ar: str, path: Path = CHECKS_FILE) -> tuple:
    """(pinned version, [check ids]) for an assessment requirement."""
    doc = yaml.safe_load(Path(path).read_text()) or {}
    version = str(doc.get("prowler-version") or "")
    entry = (doc.get("assessment-requirements") or {}).get(ar)
    if not version or not entry or not entry.get("checks"):
        raise ProwlerError(f"{ar}: no pinned version or no checks in {path}")
    return version, [c["id"] for c in entry["checks"]]


def _interpreter(binary: str) -> str:
    """The Python that runs the installed `prowler` script (from its shebang)."""
    path = shutil.which(binary) or binary
    try:
        first = Path(path).read_text(errors="ignore").splitlines()[0]
    except (OSError, IndexError):
        return sys.executable
    if first.startswith("#!"):
        parts = first[2:].split()
        if parts and parts[0].endswith("/env") and len(parts) > 1:
            return shutil.which(parts[1]) or sys.executable
        if parts and "python" in Path(parts[0]).name:
            return parts[0]
    return sys.executable


def installed_version(binary: str) -> str:
    code = "import importlib.metadata as m; print(m.version('prowler'))"
    res = subprocess.run([_interpreter(binary), "-c", code], capture_output=True, text=True)
    if res.returncode != 0:
        raise ProwlerError(f"cannot read the installed Prowler version: {res.stderr.strip()[:200]}")
    return res.stdout.strip()


def normalize(ocsf: list, required: list) -> list:
    """OCSF detection findings -> the fields the policy needs, nothing else."""
    out = []
    for f in ocsf:
        check = (f.get("metadata") or {}).get("event_code")
        if check not in required:
            continue
        res = (f.get("resources") or [{}])[0]
        out.append({
            "check_id": check,
            "status": str(f.get("status_code") or "UNKNOWN").upper(),
            "region": str(res.get("region") or (f.get("cloud") or {}).get("region") or ""),
            "resource_type": mask(res.get("type")),
            "resource_name": mask(res.get("name") or "-"),
            "detail": mask(f.get("status_detail") or f.get("message") or "")[:DETAIL_MAX],
        })
    return sorted(out, key=lambda x: (x["check_id"], x["region"], x["resource_name"]))


def run_prowler(binary: str, profile: str, regions: list, checks: list, timeout: int) -> list:
    tmp = tempfile.mkdtemp(prefix="rsc-prowler-")
    try:
        cmd = [binary, "aws", "--profile", profile, "--region", *regions, "--checks", *checks,
               "--output-formats", "json-ocsf", "--output-directory", tmp, "--output-filename", "rsc",
               "--no-banner", "--no-color", "--ignore-exit-code-3"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ProwlerError(f"Prowler did not finish within {timeout}s") from None
        except OSError as e:
            raise ProwlerError(f"cannot run Prowler ({binary}): {e}") from None
        if res.returncode != 0:
            raise ProwlerError(f"Prowler failed (exit {res.returncode}): {mask((res.stderr or res.stdout).strip()[-300:])}")
        files = sorted(Path(tmp).glob("*.ocsf.json"))
        if not files:
            return None  # ran, but wrote nothing we can read
        try:
            data = json.loads(files[0].read_text())
        except ValueError:
            return None
        return data if isinstance(data, list) else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def collect(ar: str, target: str, profile: str, regions: list, binary: str, timeout: int,
            checks_file: Path = CHECKS_FILE, now: datetime = None) -> dict:
    if not profile.endswith("-ro"):
        raise ProwlerError(f"refusing profile {profile!r}: only a read-only (-ro) profile may be used")
    pinned, checks = load_checks(ar, checks_file)
    version = installed_version(binary)
    if version != pinned:
        raise ProwlerError(f"Prowler {version} is installed but {pinned} is pinned in config/prowler/checks.yaml; "
                           f"install the pinned version (see README)")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ocsf = run_prowler(binary, profile, regions, checks, timeout)
    return {
        "assessment_requirement": ar,
        "generated_at": now,
        "target": target,
        "target_type": "aws_accounts",
        "collection": {
            "complete": ocsf is not None and len(ocsf) > 0,
            "source": "prowler",
            "prowler_version": version,
            "required_checks": checks,
            "regions": regions,
            "generated_at": now,
        },
        "findings": normalize(ocsf or [], checks),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ar", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--regions", required=True, help="comma separated")
    ap.add_argument("--prowler", default=os.environ.get("RSC_PROWLER") or "prowler")
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("RSC_PROWLER_TIMEOUT", "900")))
    args = ap.parse_args()
    regions = [r for r in args.regions.split(",") if r]
    if not regions:
        sys.exit("ERROR: no regions to check")
    try:
        print(json.dumps(collect(args.ar, args.target, args.profile, regions, args.prowler, args.timeout), indent=2))
    except ProwlerError as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
