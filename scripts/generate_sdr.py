#!/usr/bin/env python3
"""Generate the FedRAMP Security Decision Record (JSON) from existing outputs.

A transform over what the other tools already produced, so it could move
upstream later:
  output/coverage.json         KSI states, methods, scope (make coverage)
  mappings/fedramp-20x/ksi/    KSI records: the hand-written explanations
  gemara/*/policy.yaml         planned cycle (frequency)
  .complytime/scan/            latest L5 EvaluationLogs (results only)

Writes output/sdr/sdr.json and validates it against the vendored schema.

Never emitted: assessor content, local paths, account IDs, ARNs, usernames, or
raw evaluation messages (they can name people). Failed results stay visible. An
AR with no result is "not evaluated", never passed.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fedramp_data  # noqa: E402
import history_summary  # noqa: E402
import ksi_data  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "mappings/vendor/fedramp/schemas"
SDR_SCHEMA = SCHEMA_DIR / "fedramp-security-decision-record-schema-2026-06-24.json"
CPO_PLACEHOLDER = "urn:rosa-seaplane:cpo:not-yet-published"
SDR_VERSION = "0.1.0"
KNOWN_RESULTS = {"passed", "failed"}
LEAK_PATTERNS = (r"/Users/", r"file://", r"[0-9]{12}", r"arn:aws")


def load_results(scan_dir: Path) -> dict:
    """AR ID -> {"result", "time"}: the newest result per AR across L5 logs.

    Only the result and its timestamp are kept. Messages and evidence payloads
    carry local paths and usernames.
    """
    latest = {}
    for path in sorted(scan_dir.glob("evaluation-log-*.yaml")):
        doc = yaml.safe_load(path.read_text()) or {}
        for ev in doc.get("evaluations", []):
            for log in ev.get("assessment-logs", []):
                ar = (log.get("requirement") or {}).get("entry-id")
                start = log.get("start")
                if not ar or not start:
                    continue
                when = start if isinstance(start, datetime) else datetime.fromisoformat(str(start))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                result = str(log.get("result", "")).lower()
                if ar not in latest or when > latest[ar]["time"]:
                    latest[ar] = {"result": result if result in KNOWN_RESULTS else "inconclusive",
                                  "time": when}
    return latest


def load_automation_summary(evidence_dir: Path) -> dict:
    """AR ID -> {merged, automation_exempt, exemption_approved} summed over targets.

    Only evidence files carrying a `summary` count (AR02 today). Says how many
    merges relied on the documented automation exemption (config/automation.yaml).
    """
    out = {}
    for ar_dir in sorted(p for p in Path(evidence_dir).glob("*") if p.is_dir()):
        merged = exempt = files = 0
        approved = True
        for f in sorted(ar_dir.glob("*.json")):
            if f.name == "manifest.json":
                continue
            try:
                summary = (json.loads(f.read_text()) or {}).get("summary")
            except ValueError:
                continue
            if not summary:
                continue
            files += 1
            merged += int(summary.get("merged", 0))
            exempt += int(summary.get("automation_exempt", 0))
            approved = approved and bool(summary.get("exemption_approved"))
        if files:
            out[ar_dir.name] = {"merged": merged, "automation_exempt": exempt, "exemption_approved": approved}
    return out


def automation_sentence(summary: dict) -> str:
    """Plain statement of how much the result leans on the exemption, or ''."""
    if not summary or not summary.get("merged"):
        return ""
    state = "approved" if summary["exemption_approved"] else "proposed, approval pending"
    return (f"{summary['automation_exempt']} of {summary['merged']} merged PRs counted as approved by automation "
            f"under the documented exemption in config/automation.yaml ({state}).")


def load_frequencies(gemara_dir: Path) -> dict:
    """AR ID -> planned frequency, from every domain's policy.yaml."""
    freq = {}
    for p in sorted(gemara_dir.glob("*/policy.yaml")):
        doc = yaml.safe_load(p.read_text()) or {}
        for plan in doc.get("adherence", {}).get("assessment-plans", []):
            if plan.get("frequency"):
                freq[plan["requirement-id"]] = plan["frequency"]
    return freq


def cycle_text(freqs: set) -> str:
    if not freqs:
        return "Planned cycle: none defined yet."
    planned = ", ".join(sorted(freqs))
    return (f"Planned cycle: {planned}. Currently run manually from a developer laptop; "
            "nothing schedules the checks yet.")


def evidence_for(method: dict, results: dict, automation: dict = None) -> dict:
    res = results.get(method["ar"])
    sc = method["scope"]
    reached = (f"reached {sc['reached']} of {sc['total']} in-scope targets" if sc["run"]
               else "target coverage unknown (no collection manifest)")
    if res is None:
        text = f"{method['ar']}: not evaluated. {reached[0].upper() + reached[1:]}."
        updated = None
    else:
        text = (f"{method['ar']}: {res['result']} (evaluator {method['executor']}). "
                f"{reached[0].upper() + reached[1:]}.")
        updated = res["time"].astimezone(timezone.utc).strftime("%Y-%m-%d")
    note = automation_sentence((automation or {}).get(method["ar"]))
    if note:
        text += " " + note
    ev = {"evidenceType": "Report",
          "evidenceDescription": f"Latest evaluation result for {method['ar']}",
          "evidenceText": text}
    if updated:
        ev["lastUpdated"] = updated
    return ev


def implementation_status(state: str) -> str:
    if state == "SDR-ready":
        return "Implemented"
    if state == "Not started":
        return "Not Implemented"
    return "Partially Implemented"


def ksi_entry(row: dict, record: dict, freqs: dict, results: dict, automation: dict = None, history: dict = None) -> dict:
    record = record or {}
    implemented = [m for m in row["methods"] if m["implemented"]]

    implementation = []
    if str(record.get("measures") or "").strip():
        implementation.append(record["measures"].strip())
    if row["state"] == "Not started":
        implementation.append("No automated method is implemented for this KSI yet.")
    else:
        implementation.append(cycle_text({freqs[m["ar"]] for m in implemented if m["ar"] in freqs}))

    validation = []
    for m in implemented:
        if m["rationale"].strip():
            validation.append(f"{m['ar']}: {m['rationale'].strip()}")
    for key in ("automation-verification", "validation"):
        if str(record.get(key) or "").strip():
            validation.append(record[key].strip())

    evidence = [evidence_for(m, results, automation) for m in implemented]
    line = history_summary.history_sentence(((history or {}).get("ksis") or {}).get(row["id"]))
    if line and evidence:
        item = {"evidenceType": "Report", "evidenceDescription": "History of daily results (30-day summary)",
                "evidenceText": line}
        last = (history.get("history") or {}).get("last_record_day")
        if last:
            item["lastUpdated"] = last
        evidence.append(item)

    return {
        "ksiId": row["id"],
        "ksiImplementationStatus": implementation_status(row["state"]),
        "ksiImplementation": implementation,
        "ksiValidation": validation,
        "ksiAssessment": [],  # assessor content; never invented
        "ksiTests": [m["ar"] for m in implemented],
        "ksiEvidence": evidence,
    }


def build_sdr(coverage: dict, records: dict, freqs: dict, results: dict, now: datetime, automation: dict = None,
              history: dict = None) -> dict:
    return {
        "certificationPackageOverviewUri": CPO_PLACEHOLDER,
        "metadata": {
            "version": SDR_VERSION,
            "lastUpdated": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updateSource": f"local-run ({coverage['environment']})",
        },
        "fedRampRequirements": [],  # out of scope for this phase
        "keySecurityIndicators": [
            ksi_entry(row, records.get(row["id"]), freqs, results, automation, history) for row in coverage["ksis"]
        ],
    }


def validate_sdr(sdr: dict) -> None:
    """Raise jsonschema.ValidationError if the SDR breaks the vendored schema."""
    import jsonschema
    from referencing import Registry, Resource

    resources = []
    for p in SCHEMA_DIR.glob("*.json"):
        doc = json.loads(p.read_text())
        resources.append((doc["$id"], Resource.from_contents(doc)))
    schema = json.loads(SDR_SCHEMA.read_text())
    validator = jsonschema.Draft202012Validator(
        schema, registry=Registry().with_resources(resources),
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)
    validator.validate(sdr)


def find_leaks(text: str) -> list:
    return [p for p in LEAK_PATTERNS if re.search(p, text)]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--coverage", default=str(ROOT / "output/coverage.json"))
    ap.add_argument("--scan-dir", default=str(ROOT / ".complytime/scan"))
    ap.add_argument("--evidence-dir", default=str(ROOT / "evidence/output"))
    ap.add_argument("--history-summary", default=str(ROOT / "output/history/summary.json"),
                    help="from `make history-summary`; adds a 30-day history line per KSI when it exists")
    ap.add_argument("--out", default=str(ROOT / "output/sdr/sdr.json"))
    args = ap.parse_args()

    cov_path = Path(args.coverage)
    if not cov_path.is_file():
        sys.exit(f"ERROR: {cov_path} not found; run `make coverage` first.")
    coverage = json.loads(cov_path.read_text())
    ksis = fedramp_data.load_ksis()
    hist_path = Path(args.history_summary)
    history = json.loads(hist_path.read_text()) if hist_path.is_file() else None
    sdr = build_sdr(coverage, ksi_data.load_records(ksis), load_frequencies(ROOT / "gemara"),
                    load_results(Path(args.scan_dir)), datetime.now(timezone.utc),
                    load_automation_summary(Path(args.evidence_dir)), history)

    text = json.dumps(sdr, indent=2) + "\n"
    leaks = find_leaks(text)
    if leaks:
        sys.exit(f"ERROR: refusing to write an SDR matching sensitive patterns: {leaks}")
    validate_sdr(sdr)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(f"Wrote {out} ({len(sdr['keySecurityIndicators'])} KSI entries)")


if __name__ == "__main__":
    main()
