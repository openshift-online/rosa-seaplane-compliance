#!/usr/bin/env python3
"""One deterministic findings report: findings, gaps in our work, limits of the checks.

Everything a person (or a model, later) needs to write the recommendations, with
nothing left to guess. Plain code over files already on disk: no AI, no network, no
collector is re-run, and the same inputs give the same output apart from the
timestamp.

It evaluates the policies over the existing evidence exactly as scripts/why.sh does
(conftest over every opa/*/policy, evidence files only) and keeps three kinds of
thing visibly apart:

  FINDINGS  one entry per denial, each with a rule, a subject, a fix hint and the
            KSIs the requirement serves. `kind` separates
              violation            the system does not meet the requirement
              incomplete-evidence  we could not tell (incomplete collection, a
                                   cross-check mismatch, a check that did not run)
              not-reached          a target the collector could not reach
            A failing check and an unchecked target are different things.
  GAPS      what is still missing in our own work, per in-phase KSI.
  LIMITS    what each check cannot see (evidence/known-gaps.yaml, plus what the
            Prowler-backed checks do not cover).

Rule ids and fix hints live in config/findings/rules.yaml. Writes output/findings.json
and output/findings.md. Both describe real findings: local only, never committed.

    build_findings.py [--evidence-dir D] [--coverage F] [--out-dir D]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_trace  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RULES_FILE = ROOT / "config/findings/rules.yaml"
LIMITS_FILE = ROOT / "evidence/known-gaps.yaml"
PROWLER_FILE = ROOT / "config/prowler/checks.yaml"
SCHEMA_VERSION = 1
# Same pinned version as tests/run.sh (tests/python/test_build_findings.py keeps them equal).
CONFTEST_IMAGE = os.environ.get("CONFTEST_IMAGE", "docker.io/openpolicyagent/conftest:v0.71.1")
KIND_ORDER = ("violation", "incomplete-evidence", "not-reached")
KIND_TITLES = {
    "violation": "Violations: the system does not meet the requirement",
    "incomplete-evidence": "Incomplete evidence: we could not tell",
    "not-reached": "Not reached: unchecked targets",
}
RULE_TAG = re.compile(r"^(?P<text>.*?)\s*\[rule: (?P<rule>[a-z0-9][a-z0-9.\-]*)\]\s*$", re.S)
ID_RE = re.compile(r"[0-9]{12}")
UNCLASSIFIED = "unclassified"
SUBJECTS_SHOWN = 10


class FindingsError(RuntimeError):
    pass


# --- small helpers ---------------------------------------------------------------

def mask(text) -> str:
    return ID_RE.sub("<ID>", str(text))


def mask_all(obj):
    """Belt and braces: no 12-digit sequence survives anywhere in the report."""
    if isinstance(obj, str):
        return mask(obj)
    if isinstance(obj, list):
        return [mask_all(x) for x in obj]
    if isinstance(obj, dict):
        return {mask_all(k): mask_all(v) for k, v in obj.items()}
    return obj


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text()) or {}


# --- inputs ----------------------------------------------------------------------

def load_rules(path: Path = RULES_FILE) -> dict:
    """{"rules": {id: entry}, "collection": {id: entry}} with subject patterns compiled."""
    doc = load_yaml(path)
    out = {"rules": {}, "collection": {}}
    for section, key in (("rules", "rules"), ("collection-rules", "collection")):
        for rid, entry in (doc.get(section) or {}).items():
            entry = dict(entry)
            if entry.get("kind") not in KIND_ORDER:
                raise FindingsError(f"{rid}: kind must be one of {', '.join(KIND_ORDER)}")
            entry["_subject"] = re.compile(entry["subject"]) if entry.get("subject") else None
            out[key][rid] = entry
    return out


def load_limits(limits_path: Path = LIMITS_FILE, prowler_path: Path = PROWLER_FILE) -> dict:
    """AR id -> [{text, source}]: the sidecar, plus what the Prowler-backed checks do not cover."""
    out = {}

    def add(ar, items, source):
        for t in items or []:
            if not isinstance(t, str):
                # An unquoted ": " in a YAML list item turns it into a mapping; never print that.
                raise FindingsError(f"{source}: {ar} has a limit that is not plain text ({t!r}); quote it")
            out.setdefault(ar, []).append({"text": " ".join(t.split()), "source": source})

    for ar, items in load_yaml(limits_path).items():
        add(ar, items, "evidence/known-gaps.yaml")
    if Path(prowler_path).is_file():
        for ar, spec in (load_yaml(prowler_path).get("assessment-requirements") or {}).items():
            add(ar, spec.get("does-not-cover"), "config/prowler/checks.yaml (does-not-cover)")
    return out


def conftest_argv() -> list:
    """The conftest command: CONFTEST_BIN, else one on PATH, else the pinned container."""
    if os.environ.get("CONFTEST_BIN"):
        return [os.environ["CONFTEST_BIN"]]
    if shutil.which("conftest"):
        return [shutil.which("conftest")]
    for runtime in ("podman", "docker"):
        if shutil.which(runtime):
            return [runtime, "run", "--rm", "-v", f"{ROOT}:/project:ro", "-w", "/project", CONFTEST_IMAGE]
    raise FindingsError("conftest is not installed and neither podman nor docker is available "
                        "(go install github.com/open-policy-agent/conftest@latest, or set CONFTEST_BIN).")


def evaluate(evidence_dir: Path, policy_dirs: list, argv: list, root: Path = ROOT) -> list:
    """Run the policies over every evidence file (never manifest.json), as why.sh does.

    Returns [{ar, file, target, evidence_generated_at, messages}] in a stable order.
    Reads local files only: no collector is run and nothing is fetched.
    """
    evidence_dir = Path(evidence_dir)
    files = []
    for ar_dir in sorted(p for p in evidence_dir.iterdir() if p.is_dir()):
        for f in sorted(ar_dir.glob("*.json")):
            if f.name != "manifest.json":
                files.append((ar_dir.name, f))
    if not files:
        return []
    def rel(f: Path) -> str:
        try:
            return str(f.resolve().relative_to(root.resolve()))
        except ValueError:
            return str(f)
    cmd = [*argv, "test", *[rel(f) for _, f in files]]
    for d in policy_dirs:
        cmd += ["-p", str(Path(d).relative_to(root)) if Path(d).is_absolute() else str(d)]
    cmd += ["--all-namespaces", "--output", "json"]
    res = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    try:
        results = json.loads(res.stdout)
    except ValueError:
        raise FindingsError(f"conftest produced no readable result (exit {res.returncode}): {mask(res.stderr.strip()[:300])}")
    by_file = {}
    for r in results:
        by_file.setdefault(r["filename"], []).extend(x["msg"] for x in r.get("failures") or [])
    out = []
    for ar, f in files:
        doc = json.loads(f.read_text())
        out.append({
            "ar": ar, "file": f.name,
            "target": doc.get("target") or doc.get("repository") or f.stem,
            "evidence_generated_at": doc.get("generated_at"),
            "messages": by_file.get(rel(f), []),
        })
    return out


def load_manifests(evidence_dir: Path) -> dict:
    out = {}
    for mf in sorted(Path(evidence_dir).glob("*/manifest.json")):
        out[mf.parent.name] = json.loads(mf.read_text())
    return out


# --- the report (pure) -----------------------------------------------------------

def parse_denial(raw: str, rules: dict) -> tuple:
    """(rule id, message without the tag). Untagged messages are 'unclassified'."""
    m = RULE_TAG.match(raw)
    if not m:
        return UNCLASSIFIED, raw.strip()
    return m.group("rule"), m.group("text").strip()


def subject_of(entry: dict, message: str, target: str) -> str:
    pat = (entry or {}).get("_subject")
    m = pat.search(message) if pat else None
    return m.group("subject") if m else target


def finding(ar: str, ars: dict, ksis_by_ar: dict, rule: str, entry: dict, kind: str, target: str, subject: str, message: str) -> dict:
    info = ars.get(ar) or {}
    return {
        "ar": ar, "ar_text": info.get("text"), "control": info.get("control"),
        "target": target, "rule": rule, "kind": kind,
        "title": (entry or {}).get("title") or "Denial without a rule id",
        "subject": subject, "message": message,
        "fix": " ".join(((entry or {}).get("fix") or "").split()),
        "ksis": sorted(ksis_by_ar.get(ar, [])),
    }


def natural(text: str) -> tuple:
    """'PR #9' sorts before 'PR #10'. Deterministic: digit runs compare as numbers."""
    return tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in re.split(r"(\d+)", str(text)) if part != "")


def sort_key(f: dict) -> tuple:
    kind = KIND_ORDER.index(f["kind"]) if f["kind"] in KIND_ORDER else len(KIND_ORDER)
    return (f["ar"], kind, f["rule"], natural(f["target"]), natural(f["subject"]), f["message"])


def gaps_from(coverage: dict, manifests: dict) -> list:
    """Per in-phase KSI: what is still missing in our own work."""
    out = []
    for row in coverage["ksis"]:
        unreached = []
        for m in row["methods"]:
            if not m.get("implemented"):
                continue
            for name in (m.get("scope") or {}).get("missing") or []:
                unreached.append({"ar": m["ar"], "target": name})
        unreached.sort(key=lambda x: (x["ar"], x["target"]))
        out.append({
            "ksi": row["id"], "name": row["name"], "state": row["state"], "type": row.get("type"),
            "methods_implemented": min(row["methods_implemented"], 2), "methods_required": 2,
            "open_controls": sorted(row["controls"].get("open", [])),
            "controls_decided": row["controls_decided"], "controls_total": row["controls_total"],
            "explanations": ("written" if row.get("narrative") else
                             "not written, or proposed and awaiting review" if row.get("has_record") else "no KSI record yet"),
            "next": list(row.get("next") or []),
            "targets_not_reached": unreached,
        })
    return sorted(out, key=lambda g: g["ksi"])


def build_report(evaluations: list, manifests: dict, ars: dict, coverage: dict, rules: dict, limits: dict,
                 now: datetime, evidence_ars: set = None) -> dict:
    """The whole report from pre-computed inputs. Pure: same inputs, same output."""
    ksis_by_ar = {}
    for row in coverage["ksis"]:
        for m in row["methods"]:
            ksis_by_ar.setdefault(m["ar"], set()).add(row["id"])

    findings = []
    for ev in evaluations:
        for raw in ev["messages"]:
            rule, message = parse_denial(raw, rules)
            entry = rules["rules"].get(rule)
            findings.append(finding(ev["ar"], ars, ksis_by_ar, rule, entry, (entry or {}).get("kind", "violation"),
                                    ev["target"], subject_of(entry, message, ev["target"]), message))

    # Targets the collectors could not reach: unchecked, which is not the same as failing.
    entry = rules["collection"]["collection.target-not-reached"]
    for ar, manifest in sorted(manifests.items()):
        seen = set()
        for t in manifest.get("targets", []):
            if t.get("status") != "collected":
                seen.add(t["name"])
                why = f"{t.get('status')}: {t.get('error')}" if t.get("error") else str(t.get("status"))
                findings.append(finding(ar, ars, ksis_by_ar, "collection.target-not-reached", entry, entry["kind"],
                                        t["name"], t["name"], " ".join(why.split())[:300]))
    # Targets coverage expected but that no manifest lists at all.
    for row in coverage["ksis"]:
        for m in row["methods"]:
            if not m.get("implemented"):
                continue
            listed = {t["name"] for t in (manifests.get(m["ar"]) or {}).get("targets", [])}
            for name in (m.get("scope") or {}).get("missing") or []:
                if name not in listed and (m["ar"], name) not in {(f["ar"], f["target"]) for f in findings if f["rule"] == "collection.target-not-reached"}:
                    findings.append(finding(m["ar"], ars, ksis_by_ar, "collection.target-not-reached", entry, entry["kind"],
                                            name, name, "not listed in the collector's manifest"))
    # A requirement with a method but no evidence at all.
    entry = rules["collection"]["collection.no-evidence"]
    have = set(evidence_ars if evidence_ars is not None else {e["ar"] for e in evaluations})
    for ar in sorted({m["ar"] for row in coverage["ksis"] for m in row["methods"] if m.get("implemented")} - have):
        findings.append(finding(ar, ars, ksis_by_ar, "collection.no-evidence", entry, entry["kind"], "*", "*",
                                "no evidence directory for this requirement"))

    # Several KSIs can serve one AR; one denial is still one finding.
    seen, unique = set(), []
    for f in sorted(findings, key=sort_key):
        k = (f["ar"], f["rule"], f["target"], f["subject"], f["message"])
        if k not in seen:
            seen.add(k)
            unique.append(f)
    findings = unique

    by_kind, by_ar, by_rule = {}, {}, {}
    for f in findings:
        by_kind[f["kind"]] = by_kind.get(f["kind"], 0) + 1
        by_ar.setdefault(f["ar"], {})
        by_ar[f["ar"]][f["kind"]] = by_ar[f["ar"]].get(f["kind"], 0) + 1
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    stamps = sorted(e["evidence_generated_at"] for e in evaluations if e.get("evidence_generated_at"))

    all_ars = sorted(set(limits) | {f["ar"] for f in findings} | set(ars))
    report = {
        "meta": {
            "schema_version": SCHEMA_VERSION,
            "generated_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "environment": coverage.get("environment"),
            "evidence_generated_at": {"oldest": stamps[0] if stamps else None, "newest": stamps[-1] if stamps else None},
            "evidence_files": len(evaluations),
            "counts": {"by_kind": dict(sorted(by_kind.items())), "by_ar": {k: dict(sorted(v.items())) for k, v in sorted(by_ar.items())},
                       "by_rule": dict(sorted(by_rule.items()))},
            "unclassified": by_rule.get(UNCLASSIFIED, 0),
        },
        "findings": findings,
        "gaps": gaps_from(coverage, manifests),
        "limits": {ar: {"ar_text": (ars.get(ar) or {}).get("text"), "limits": limits.get(ar, [])}
                   for ar in all_ars if ar in limits or ar in {f["ar"] for f in findings}},
    }
    return mask_all(report)


# --- markdown --------------------------------------------------------------------

def render_markdown(report: dict) -> str:
    meta, out = report["meta"], []
    counts = meta["counts"]["by_kind"]
    ev = meta["evidence_generated_at"]
    out += ["# Findings report", "",
            "> Local run. Not certification evidence. This describes real findings: do not publish it.", "",
            f"Environment: `{meta['environment']}`. Generated {meta['generated_at']}. "
            f"Evidence collected {ev['oldest']} to {ev['newest']} ({meta['evidence_files']} files). "
            "Built deterministically from files on disk: no AI, no network.", "",
            "Three kinds of thing are kept apart: **findings** (what the checks found, itself split into "
            "violations, incomplete evidence and unreached targets), **gaps** in our own work, and **limits** of the checks.", "",
            "## Summary", ""]
    for k in KIND_ORDER:
        out.append(f"- {counts.get(k, 0)} {k}")
    if meta["unclassified"]:
        out.append(f"- **{meta['unclassified']} denial(s) carry no rule id** (a policy needs fixing)")
    out += ["", "## Findings", ""]

    by_kind = {}
    for f in report["findings"]:
        by_kind.setdefault(f["kind"], []).append(f)
    for kind in [k for k in KIND_ORDER if k in by_kind] + [k for k in by_kind if k not in KIND_ORDER]:
        out += [f"### {KIND_TITLES.get(kind, kind)} ({len(by_kind[kind])})", ""]
        by_ar = {}
        for f in by_kind[kind]:
            by_ar.setdefault(f["ar"], []).append(f)
        for ar, items in by_ar.items():
            head = items[0]
            out.append(f"#### {ar}" + (f": {head['ar_text']}" if head["ar_text"] else ""))
            out.append(f"Serves: {', '.join(head['ksis']) or 'no KSI mapped'}")
            out.append("")
            by_rule = {}
            for f in items:
                by_rule.setdefault(f["rule"], []).append(f)
            for rule, group in by_rule.items():
                targets = sorted({f["target"] for f in group})
                out.append(f"- **{group[0]['title']}** (`{rule}`): {len(group)} finding(s) on {len(targets)} target(s)")
                if group[0]["fix"]:
                    out.append(f"  - Fix: {group[0]['fix']}")
                subjects = []
                for f in group:
                    label = f["subject"] if f["subject"] == f["target"] else f"{f['target']}: {f['subject']}"
                    if label not in subjects:
                        subjects.append(label)
                shown = subjects[:SUBJECTS_SHOWN]
                more = len(subjects) - len(shown)
                out.append("  - About: " + "; ".join(shown) + (f"; and {more} more (full list in findings.json)" if more > 0 else ""))
            out.append("")
    if not report["findings"]:
        out += ["No findings.", ""]

    out += ["## Gaps in our own work", "",
            "What is still missing, per KSI in this phase. Findings above are about the system; these are about our checks and records.", ""]
    started = [g for g in report["gaps"] if g["state"] != "Not started"]
    for g in started:
        out.append(f"- **{g['ksi']}** ({g['name']}): {g['state']}. Methods {g['methods_implemented']}/{g['methods_required']}. "
                   f"Related controls decided {g['controls_decided']}/{g['controls_total']}. Explanations: {g['explanations']}.")
        if g["open_controls"]:
            out.append(f"  - Open controls: {', '.join(g['open_controls'])}")
        if g["targets_not_reached"]:
            out.append("  - Targets not reached: " + ", ".join(f"{t['target']} ({t['ar']})" for t in g["targets_not_reached"]))
        if g["next"]:
            out.append(f"  - Next: {'; '.join(g['next'])}")
    idle = [g["ksi"] for g in report["gaps"] if g["state"] == "Not started"]
    if idle:
        out.append(f"- Not started ({len(idle)}): {', '.join(idle)}")
    out += ["", "## Limits of the checks", "",
            "What each check cannot see. A pass means no problem was found within these limits, not that none exists.", ""]
    for ar, spec in report["limits"].items():
        if not spec["limits"]:
            continue
        out.append(f"#### {ar}" + (f": {spec['ar_text']}" if spec["ar_text"] else ""))
        out += [f"- {x['text']}" for x in spec["limits"]]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# --- command line ----------------------------------------------------------------

def build(root: Path, evidence_dir: Path, coverage_path: Path, now: datetime, argv: list) -> dict:
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.is_dir() or not any(evidence_dir.glob("*/*.json")):
        raise FindingsError(f"no evidence in {evidence_dir}. Run `make run-local` first.")
    if not Path(coverage_path).is_file():
        raise FindingsError(f"{coverage_path} not found; run `make coverage` first.")
    coverage = json.loads(Path(coverage_path).read_text())
    _, ars = build_trace.load_catalogs(root)
    evaluations = evaluate(evidence_dir, sorted(root.glob("opa/*/policy")), argv, root)
    return build_report(evaluations, load_manifests(evidence_dir), ars, coverage, load_rules(), load_limits(), now,
                        evidence_ars={p.name for p in evidence_dir.iterdir() if p.is_dir()})


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence-dir", default=os.environ.get("RSC_EVIDENCE_DIR") or str(ROOT / "evidence/output"))
    ap.add_argument("--coverage", default=str(ROOT / "output/coverage.json"))
    ap.add_argument("--out-dir", default=str(ROOT / "output"))
    args = ap.parse_args()
    try:
        report = build(ROOT, Path(args.evidence_dir), Path(args.coverage), datetime.now(timezone.utc), conftest_argv())
    except FindingsError as e:
        sys.exit(f"ERROR: {e}")
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / "findings.md").write_text(render_markdown(report))
    c = report["meta"]["counts"]["by_kind"]
    print(f"Wrote {out / 'findings.json'} and {out / 'findings.md'}: "
          + ", ".join(f"{c.get(k, 0)} {k}" for k in KIND_ORDER))


if __name__ == "__main__":
    main()
