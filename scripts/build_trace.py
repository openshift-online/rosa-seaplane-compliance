#!/usr/bin/env python3
"""Build output/trace.json: the data behind the assessment-requirement (AR) pages.

The AR is the narrow middle of the trail. Above it is the "why": links to
requirements (KSIs, 800-53 controls, any framework a mapping file names), each
with a rationale. Below it is the "how and proof": plan, collector, schema,
Rego, fixtures, the targets reached, and the latest result.

Everything is derived from files that already exist: the control catalogs and
policies (gemara/*/), the mapping documents (mappings/*.mapping.yaml), the Rego
packages and their complytime-mapping.json, collector manifests, the latest
complyctl L5 EvaluationLog, and output/coverage.json. Nothing is hardcoded to a
domain, AR ID or framework: a second certification is just another mapping file.

Results are recorded at AR level only (passed / failed / not evaluated), as the
scan records them. Per-target pass/fail is not in the L5 log and is not
reconstructed here; per-target *scope* (reached / error) comes from manifests.

Implementation links are resolved by convention and by explicit pointers, and
the build FAILS, listing every problem, when one does not resolve:
  evidence/<AR>.sh                         the collector
  opa/<domain>/policy/complytime-mapping.json   AR -> Rego package
  the .rego file with that `package`       the logic
  `# schema: schemas/<name>.cue` header    the evidence shape (explicit pointer)
  tests/fixtures/<AR>/{pass,fail}.json     fixtures (absence is reported, not fatal)
Only ARs whose policy plan declares an Automated evaluation method are required
to resolve.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fedramp_data  # noqa: E402
import environment as environment_config  # noqa: E402
import generate_sdr  # noqa: E402
import ksi_data  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = 1
KSI_FRAMEWORK = "fedramp-ksi-controls"  # the framework whose entries are the dataset's KSIs
KNOWN_RESULTS = {"passed", "failed"}
PACKAGE_RE = re.compile(r"^package\s+([\w.]+)", re.M)
HEADER_RE = re.compile(r"^#\s*(platform|schema):\s*(\S+)\s*$", re.M)


class TraceError(Exception):
    """One or more links did not resolve; the message lists all of them."""


def squash(text) -> str:
    return " ".join(str(text or "").split())


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- loading ------------------------------------------------------------------

def load_catalogs(root: Path) -> tuple:
    """(controls, ars) across every gemara/<domain>/controls.yaml."""
    controls, ars = {}, {}
    for path in sorted(root.glob("gemara/*/controls.yaml")):
        domain = path.parent.name
        for ctl in load_yaml(path).get("controls", []):
            ar_ids = []
            for ar in ctl.get("assessment-requirements", []):
                ars[ar["id"]] = {
                    "id": ar["id"], "text": squash(ar.get("text")), "control": ctl["id"], "domain": domain,
                    "applicability": list(ar.get("applicability") or []), "state": ar.get("state"),
                }
                ar_ids.append(ar["id"])
            controls[ctl["id"]] = {
                "id": ctl["id"], "title": ctl.get("title"), "objective": squash(ctl.get("objective")),
                "group": ctl.get("group"), "domain": domain, "catalog_file": rel(root, path), "ars": ar_ids,
            }
    return controls, ars


def load_plans(root: Path) -> dict:
    """AR ID -> its policy assessment plan, flattened."""
    plans = {}
    for path in sorted(root.glob("gemara/*/policy.yaml")):
        for plan in load_yaml(path).get("adherence", {}).get("assessment-plans", []):
            methods = plan.get("evaluation-methods") or []
            m = methods[0] if methods else {}
            ex = m.get("executor") or {}
            plans[plan["requirement-id"]] = {
                "id": plan["id"], "frequency": plan.get("frequency"), "policy_file": rel(root, path),
                "method": m.get("id"), "type": m.get("type"), "mode": m.get("mode"),
                "required": m.get("required"), "description": squash(m.get("description")),
                "executor": ex.get("id"), "executor_name": ex.get("name"),
            }
    return plans


def load_rego(root: Path) -> dict:
    """domain -> {"mapping": {AR: package}, "files": {package: {file, platform, schema}}}."""
    out = {}
    for pol in sorted(root.glob("opa/*/policy")):
        domain = pol.parent.name
        mapping, files = {}, {}
        mp = pol / "complytime-mapping.json"
        if mp.is_file():
            for m in json.loads(mp.read_text()).get("mappings", []):
                mapping[m["requirement_id"]] = m["id"]
        for f in sorted(pol.glob("*.rego")):
            if f.name.endswith("_test.rego"):
                continue
            text = f.read_text()
            pkg = PACKAGE_RE.search(text)
            if not pkg:
                continue
            headers = dict(HEADER_RE.findall(text))
            files[pkg.group(1)] = {"file": rel(root, f), "platform": headers.get("platform"),
                                   "schema": headers.get("schema")}
        out[domain] = {"mapping": mapping, "files": files}
    return out


def resolve_impl(root: Path, ar: dict, plan: dict, rego: dict, problems: list):
    """The AR's implementation links, or None when it declares no automated method."""
    if not plan or plan.get("mode") != "Automated":
        return None
    ar_id, domain = ar["id"], ar["domain"]

    collector = root / "evidence" / f"{ar_id}.sh"
    collector_rel = rel(root, collector) if collector.is_file() else None
    if collector_rel is None:
        problems.append(f"{ar_id}: no collector at evidence/{ar_id}.sh")

    dom = rego.get(domain, {"mapping": {}, "files": {}})
    pkg = dom["mapping"].get(ar_id)
    rego_info = dom["files"].get(pkg) if pkg else None
    if pkg is None:
        problems.append(f"{ar_id}: not in opa/{domain}/policy/complytime-mapping.json")
    elif rego_info is None:
        problems.append(f"{ar_id}: no .rego under opa/{domain}/policy declares package {pkg}")

    schema = None
    if rego_info is not None:
        schema = rego_info["schema"]
        if not schema:
            problems.append(f"{rego_info['file']}: missing a '# schema: schemas/<name>.cue' header")
        elif not schema.startswith("schemas/") or not (root / schema).is_file():
            problems.append(f"{rego_info['file']}: '# schema: {schema}' does not point at an existing file under schemas/")
            schema = None

    fixtures = {n: (root / "tests/fixtures" / ar_id / f"{n}.json").is_file() for n in ("pass", "fail")}
    test_file = None
    if rego_info is not None:
        t = root / rego_info["file"].replace(".rego", "_test.rego")
        test_file = rel(root, t) if t.is_file() else None
    return {
        "collector": collector_rel, "rego_package": pkg, "rego_file": rego_info["file"] if rego_info else None,
        "rego_test_file": test_file, "platform": rego_info["platform"] if rego_info else None,
        "schema": schema, "fixtures": fixtures,
        "evaluator": plan.get("executor"),
    }


def load_links(root: Path, ars: dict, problems: list) -> tuple:
    """(frameworks, links) from every mappings/*.mapping.yaml of ARs."""
    frameworks, links = {}, []
    for path in sorted(root.glob("mappings/*.mapping.yaml")):
        doc = load_yaml(path)
        if (doc.get("source-reference") or {}).get("entry-type") != "AssessmentRequirement":
            continue
        fw = (doc.get("target-reference") or {}).get("reference-id")
        if not fw:
            problems.append(f"{rel(root, path)}: no target-reference.reference-id")
            continue
        refs = {r.get("id"): r for r in (doc.get("metadata") or {}).get("mapping-references", [])}
        entry = frameworks.setdefault(fw, {"id": fw, "title": (refs.get(fw) or {}).get("title") or fw,
                                           "mapping_files": []})
        entry["mapping_files"].append(rel(root, path))
        for m in doc.get("mappings", []):
            if m["source"] not in ars:
                problems.append(f"{rel(root, path)}: mapping {m.get('id')} names unknown AR {m['source']}")
                continue
            for t in m.get("targets", []):
                links.append({
                    "ar": m["source"], "framework": fw, "requirement_raw": str(t["entry-id"]),
                    "mapping_file": rel(root, path), "mapping_id": m.get("id"),
                    "relationship": m.get("relationship"), "strength": t.get("strength"),
                    "rationale": squash(t.get("rationale")),
                })
    return frameworks, links


def classify(raw: str, ksis: dict) -> tuple:
    """(kind, normalized id): a dataset KSI, a NIST-style control ID, or any other requirement."""
    if raw in ksis:
        return "ksi", raw
    try:
        return "control", fedramp_data.normalize_control_id(raw)
    except ValueError:
        return "requirement", raw


# --- scope and results --------------------------------------------------------

def load_scope(root: Path, ars: dict, evidence_dir: Path, environment_name: str = None) -> dict:
    """AR ID -> targets reached / errored / not reached, from collector manifests."""
    scope_file = root / "config/scope.yaml"
    declared = load_yaml(scope_file) if scope_file.is_file() else {}
    automation = generate_sdr.load_automation_summary(evidence_dir)
    out = {}
    for ar_id, ar in ars.items():
        expected = []
        for a in ar["applicability"]:
            listed = list(declared.get(a.replace("_", "-")) or [])
            if not listed and a == "aws_accounts":
                # Not declared in config/scope.yaml: use the logical account names of
                # the environment config (never IDs).
                listed = environment_config.account_names(environment_name)
            if not listed and a == "deployment_pipelines":
                # Likewise the deployment pipelines the environment config lists.
                listed = environment_config.pipeline_names(environment_name)
            if not listed and a == "deployment_clusters":
                # And the clusters whose deployed applications are health-checked.
                listed = environment_config.cluster_names(environment_name)
            expected += listed
        mf = evidence_dir / ar_id / "manifest.json"
        manifest = json.loads(mf.read_text()) if mf.is_file() else None
        got = {t["name"]: t for t in (manifest or {}).get("targets", [])}
        if not expected:
            expected = list(got)
        names = expected + [n for n in got if n not in expected]
        targets = []
        for n in names:
            if manifest is None:
                targets.append({"name": n, "status": "not run"})
            elif n not in got:
                targets.append({"name": n, "status": "not reached"})
            elif got[n].get("status") == "collected":
                targets.append({"name": n, "status": "reached"})
            else:
                targets.append({"name": n, "status": "error", "error": squash(got[n].get("error"))[:200]})
        out[ar_id] = {
            "target_type": ar["applicability"][0] if ar["applicability"] else None,
            "run": manifest is not None, "environment": (manifest or {}).get("environment"),
            "generated_at": (manifest or {}).get("generated_at"),
            "expected": expected, "targets": targets,
            "automation": automation.get(ar_id),
        }
    return out


def load_results(root: Path, scan_dir: Path) -> tuple:
    """(AR -> latest result, meta about the newest log). AR level only."""
    best, newest = {}, None
    for path in sorted(scan_dir.glob("evaluation-log-*.yaml")):
        doc = load_yaml(path)
        for ev in doc.get("evaluations", []):
            for log in ev.get("assessment-logs", []):
                ar = (log.get("requirement") or {}).get("entry-id")
                start = log.get("start")
                if not ar or not start:
                    continue
                when = start if isinstance(start, datetime) else datetime.fromisoformat(str(start))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                if ar not in best or when > best[ar]["time"]:
                    result = str(log.get("result", "")).lower()
                    best[ar] = {"time": when, "log": path,
                                "overall": result if result in KNOWN_RESULTS else "inconclusive",
                                "message": squash(log.get("message"))[:500] or None}
                if newest is None or when > newest[0]:
                    newest = (when, path)
    results = {}
    for ar, r in best.items():
        report = r["log"].with_name(r["log"].name.replace("evaluation-log-", "report-", 1).replace(".yaml", ".md"))
        results[ar] = {
            "overall": r["overall"], "message": r["message"],
            "evaluated_at": r["time"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "log_file": rel(root, r["log"]), "report_file": rel(root, report) if report.is_file() else None,
        }
    meta = None
    if newest:
        log = newest[1]
        report = log.with_name(log.name.replace("evaluation-log-", "report-", 1).replace(".yaml", ".md"))
        meta = {"log_file": rel(root, log), "report_file": rel(root, report) if report.is_file() else None,
                "evaluated_at": newest[0].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return results, meta


# --- assembly -----------------------------------------------------------------

def build(root: Path, coverage: dict, now: datetime, environment: str,
          evidence_dir: Path = None, scan_dir: Path = None, coverage_path: Path = None) -> dict:
    """Assemble trace.json. Raises TraceError listing every unresolved link."""
    root = Path(root)
    evidence_dir = Path(evidence_dir or root / "evidence/output")
    scan_dir = Path(scan_dir or root / ".complytime/scan")
    problems = []

    controls, ars = load_catalogs(root)
    plans = load_plans(root)
    rego = load_rego(root)
    frameworks, links = load_links(root, ars, problems)
    for ar_id in plans:
        if ar_id not in ars:
            problems.append(f"policy plan {plans[ar_id]['id']} names unknown AR {ar_id}")

    impls = {ar_id: resolve_impl(root, ar, plans.get(ar_id), rego, problems) for ar_id, ar in ars.items()}
    if problems:
        raise TraceError("trace build failed; these links do not resolve:\n  - " + "\n  - ".join(problems))

    try:
        ksis = fedramp_data.load_ksis()
    except (OSError, KeyError):
        ksis = {}
    rows = {r["id"]: r for r in coverage.get("ksis", [])}
    records_dir = root / "mappings/fedramp-20x/ksi"
    records = ksi_data.load_records(ksis, records_dir) if ksis and records_dir.is_dir() else {}

    # requirements, keyed "<framework>:<id>"
    requirements, finished_links = {}, []
    for link in links:
        kind, rid = classify(link["requirement_raw"], ksis)
        key = f"{link['framework']}:{rid}"
        requirements.setdefault(key, {"framework": link["framework"], "id": rid, "display_id": link["requirement_raw"],
                                      "kind": kind, "name": None, "statement": None, "ars": []})
        if link["ar"] not in requirements[key]["ars"]:
            requirements[key]["ars"].append(link["ar"])
        finished_links.append({"ar": link["ar"], "requirement": key, "framework": link["framework"],
                               "mapping_file": link["mapping_file"], "mapping_id": link["mapping_id"],
                               "relationship": link["relationship"], "strength": link["strength"],
                               "rationale": link["rationale"]})

    # Every in-phase KSI is a requirement, mapped or not, so "no AR yet" is visible.
    for ksi_id, row in rows.items():
        key = f"{KSI_FRAMEWORK}:{ksi_id}"
        req = requirements.setdefault(key, {"framework": KSI_FRAMEWORK, "id": ksi_id, "display_id": ksi_id,
                                            "kind": "ksi", "name": None, "statement": None, "ars": []})
        if KSI_FRAMEWORK not in frameworks:
            frameworks[KSI_FRAMEWORK] = {"id": KSI_FRAMEWORK, "title": "FedRAMP Key Security Indicators",
                                         "mapping_files": []}
        req.update({"name": row["name"], "statement": row["statement"], "family": row["family"],
                    "type": row["type"], "state": row["state"],
                    "methods_required": 2, "methods_implemented": row["methods_implemented"],
                    "next": row.get("next", []), "scope_full": row["scope_full"]})
    for key, req in requirements.items():
        if req["kind"] == "ksi" and req["name"] is None and req["id"] in ksis:
            req["name"], req["statement"] = ksis[req["id"]]["name"], ksis[req["id"]]["statement"]
            req["family"] = ksis[req["id"]]["family"]

    # Control status per (KSI, control) pair: the triangle KSI -> control, AR -> KSI, AR -> control.
    control_links = [l for l in finished_links if requirements[l["requirement"]]["kind"] == "control"]
    for key, req in requirements.items():
        if req["kind"] != "ksi" or req["id"] not in rows:
            continue
        row, rec = rows[req["id"]], records.get(req["id"], {})
        serving = set(req["ars"])
        status = {}
        for label in ("addressed", "inherited", "not-applicable", "open"):
            for c in row["controls"].get(label, []):
                via = sorted({l["ar"] for l in control_links
                              if l["ar"] in serving and requirements[l["requirement"]]["id"] == c})
                if label == "addressed":
                    why = " ".join(f"{l['ar']}: {l['rationale']}" for l in control_links
                                   if l["ar"] in serving and requirements[l["requirement"]]["id"] == c and l["rationale"])
                else:
                    why = (rec.get("control-decisions", {}).get(c) or {}).get("rationale")
                status[c] = {"status": label, "via_ars": via, "rationale": why or None}
        req["related"] = list(status)
        req["control_status"] = status
        req["record"] = {k: (rec.get(k) or None) for k in ("measures", "automation-verification", "validation")}

    scope = load_scope(root, ars, evidence_dir, environment)
    results, scan_meta = load_results(root, scan_dir)

    ar_out = {}
    for ar_id, ar in sorted(ars.items()):
        plan, impl = plans.get(ar_id), impls[ar_id]
        fixtures_ok = bool(impl) and all(impl["fixtures"].values())
        implemented = bool(impl) and bool(impl["collector"] and impl["rego_file"] and impl["schema"]) and fixtures_ok
        served = sorted({l["requirement"] for l in finished_links if l["ar"] == ar_id})
        ksi_keys = [k for k in served if requirements[k]["kind"] == "ksi"]
        own_missing = []
        if impl is None:
            own_missing.append("no automated evaluation method in the policy yet")
        elif not fixtures_ok:
            gone = [n for n, ok in impl["fixtures"].items() if not ok]
            own_missing.append(f"add {' and '.join(gone)} fixture(s) under tests/fixtures/{ar_id}/")
        if not served:
            own_missing.append("not mapped to any requirement")
        sc = scope[ar_id]
        if not sc["run"]:
            own_missing.append("run the checks (make run-local): no collector manifest yet")
        else:
            bad = [t["name"] for t in sc["targets"] if t["status"] in ("error", "not reached")]
            if bad:
                own_missing.append(f"reach {len(bad)} target(s) not collected: {', '.join(bad)}")
        if ar_id not in results:
            own_missing.append("no scan result yet (make run-local)")
        ar_out[ar_id] = {
            **ar, "plan": plan, "impl": impl, "implemented": implemented,
            "implementation_state": "Implemented" if implemented else "Not implemented",
            "what_it_checks": (plan or {}).get("description") or None,
            "fails_when": None, "failure_handling": None,  # no structured home yet: shown as "not defined yet"
            "requirements": served,
            "missing": {"own": own_missing, "by_requirement": {k: requirements[k].get("next", []) for k in ksi_keys}},
        }

    inputs = [p for pat in ("gemara/*/controls.yaml", "gemara/*/policy.yaml", "mappings/*.mapping.yaml")
              for p in sorted(root.glob(pat))]
    meta_inputs = [{"file": rel(root, p), "sha256": sha256(p)} for p in inputs]
    if coverage_path and Path(coverage_path).is_file():
        meta_inputs.append({"file": "output/coverage.json", "sha256": sha256(Path(coverage_path))})
    if scan_meta:
        meta_inputs.append({"file": scan_meta["log_file"], "sha256": sha256(root / scan_meta["log_file"])})

    return {
        "meta": {"schema_version": SCHEMA_VERSION, "generated_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "environment": environment, "scan": scan_meta, "inputs": meta_inputs,
                 "evidence_dir": rel(root, evidence_dir) if evidence_dir.is_relative_to(root) else None},
        "frameworks": sorted(frameworks.values(), key=lambda f: f["id"]),
        "requirements": dict(sorted(requirements.items())),
        "controls": dict(sorted(controls.items())),
        "ars": ar_out,
        "links": sorted(finished_links, key=lambda l: (l["ar"], l["requirement"], l["mapping_id"] or "")),
        "scope": scope,
        "results": dict(sorted(results.items())),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--coverage", default=str(ROOT / "output/coverage.json"))
    ap.add_argument("--scan-dir", default=None)
    ap.add_argument("--out", default=str(ROOT / "output/trace.json"))
    args = ap.parse_args()

    cov_path = Path(args.coverage)
    if not cov_path.is_file():
        sys.exit(f"ERROR: {cov_path} not found; run `make coverage` first.")
    evidence_dir = Path(os.environ["RSC_EVIDENCE_DIR"]) if os.environ.get("RSC_EVIDENCE_DIR") else None
    try:
        trace = build(Path(args.root), json.loads(cov_path.read_text()), datetime.now(timezone.utc),
                      os.environ.get("RSC_ENV", "integration"), evidence_dir=evidence_dir,
                      scan_dir=Path(args.scan_dir) if args.scan_dir else None, coverage_path=cov_path)
    except TraceError as e:
        sys.exit(f"ERROR: {e}")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(trace, indent=2) + "\n")
    print(f"Wrote {out} ({len(trace['ars'])} ARs, {len(trace['requirements'])} requirements, {len(trace['links'])} links)")


if __name__ == "__main__":
    main()
