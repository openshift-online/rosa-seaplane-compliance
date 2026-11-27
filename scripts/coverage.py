#!/usr/bin/env python3
"""KSI coverage rollup: how far is each KSI, and what is the next thing to do?

A thin layer over `complypack coverage` and `complypack triage` (run per control
domain), adding only the KSI view. Coverage means the checks are implemented;
it never reads pass/fail results (no --run-tests, no EvaluationLogs). Collector
manifests only say which targets the checks reached.

    scripts/coverage.py                  summary of every in-phase KSI
    scripts/coverage.py --ksi KSI-X-Y    drill-down for one KSI

Always writes output/coverage.json for the HTML viewer.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import environment  # noqa: E402
import fedramp_data  # noqa: E402
import ksi_data  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_METHODS = 2
KSI_MAPPING_REF = "fedramp-ksi-controls"
CONTROL_MAPPING_REF = "fedramp-sp800-53-guidance"
KIND_ABBREV = {"intent": "int", "behavioral": "beh"}

NOT_STARTED, IN_PROGRESS, COVERED, SDR_READY = "Not started", "In progress", "Covered", "SDR-ready"


# --- gathering (the only part that touches files or runs tools) ---------------

def run_complypack(subcommand: str, policy_id: str, extra: list) -> dict:
    cmd = ["complypack", subcommand, "--policy", policy_id, "--config", "complypack.yaml",
           "--format", "json", *extra]
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"ERROR: {' '.join(cmd)} failed:\n{res.stderr or res.stdout}")
    return json.loads(res.stdout)


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


APPLICABILITY_TARGET = {"github_repositories": "github-repository", "aws_accounts": "aws-account",
                        "deployment_pipelines": "deployment-pipeline", "deployment_clusters": "deployment-cluster"}


def ar_target_types() -> dict:
    """AR id -> target types, from each AR's applicability in the control catalogs.

    A KSI can mix methods over different targets (GitHub repositories for one,
    AWS accounts for another), so what each method must reach comes from the AR, not
    from the KSI record.
    """
    out = {}
    for catalog in sorted((ROOT / "gemara").glob("*/controls.yaml")):
        for control in load_yaml(catalog).get("controls", []):
            for ar in control.get("assessment-requirements", []):
                out[ar["id"]] = [APPLICABILITY_TARGET[a] for a in ar.get("applicability", [])
                                 if a in APPLICABILITY_TARGET]
    return out


def domains() -> list:
    """(policy id, policy doc, opa policy dir) for every gemara/<domain>/policy.yaml."""
    out = []
    for p in sorted((ROOT / "gemara").glob("*/policy.yaml")):
        doc = load_yaml(p)
        out.append((doc["metadata"]["id"], doc, ROOT / "opa" / p.parent.name / "policy"))
    return out


def gather() -> dict:
    """Everything the rollup needs, as plain data."""
    coverage, triage, kinds = {}, {}, {}
    for policy_id, doc, opa_dir in domains():
        for r in run_complypack("coverage", policy_id, ["--policy-dir", str(opa_dir)])["requirements"]:
            coverage[r["requirement_id"]] = r
        for r in run_complypack("triage", policy_id, [])["automated"]:
            triage[r["requirement_id"]] = r
        for plan in doc.get("adherence", {}).get("assessment-plans", []):
            methods = plan.get("evaluation-methods") or []
            kinds[plan["requirement-id"]] = (methods[0].get("type") if methods else "") or ""

    ksi_maps, control_maps = {}, {}
    for p in sorted((ROOT / "mappings").glob("*.mapping.yaml")):
        doc = load_yaml(p)
        ref = (doc.get("target-reference") or {}).get("reference-id")
        for m in doc.get("mappings", []):
            for t in m.get("targets", []):
                if ref == KSI_MAPPING_REF:
                    ksi_maps.setdefault(t["entry-id"], {})[m["source"]] = t.get("rationale", "")
                elif ref == CONTROL_MAPPING_REF:
                    control_maps.setdefault(m["source"], set()).add(
                        fedramp_data.normalize_control_id(t["entry-id"]))

    evidence_dir = Path(os.environ.get("RSC_EVIDENCE_DIR", ROOT / "evidence/output"))
    manifests = {}
    for ar in coverage:
        mf = evidence_dir / ar / "manifest.json"
        if mf.is_file():
            manifests[ar] = json.loads(mf.read_text())

    fixtures = {ar for ar in coverage
                if all((ROOT / "tests/fixtures" / ar / f"{n}.json").is_file() for n in ("pass", "fail"))}

    ksis = fedramp_data.load_ksis()
    return {
        "ksis": ksis,
        "scope": ksi_data.load_scope(),
        "records": ksi_data.load_records(ksis),
        "repos": ksi_data.load_repo_scope(),
        "accounts": environment.account_names(),
        "pipelines": environment.pipeline_names(),
        "clusters": environment.cluster_names(),
        "ar_target_types": ar_target_types(),
        "coverage": coverage, "triage": triage, "kinds": kinds,
        "ksi_maps": ksi_maps, "control_maps": control_maps,
        "manifests": manifests, "fixtures": fixtures,
    }


# --- rollup (pure) -----------------------------------------------------------

def expected_targets(target_types: list, manifest: dict, repos: list, accounts: list = None,
                     pipelines: list = None, clusters: list = None) -> list:
    """Targets a method should have reached. GitHub repos come from the scope file,
    AWS accounts, deployment pipelines and health-checked clusters (logical names, never
    IDs) from the environment config, so a target a collector never listed still shows
    up as missing."""
    if "github-repository" in (target_types or []):
        return list(repos)
    if "aws-account" in (target_types or []) and accounts:
        return list(accounts)
    if "deployment-pipeline" in (target_types or []) and pipelines:
        return list(pipelines)
    if "deployment-cluster" in (target_types or []) and clusters:
        return list(clusters)
    return [t["name"] for t in (manifest or {}).get("targets", [])]


def method_scope(ar: str, target_types: list, data: dict) -> dict:
    manifest = data["manifests"].get(ar)
    if manifest is None:
        return {"run": False, "reached": 0, "total": None, "missing": []}
    expected = expected_targets(target_types, manifest, data["repos"], data.get("accounts"), data.get("pipelines"), data.get("clusters"))
    collected = {t["name"] for t in manifest.get("targets", []) if t.get("status") == "collected"}
    missing = [t for t in expected if t not in collected]
    return {"run": True, "reached": len(expected) - len(missing), "total": len(expected), "missing": missing}


def rollup_ksi(ksi_id: str, bucket: str, data: dict) -> dict:
    info = data["ksis"][ksi_id]
    record = data["records"].get(ksi_id)
    target_types = (record or {}).get("target-types") or []

    methods = []
    for ar in sorted(data["ksi_maps"].get(ksi_id, {})):
        cov, tri = data["coverage"].get(ar), data["triage"].get(ar)
        has_fixtures = ar in data["fixtures"]
        implemented = bool(tri and cov and cov.get("status") == "implemented" and has_fixtures)
        methods.append({
            "ar": ar,
            "kind": (data["kinds"].get(ar) or "").lower(),
            "executor": tri["executor"] if tri else None,
            "automated": tri is not None,
            "policy": bool(cov and cov.get("status") == "implemented"),
            "fixtures": has_fixtures,
            "implemented": implemented,
            "rationale": data["ksi_maps"][ksi_id][ar],
            # Per AR when the catalogs say (a KSI can mix target types), else the KSI record's.
            "scope": method_scope(ar, data.get("ar_target_types", {}).get(ar) or target_types, data),
        })
    implemented = [m for m in methods if m["implemented"]]

    addressed = sorted({c for m in methods for c in data["control_maps"].get(m["ar"], set())}
                       & set(info["controls"]))
    decisions = (record or {}).get("control-decisions", {})
    controls = {"addressed": addressed, "inherited": [], "not-applicable": [], "open": []}
    for c in info["controls"]:
        if c in addressed:
            continue
        d = decisions.get(c)
        controls[d["decision"] if d else "open"].append(c)
    decided = len(info["controls"]) - len(controls["open"])

    # Scope: the implemented methods must all have run and reached every target.
    scopes = [m["scope"] for m in implemented]
    scope_run = bool(scopes) and all(s["run"] for s in scopes)
    scope_full = scope_run and all(s["reached"] == s["total"] and s["total"] > 0 for s in scopes)
    narrative = bool(record) and ksi_data.narrative_written(record)

    if not methods:
        state = NOT_STARTED
    # Without a record there are no declared target types, so full scope can't be judged.
    elif len(implemented) >= REQUIRED_METHODS and scope_full and record is not None:
        state = SDR_READY if not controls["open"] and narrative else COVERED
    else:
        state = IN_PROGRESS

    row = {
        "id": ksi_id, "name": info["name"], "statement": info["statement"],
        "family": info["family"], "type": "auto" if bucket == "automatable" else "hybrid",
        "methods": methods, "methods_implemented": len(implemented),
        "controls": controls, "controls_total": len(info["controls"]), "controls_decided": decided,
        "scope_run": scope_run, "scope_full": scope_full,
        "has_record": record is not None, "narrative": narrative, "state": state,
    }
    row["next"] = next_steps(row)
    return row


def rollup(data: dict, environment: str) -> dict:
    scope = data["scope"]
    ksi_data.check_scope(scope, data["ksis"])
    in_phase = [(k, b) for b in ("automatable", "hybrid") for k in scope[b]]
    rows = sorted((rollup_ksi(k, b, data) for k, b in in_phase), key=lambda r: r["id"])
    return {
        "environment": environment,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "ksis": len(rows),
            "automatable": len(scope["automatable"]), "hybrid": len(scope["hybrid"]),
            "deferred_process": len(scope["process"]),
            "covered": sum(r["state"] in (COVERED, SDR_READY) for r in rows),
            "sdr_ready": sum(r["state"] == SDR_READY for r in rows),
            "methods_implemented": sum(min(r["methods_implemented"], REQUIRED_METHODS) for r in rows),
            "methods_required": len(rows) * REQUIRED_METHODS,
        },
        "ksis": rows,
    }


# --- rendering ---------------------------------------------------------------

def methods_cell(r: dict) -> str:
    kinds = "+".join(KIND_ABBREV.get(m["kind"], m["kind"][:3]) for m in r["methods"] if m["implemented"])
    return f"{min(r['methods_implemented'], REQUIRED_METHODS)}/{REQUIRED_METHODS}" + (f" {kinds}" if kinds else "")


def scope_cell(r: dict) -> str:
    impl = [m["scope"] for m in r["methods"] if m["implemented"]]
    if not impl:
        return "-"
    if not all(s["run"] for s in impl):
        return "not run"
    # Methods can reach different kinds of targets (repos, accounts), so add up what
    # was reached and what was expected across all of them.
    return f"{sum(s['reached'] for s in impl)}/{sum(s['total'] for s in impl)}"


def controls_cell(r: dict) -> str:
    n = len(r["controls"]["open"])
    return f"{r['controls_decided']}/{r['controls_total']}" + (f", {n} open" if n else "")


def render_summary(roll: dict) -> str:
    s = roll["summary"]
    out = [
        f"FedRAMP 20x Class C coverage (environment: {roll['environment']})",
        f"Phase scope: {s['ksis']} KSIs ({s['automatable']} automatable, {s['hybrid']} hybrid). "
        f"{s['deferred_process']} process KSIs deferred.",
        f"Covered {s['covered']}/{s['ksis']} | SDR-ready {s['sdr_ready']}/{s['ksis']} | "
        f"Methods {s['methods_implemented']}/{s['methods_required']}",
        "",
    ]
    header = ("KSI", "Type", "Methods", "Scope", "Controls", "Narrative", "State")
    rows = [header] + [(r["id"], r["type"], methods_cell(r), scope_cell(r), controls_cell(r),
                        "yes" if r["narrative"] else "no", r["state"]) for r in roll["ksis"]]
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    out += ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows]
    return "\n".join(out)


def next_steps(r: dict) -> list:
    """What to do next for a KSI, as short imperative phrases."""
    c = r["controls"]
    nxt = []
    short = REQUIRED_METHODS - min(r["methods_implemented"], REQUIRED_METHODS)
    if short:
        nxt.append(f"implement {short} more automated method{'s' if short > 1 else ''}")
    if r["methods_implemented"] and not r["scope_full"]:
        nxt.append("run the checks and reach all targets" if not r["scope_run"] else "reach all targets")
    if c["open"]:
        nxt.append(f"decide {len(c['open'])} open control{'s' if len(c['open']) > 1 else ''}")
    if not r["narrative"]:
        nxt.append("write the SDR explanations" if r["has_record"] else "add the KSI record")
    return nxt


def render_detail(r: dict) -> str:
    out = [f"{r['id']}  {r['name']}", r["statement"] or "", ""]
    out.append(f"Methods ({min(r['methods_implemented'], REQUIRED_METHODS)}/{REQUIRED_METHODS})")
    for m in r["methods"]:
        sc = m["scope"]
        targets = "not run" if not sc["run"] else f"{sc['reached']}/{sc['total']}"
        out.append(f"  {m['ar']}  {m['kind'] or '?':<11}  {m['executor'] or 'none':<5}  "
                   f"policy {'yes' if m['policy'] else 'no':<3}  fixtures {'yes' if m['fixtures'] else 'no':<3}  "
                   f"targets {targets}")
        if sc["missing"]:
            out.append(f"    missing: {', '.join(sc['missing'])}")
    if not r["methods"]:
        out.append("  (no mapped AR)")
    c = r["controls"]
    out += ["", f"Controls ({r['controls_decided']}/{r['controls_total']} decided)"]
    for label in ("addressed", "inherited", "not-applicable", "open"):
        if c[label]:
            out.append(f"  {label:<15} {', '.join(c[label])}")

    nxt = next_steps(r)
    out += ["", f"State: {r['state']}", "Next: " + ("; ".join(nxt) if nxt else "nothing; keep the checks running") + "."]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ksi", help="Drill down into one KSI, e.g. KSI-CMT-VTD.")
    ap.add_argument("--out", default=str(ROOT / "output/coverage.json"))
    args = ap.parse_args()

    data = gather()
    roll = rollup(data, os.environ.get("RSC_ENV", "integration"))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(roll, indent=2) + "\n")

    if args.ksi:
        match = [r for r in roll["ksis"] if r["id"] == args.ksi]
        if not match:
            sys.exit(f"ERROR: {args.ksi} is not an in-phase KSI (unknown, or a deferred process KSI).")
        print(render_detail(match[0]))
    else:
        print(render_summary(roll))


if __name__ == "__main__":
    main()
