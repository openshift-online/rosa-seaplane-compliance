"""A synthetic repository for build_trace tests: two control domains, two
frameworks (a KSI one and a generic one), fake repos and fake users. Public-repo
safe: nothing here is real."""
import json
from pathlib import Path

import yaml

AR_A1, AR_A2, AR_B1 = "FAKE.A.CTRL01.AR01", "FAKE.A.CTRL01.AR02", "FAKE.B.CTRL07.AR01"


def write(root: Path, rel: str, text: str):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def catalog(domain, control, ars):
    return yaml.safe_dump({"controls": [{
        "id": control, "title": f"Control {control}", "group": domain, "objective": "Keep things true.",
        "assessment-requirements": [{"id": a, "text": t, "applicability": app, "state": "Active"} for a, t, app in ars]}]})


def policy(plans):
    return yaml.safe_dump({"adherence": {"assessment-plans": [
        {"id": f"PLAN.{ar}", "requirement-id": ar, "frequency": freq, "evaluation-methods": [{
            "id": f"PLAN.{ar}.EM01", "type": "Behavioral", "mode": mode, "required": True,
            "description": f"Evaluates {ar}.", "executor": {"id": "opa", "name": "opa-provider"}}]}
        for ar, freq, mode in plans]}})


def rego(package, platform="fake-platform", schema="schemas/fake.cue"):
    head = f"# platform: {platform}\n" + (f"# schema: {schema}\n" if schema else "")
    return head + f"package {package}\n\nimport rego.v1\n"


def mapping(fw, title, entries, source_type="AssessmentRequirement"):
    """entries: [(mapping_id, AR, [(target, strength, rationale)])]"""
    return yaml.safe_dump({
        "title": title,
        "metadata": {"id": f"MAP.{fw}", "mapping-references": [{"id": fw, "title": title}]},
        "source-reference": {"reference-id": "FAKE", "entry-type": source_type},
        "target-reference": {"reference-id": fw, "entry-type": "Control"},
        "mappings": [{"id": mid, "source": ar, "relationship": "supports",
                      "targets": [{"entry-id": t, "strength": st, "rationale": why} for t, st, why in tgts]}
                     for mid, ar, tgts in entries]})


def make_repo(root: Path) -> Path:
    root = Path(root)
    write(root, "gemara/dom-a/controls.yaml", catalog("dom-a", "FAKE.A.CTRL01", [
        (AR_A1, "Accounts   must be\n locked down.", ["aws_accounts"]),
        (AR_A2, "A second requirement with no plan yet.", ["aws_accounts"])]))
    write(root, "gemara/dom-a/policy.yaml", policy([(AR_A1, "weekly", "Automated")]))
    write(root, "gemara/dom-b/controls.yaml", catalog("dom-b", "FAKE.B.CTRL07", [(AR_B1, "Networks must be closed.", ["vpcs"])]))
    write(root, "gemara/dom-b/policy.yaml", policy([(AR_B1, "daily", "Automated")]))
    for dom, ar, pkg in (("dom-a", AR_A1, "fake.dom_a.locked"), ("dom-b", AR_B1, "fake.dom_b.closed")):
        write(root, f"opa/{dom}/policy/{pkg.split('.')[-1]}.rego", rego(pkg))
        write(root, f"opa/{dom}/policy/{pkg.split('.')[-1]}_test.rego", rego(pkg, schema=None))
        write(root, f"opa/{dom}/policy/complytime-mapping.json", json.dumps({"version": "1", "mappings": [{"id": pkg, "requirement_id": ar}]}))
        write(root, f"evidence/{ar}.sh", "#!/usr/bin/env bash\n")
        for n in ("pass", "fail"):
            write(root, f"tests/fixtures/{ar}/{n}.json", "{}")
    write(root, "schemas/fake.cue", "x: string\n")
    write(root, "config/scope.yaml", yaml.safe_dump({"aws-accounts": ["acct-one", "acct-two", "acct-three"], "vpcs": ["vpc-1"]}))
    # Framework one: the real KSI dataset's IDs (so KSI logic is exercised). Framework two: NIST-style controls.
    # Framework three: some other certification with its own ID scheme.
    write(root, "mappings/a-to-ksi.mapping.yaml", mapping("fedramp-ksi-controls", "KSIs", [
        ("M1", AR_A1, [("KSI-CMT-VTD", 6, "Locks accounts so changes are validated.")]),
        ("M2", AR_B1, [("KSI-CMT-VTD", 3, "Closed networks limit blast radius.")])]))
    write(root, "mappings/a-to-800-53.mapping.yaml", mapping("fedramp-sp800-53-guidance", "NIST 800-53", [
        ("N1", AR_A1, [("CM-03", 5, "Change control."), ("CM-03 (02)", 7, "Testing of changes.")]),
        ("N2", AR_B1, [("SC-07", 4, "Boundary protection.")])]))
    write(root, "mappings/a-to-other.mapping.yaml", mapping("other-cert", "Some Other Cert", [
        ("O1", AR_A1, [("OC-REQ-9", 2, "Another certification's requirement.")])]))
    # Not a mapping of ARs: must be ignored.
    write(root, "mappings/vendor-like.mapping.yaml", mapping("ignored", "Ignored", [], source_type="Control"))
    # Collector manifests: acct-two errored, acct-three never reached.
    write(root, f"evidence/output/{AR_A1}/manifest.json", json.dumps({"ar": AR_A1, "environment": "integration",
          "generated_at": "2026-01-01T00:00:00Z", "targets": [
              {"name": "acct-one", "status": "collected"}, {"name": "acct-two", "status": "error", "error": "gh: denied"}]}))
    # One L5 log with a fake user and local paths in the message (the viewer may show it; tests check escaping).
    write(root, ".complytime/scan/evaluation-log-fake-20260101-000000.yaml", yaml.safe_dump({"evaluations": [{"assessment-logs": [
        {"requirement": {"entry-id": AR_A1}, "result": "Failed", "message": "acct-one: PR #1 (mallory) bad <b>x</b>",
         "start": "2026-01-01T00:00:00Z"}]}]}))
    write(root, ".complytime/scan/report-fake-20260101-000000.md", "report\n")
    return root


def coverage_for(ksi="KSI-CMT-VTD"):
    return {"ksis": [{
        "id": ksi, "name": "Validating Throughout Deployment", "statement": "Validate.", "family": "CMT", "type": "auto",
        "state": "In progress", "methods_implemented": 1, "scope_full": False, "next": ["reach all targets"],
        "controls": {"addressed": ["cm-3", "cm-3.2"], "inherited": [], "not-applicable": [], "open": ["si-2", "cm-4.2"]},
    }]}
