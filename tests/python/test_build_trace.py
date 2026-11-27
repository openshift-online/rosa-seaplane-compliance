import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_trace  # noqa: E402
import trace_fakes as fk  # noqa: E402

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
KSI = "fedramp-ksi-controls:KSI-CMT-VTD"
NIST = "fedramp-sp800-53-guidance"


class Fake(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = fk.make_repo(Path(self.tmp.name))

    def build(self, coverage=None):
        return build_trace.build(self.root, coverage if coverage is not None else fk.coverage_for(), NOW, "integration")

    def problems(self):
        with self.assertRaises(build_trace.TraceError) as cm:
            self.build()
        return str(cm.exception)


class Join(Fake):
    def test_generic_domains_and_ars(self):
        t = self.build()
        self.assertEqual(sorted(t["ars"]), [fk.AR_A1, fk.AR_A2, fk.AR_B1])
        self.assertEqual({a["domain"] for a in t["ars"].values()}, {"dom-a", "dom-b"})
        self.assertEqual(sorted(t["controls"]), ["FAKE.A.CTRL01", "FAKE.B.CTRL07"])
        self.assertEqual(t["controls"]["FAKE.A.CTRL01"]["ars"], [fk.AR_A1, fk.AR_A2])

    def test_text_whitespace_is_squashed(self):
        self.assertEqual(self.build()["ars"][fk.AR_A1]["text"], "Accounts must be locked down.")

    def test_frameworks_are_keyed_by_reference_and_non_ar_mappings_ignored(self):
        t = self.build()
        self.assertEqual([f["id"] for f in t["frameworks"]], ["fedramp-ksi-controls", NIST, "other-cert"])
        self.assertEqual({f["id"]: f["title"] for f in t["frameworks"]}["other-cert"], "Some Other Cert")
        self.assertEqual(t["frameworks"][0]["mapping_files"], ["mappings/a-to-ksi.mapping.yaml"])

    def test_a_second_certification_is_just_another_mapping_file(self):
        t = self.build()
        self.assertIn("other-cert:OC-REQ-9", t["requirements"])
        self.assertEqual(t["requirements"]["other-cert:OC-REQ-9"]["kind"], "requirement")
        link = next(l for l in t["links"] if l["framework"] == "other-cert")
        self.assertEqual((link["ar"], link["strength"], link["mapping_id"]), (fk.AR_A1, 2, "O1"))
        self.assertIn("another certification", link["rationale"].lower())

    def test_nist_ids_are_normalized_and_keep_their_display_form(self):
        t = self.build()
        req = t["requirements"][f"{NIST}:cm-3.2"]
        self.assertEqual((req["kind"], req["id"], req["display_id"]), ("control", "cm-3.2", "CM-03 (02)"))
        self.assertIn(f"{NIST}:sc-7", t["requirements"])

    def test_ksi_requirement_is_enriched_and_serves_both_ars(self):
        req = self.build()["requirements"][KSI]
        self.assertEqual((req["kind"], req["state"], req["name"]), ("ksi", "In progress", "Validating Throughout Deployment"))
        self.assertEqual(req["ars"], [fk.AR_A1, fk.AR_B1])

    def test_links_carry_rationale_strength_and_mapping_file(self):
        link = next(l for l in self.build()["links"] if l["ar"] == fk.AR_B1 and l["requirement"] == KSI)
        self.assertEqual((link["strength"], link["mapping_file"], link["mapping_id"]),
                         (3, "mappings/a-to-ksi.mapping.yaml", "M2"))
        self.assertEqual(link["rationale"], "Closed networks limit blast radius.")

    def test_via_ars_closes_the_ksi_ar_control_triangle(self):
        cs = self.build()["requirements"][KSI]["control_status"]
        self.assertEqual(cs["cm-3"]["status"], "addressed")
        self.assertEqual(cs["cm-3"]["via_ars"], [fk.AR_A1])
        self.assertIn("Change control.", cs["cm-3"]["rationale"])
        self.assertEqual(cs["cm-3.2"]["via_ars"], [fk.AR_A1])
        self.assertEqual((cs["si-2"]["status"], cs["si-2"]["via_ars"]), ("open", []))

    def test_control_status_is_per_ksi_pair_not_per_control(self):
        # sc-7 is mapped from AR_B1, which serves VTD, but VTD does not list it as related: not in its status.
        self.assertNotIn("sc-7", self.build()["requirements"][KSI]["control_status"])

    def test_every_dataset_ksi_in_coverage_is_a_requirement_even_if_unmapped(self):
        cov = fk.coverage_for()
        cov["ksis"].append(dict(fk.coverage_for("KSI-CMT-RMV")["ksis"][0], id="KSI-CMT-RMV", name="Redeploying"))
        req = self.build(cov)["requirements"]["fedramp-ksi-controls:KSI-CMT-RMV"]
        self.assertEqual(req["ars"], [])

    def test_ars_know_which_requirements_they_serve(self):
        ar = self.build()["ars"][fk.AR_A1]
        self.assertEqual(ar["requirements"], [KSI, f"{NIST}:cm-3", f"{NIST}:cm-3.2", "other-cert:OC-REQ-9"])
        self.assertEqual(self.build()["ars"][fk.AR_A2]["requirements"], [])


class Implementation(Fake):
    def test_links_resolve_by_convention_and_pointer(self):
        impl = self.build()["ars"][fk.AR_A1]["impl"]
        self.assertEqual(impl["collector"], f"evidence/{fk.AR_A1}.sh")
        self.assertEqual(impl["rego_file"], "opa/dom-a/policy/locked.rego")
        self.assertEqual(impl["rego_package"], "fake.dom_a.locked")
        self.assertEqual(impl["rego_test_file"], "opa/dom-a/policy/locked_test.rego")
        self.assertEqual((impl["schema"], impl["platform"]), ("schemas/fake.cue", "fake-platform"))
        self.assertEqual(impl["fixtures"], {"pass": True, "fail": True})

    def test_ar_without_an_automated_plan_has_no_impl_and_says_so(self):
        ar = self.build()["ars"][fk.AR_A2]
        self.assertIsNone(ar["impl"])
        self.assertFalse(ar["implemented"])
        self.assertIn("no automated evaluation method in the policy yet", ar["missing"]["own"])
        self.assertIn("not mapped to any requirement", ar["missing"]["own"])

    def test_undefined_fields_are_explicit_nulls(self):
        ar = self.build()["ars"][fk.AR_A1]
        self.assertIsNone(ar["fails_when"])
        self.assertIsNone(ar["failure_handling"])
        self.assertEqual(ar["what_it_checks"], f"Evaluates {fk.AR_A1}.")

    def test_plan_is_flattened(self):
        plan = self.build()["ars"][fk.AR_A1]["plan"]
        self.assertEqual((plan["frequency"], plan["executor"], plan["mode"]), ("weekly", "opa", "Automated"))

    def test_missing_fixtures_are_reported_not_fatal(self):
        (self.root / "tests/fixtures" / fk.AR_A1 / "fail.json").unlink()
        ar = self.build()["ars"][fk.AR_A1]
        self.assertFalse(ar["implemented"])
        self.assertEqual(ar["impl"]["fixtures"], {"pass": True, "fail": False})
        self.assertTrue(any("fail fixture" in m for m in ar["missing"]["own"]))


class FailsLoudly(Fake):
    def test_missing_collector(self):
        (self.root / "evidence" / f"{fk.AR_A1}.sh").unlink()
        self.assertIn(f"{fk.AR_A1}: no collector at evidence/{fk.AR_A1}.sh", self.problems())

    def test_ar_missing_from_complytime_mapping(self):
        fk.write(self.root, "opa/dom-a/policy/complytime-mapping.json", json.dumps({"mappings": []}))
        self.assertIn("not in opa/dom-a/policy/complytime-mapping.json", self.problems())

    def test_mapping_names_a_package_no_rego_declares(self):
        fk.write(self.root, "opa/dom-a/policy/locked.rego", fk.rego("fake.dom_a.renamed"))
        self.assertIn("no .rego under opa/dom-a/policy declares package fake.dom_a.locked", self.problems())

    def test_missing_schema_header(self):
        fk.write(self.root, "opa/dom-a/policy/locked.rego", fk.rego("fake.dom_a.locked", schema=None))
        self.assertIn("missing a '# schema: schemas/<name>.cue' header", self.problems())

    def test_schema_pointer_to_nowhere(self):
        fk.write(self.root, "opa/dom-a/policy/locked.rego", fk.rego("fake.dom_a.locked", schema="schemas/nope.cue"))
        self.assertIn("does not point at an existing file under schemas/", self.problems())

    def test_schema_pointer_outside_schemas_dir(self):
        fk.write(self.root, "opa/dom-a/policy/locked.rego", fk.rego("fake.dom_a.locked", schema="evidence/x.sh"))
        self.assertIn("does not point at an existing file under schemas/", self.problems())

    def test_mapping_to_an_unknown_ar(self):
        fk.write(self.root, "mappings/bad.mapping.yaml", fk.mapping("other-cert", "x", [("B1", "FAKE.NOPE.AR9", [("X", 1, "y")])]))
        self.assertIn("names unknown AR FAKE.NOPE.AR9", self.problems())

    def test_plan_for_an_unknown_ar(self):
        fk.write(self.root, "gemara/dom-b/policy.yaml", fk.policy([(fk.AR_B1, "daily", "Automated"), ("FAKE.GHOST.AR1", "daily", "Automated")]))
        self.assertIn("names unknown AR FAKE.GHOST.AR1", self.problems())

    def test_all_problems_are_listed_together(self):
        (self.root / "evidence" / f"{fk.AR_A1}.sh").unlink()
        (self.root / "evidence" / f"{fk.AR_B1}.sh").unlink()
        msg = self.problems()
        self.assertIn(fk.AR_A1, msg)
        self.assertIn(fk.AR_B1, msg)
        self.assertTrue(msg.startswith("trace build failed"))


class ScopeAndResults(Fake):
    def test_scope_uses_applicability_to_find_expected_targets(self):
        sc = self.build()["scope"][fk.AR_A1]
        self.assertEqual(sc["target_type"], "aws_accounts")
        self.assertEqual(sc["expected"], ["acct-one", "acct-two", "acct-three"])
        self.assertEqual([(t["name"], t["status"]) for t in sc["targets"]],
                         [("acct-one", "reached"), ("acct-two", "error"), ("acct-three", "not reached")])
        self.assertEqual(sc["targets"][1]["error"], "gh: denied")

    def test_deployment_pipelines_are_expected_from_the_environment_config(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            root, ev = Path(t), Path(t) / "ev"
            (ev / "X.AR1").mkdir(parents=True)
            (ev / "X.AR1" / "manifest.json").write_text(json.dumps({"targets": [
                {"name": "regional-pipeline", "status": "collected"}]}))
            sc = build_trace.load_scope(root, {"X.AR1": {"applicability": ["deployment_pipelines"]}}, ev, "integration")["X.AR1"]
        self.assertEqual(sc["expected"], ["regional-pipeline", "mc01-pipeline"])
        self.assertEqual([(x["name"], x["status"]) for x in sc["targets"]],
                         [("regional-pipeline", "reached"), ("mc01-pipeline", "not reached")])

    def test_ar_with_no_manifest_is_not_run(self):
        sc = self.build()["scope"][fk.AR_B1]
        self.assertFalse(sc["run"])
        self.assertEqual([t["status"] for t in sc["targets"]], ["not run"])

    def test_missing_line_names_unreached_targets(self):
        own = self.build()["ars"][fk.AR_A1]["missing"]["own"]
        self.assertIn("reach 2 target(s) not collected: acct-two, acct-three", own)

    def test_results_are_ar_level_only(self):
        t = self.build()
        self.assertEqual(t["results"][fk.AR_A1]["overall"], "failed")
        self.assertEqual(t["results"][fk.AR_A1]["message"], "acct-one: PR #1 (mallory) bad <b>x</b>")
        self.assertEqual(t["results"][fk.AR_A1]["report_file"], ".complytime/scan/report-fake-20260101-000000.md")
        self.assertEqual(set(t["results"][fk.AR_A1]), {"overall", "message", "evaluated_at", "log_file", "report_file"})
        self.assertNotIn(fk.AR_A2, t["results"])  # never evaluated, so no entry: the viewer says "not evaluated"

    def test_no_per_target_results_anywhere(self):
        text = json.dumps(self.build())
        for key in ("per_target", "per-target"):
            self.assertNotIn(key, text)

    def test_unknown_result_word_is_inconclusive(self):
        log = self.root / ".complytime/scan/evaluation-log-fake-20260101-000000.yaml"
        log.write_text(log.read_text().replace("Failed", "Needs Review"))
        self.assertEqual(self.build()["results"][fk.AR_A1]["overall"], "inconclusive")

    def test_meta(self):
        meta = self.build()["meta"]
        self.assertEqual((meta["schema_version"], meta["environment"], meta["generated_at"]), (1, "integration", "2026-01-02T00:00:00Z"))
        self.assertEqual(meta["scan"]["log_file"], ".complytime/scan/evaluation-log-fake-20260101-000000.yaml")
        self.assertTrue(all(len(i["sha256"]) == 64 for i in meta["inputs"]))


class RealRepo(unittest.TestCase):
    def test_the_real_repo_resolves_every_link(self):
        t = build_trace.build(ROOT, {"ksis": []}, NOW, "integration",
                              evidence_dir=Path(tempfile.gettempdir()) / "no-such-evidence", scan_dir=Path(tempfile.gettempdir()) / "no-such-scan")
        self.assertTrue(t["ars"])
        for ar in t["ars"].values():
            self.assertTrue(ar["implemented"], ar["id"])
            self.assertTrue((ROOT / ar["impl"]["schema"]).is_file())
        self.assertTrue(all(r["overall"] for r in t["results"].values()))


if __name__ == "__main__":
    unittest.main()
