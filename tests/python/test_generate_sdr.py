import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import coverage  # noqa: E402
import generate_sdr  # noqa: E402
import test_coverage as tc  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
FREQS = {tc.AR1: "daily", tc.AR2: "daily"}


def make_coverage(full_scope=True, record=True):
    d = tc.base_data()
    if record:
        d["records"]["KSI-CMT-VTD"] = dict(tc.FULL_RECORD, **{"control-decisions": tc.decide_all_open(d["ksis"])})
    if full_scope:
        d["manifests"] = {tc.AR1: tc.manifest(**{"org/a": "collected", "org/b": "collected"}),
                          tc.AR2: tc.manifest(**{"org/a": "collected", "org/b": "error"})}
    roll = coverage.rollup(d, "integration")
    return d, json.loads(json.dumps(roll))


def results_from_log():
    with tempfile.TemporaryDirectory() as t:
        (Path(t) / "evaluation-log-x.yaml").write_text((DATA / "evaluation-log.yaml").read_text())
        return generate_sdr.load_results(Path(t))


class Results(unittest.TestCase):
    def test_keeps_only_result_and_time(self):
        res = results_from_log()
        self.assertEqual(res[tc.AR1]["result"], "failed")
        self.assertEqual(res[tc.AR2]["result"], "passed")
        self.assertEqual(set(res[tc.AR1]), {"result", "time"})

    def test_newest_wins(self):
        with tempfile.TemporaryDirectory() as t:
            for name, result, ts in (("a", "Failed", "2026-11-01T00:00:00Z"), ("b", "Passed", "2026-11-02T00:00:00Z")):
                (Path(t) / f"evaluation-log-{name}.yaml").write_text(yaml_log(result, ts))
            self.assertEqual(generate_sdr.load_results(Path(t))[tc.AR1]["result"], "passed")

    def test_unknown_result_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "evaluation-log-a.yaml").write_text(yaml_log("Needs Review", "2026-11-01T00:00:00Z"))
            self.assertEqual(generate_sdr.load_results(Path(t))[tc.AR1]["result"], "inconclusive")


def yaml_log(result, ts):
    return (f"evaluations:\n- assessment-logs:\n  - requirement: {{entry-id: {tc.AR1}}}\n"
            f"    result: {result}\n    start: \"{ts}\"\n")


class Sdr(unittest.TestCase):
    def build(self, **kw):
        d, roll = make_coverage(**kw)
        return generate_sdr.build_sdr(roll, d["records"], FREQS, results_from_log(), NOW)

    def entry(self, sdr, ksi):
        return next(k for k in sdr["keySecurityIndicators"] if k["ksiId"] == ksi)

    def test_validates_against_vendored_schema(self):
        generate_sdr.validate_sdr(self.build())

    def test_schema_actually_rejects_bad_sdr(self):
        import jsonschema
        bad = self.build()
        del bad["keySecurityIndicators"][0]["ksiTests"]
        with self.assertRaises(jsonschema.ValidationError):
            generate_sdr.validate_sdr(bad)
        bad = self.build()
        bad["keySecurityIndicators"][0]["ksiImplementationStatus"] = "Done"
        with self.assertRaises(jsonschema.ValidationError):
            generate_sdr.validate_sdr(bad)

    def test_top_level(self):
        sdr = self.build()
        self.assertEqual(sdr["certificationPackageOverviewUri"], generate_sdr.CPO_PLACEHOLDER)
        self.assertEqual(sdr["fedRampRequirements"], [])
        self.assertEqual(sdr["metadata"]["updateSource"], "local-run (integration)")

    def test_assessor_fields_stay_empty(self):
        for k in self.build()["keySecurityIndicators"]:
            self.assertEqual(k["ksiAssessment"], [])

    def test_failed_results_visible(self):
        e = self.entry(self.build(), "KSI-CMT-VTD")
        text = " ".join(x["evidenceText"] for x in e["ksiEvidence"])
        self.assertIn(f"{tc.AR1}: failed", text)
        self.assertIn(f"{tc.AR2}: passed", text)
        self.assertIn("Reached 1 of 2", text)  # AR02 missed org/b: scope is not hidden by a pass

    def test_ar_without_result_is_not_evaluated(self):
        d, roll = make_coverage()
        sdr = generate_sdr.build_sdr(roll, d["records"], FREQS, {}, NOW)
        text = " ".join(x["evidenceText"] for x in self.entry(sdr, "KSI-CMT-VTD")["ksiEvidence"])
        self.assertIn("not evaluated", text)
        self.assertNotIn("passed", text)
        self.assertNotIn("lastUpdated", json.dumps(self.entry(sdr, "KSI-CMT-VTD")["ksiEvidence"]))

    def test_cycle_is_truthful(self):
        impl = " ".join(self.entry(self.build(), "KSI-CMT-VTD")["ksiImplementation"])
        self.assertIn("Planned cycle: daily", impl)
        self.assertIn("manually from a developer laptop", impl)

    def test_status_mapping(self):
        sdr = self.build()
        self.assertEqual(self.entry(sdr, "KSI-CMT-RMV")["ksiImplementationStatus"], "Not Implemented")
        self.assertEqual(self.entry(sdr, "KSI-CMT-LMC")["ksiImplementationStatus"], "Partially Implemented")
        self.assertEqual(self.entry(sdr, "KSI-CMT-VTD")["ksiImplementationStatus"], "Partially Implemented")
        d = tc.base_data()
        ok = tc.manifest(**{"org/a": "collected", "org/b": "collected"})
        d["manifests"] = {tc.AR1: ok, tc.AR2: ok}
        d["records"]["KSI-CMT-VTD"] = dict(tc.FULL_RECORD, **{"control-decisions": tc.decide_all_open(d["ksis"])})
        roll = json.loads(json.dumps(coverage.rollup(d, "integration")))
        ready = generate_sdr.build_sdr(roll, d["records"], FREQS, {}, NOW)
        self.assertEqual(self.entry(ready, "KSI-CMT-VTD")["ksiImplementationStatus"], "Implemented")

    def test_unwritten_explanations_are_not_invented(self):
        d, roll = make_coverage(record=False)
        sdr = generate_sdr.build_sdr(roll, d["records"], FREQS, {}, NOW)
        e = self.entry(sdr, "KSI-CMT-VTD")
        self.assertEqual(len(e["ksiImplementation"]), 1)  # only the cycle line
        self.assertTrue(all(v.startswith("RSC.") for v in e["ksiValidation"]))  # only mapping rationales

    def test_written_explanations_are_used(self):
        e = self.entry(self.build(), "KSI-CMT-VTD")
        self.assertEqual(e["ksiImplementation"][0], "m")
        self.assertEqual(e["ksiValidation"][-2:], ["a", "v"])

    def test_no_sensitive_content(self):
        text = json.dumps(self.build())
        self.assertEqual(generate_sdr.find_leaks(text), [])
        for needle in ("someone", "alice", "/Users"):
            self.assertNotIn(needle, text)

    def test_leak_detector(self):
        for bad in ("/Users/x", "file:///tmp", "acct " + "1" * 12, "arn:aws:iam::1"):
            self.assertTrue(generate_sdr.find_leaks(bad), bad)
        self.assertEqual(generate_sdr.find_leaks("2026-11-24T09:29:26Z"), [])


if __name__ == "__main__":
    unittest.main()


class AutomationSummary(unittest.TestCase):
    """How many merges relied on the documented automation exemption is always stated."""

    def write(self, root: Path, ar: str, name: str, summary):
        d = root / ar
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(json.dumps({"summary": summary} if summary is not None else {}))

    def test_sums_over_targets_and_skips_manifest_and_files_without_a_summary(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self.write(root, tc.AR2, "a.json", {"merged": 10, "automation_exempt": 4, "exemption_approved": False})
            self.write(root, tc.AR2, "b.json", {"merged": 5, "automation_exempt": 1, "exemption_approved": False})
            self.write(root, tc.AR2, "manifest.json", {"merged": 999, "automation_exempt": 999, "exemption_approved": True})
            self.write(root, tc.AR1, "a.json", None)  # AR01 evidence has no summary
            out = generate_sdr.load_automation_summary(root)
            self.assertEqual(out, {tc.AR2: {"merged": 15, "automation_exempt": 5, "exemption_approved": False}})

    def test_approved_only_if_every_target_says_so(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self.write(root, tc.AR2, "a.json", {"merged": 1, "automation_exempt": 1, "exemption_approved": True})
            self.write(root, tc.AR2, "b.json", {"merged": 1, "automation_exempt": 0, "exemption_approved": False})
            self.assertIs(generate_sdr.load_automation_summary(root)[tc.AR2]["exemption_approved"], False)

    def test_sentence_says_pending_until_approved(self):
        pending = generate_sdr.automation_sentence({"merged": 20, "automation_exempt": 7, "exemption_approved": False})
        self.assertIn("7 of 20", pending)
        self.assertIn("approval pending", pending)
        done = generate_sdr.automation_sentence({"merged": 20, "automation_exempt": 7, "exemption_approved": True})
        self.assertIn("(approved)", done)
        self.assertEqual(generate_sdr.automation_sentence(None), "")
        self.assertEqual(generate_sdr.automation_sentence({"merged": 0, "automation_exempt": 0, "exemption_approved": False}), "")

    def test_sdr_evidence_text_carries_the_count(self):
        d, roll = make_coverage()
        automation = {tc.AR2: {"merged": 30, "automation_exempt": 9, "exemption_approved": False}}
        sdr = generate_sdr.build_sdr(roll, d["records"], FREQS, results_from_log(), NOW, automation)
        text = " ".join(x["evidenceText"] for x in next(k for k in sdr["keySecurityIndicators"] if k["ksiId"] == "KSI-CMT-VTD")["ksiEvidence"])
        self.assertIn("9 of 30 merged PRs counted as approved by automation", text)
        generate_sdr.validate_sdr(sdr)
        self.assertEqual(generate_sdr.find_leaks(json.dumps(sdr)), [])
