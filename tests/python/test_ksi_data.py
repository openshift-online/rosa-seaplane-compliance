import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import fedramp_data  # noqa: E402
import ksi_data  # noqa: E402


class Scope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ksis = fedramp_data.load_ksis()
        cls.scope = ksi_data.load_scope()

    def test_bucket_sizes(self):
        self.assertEqual([len(self.scope[b]) for b in ksi_data.BUCKETS], [26, 9, 11])

    def test_every_ksi_exactly_once(self):
        ksi_data.check_scope(self.scope, self.ksis)
        all_ids = [k for ids in self.scope.values() for k in ids]
        self.assertEqual(len(all_ids), 46)
        self.assertEqual(set(all_ids), set(self.ksis))

    def test_duplicate_rejected(self):
        bad = copy.deepcopy(self.scope)
        bad["process"].append("KSI-CMT-VTD")
        with self.assertRaises(ksi_data.RecordError):
            ksi_data.check_scope(bad, self.ksis)

    def test_missing_rejected(self):
        bad = copy.deepcopy(self.scope)
        bad["hybrid"].remove("KSI-SVC-PRR")
        with self.assertRaises(ksi_data.RecordError):
            ksi_data.check_scope(bad, self.ksis)

    def test_unknown_rejected(self):
        bad = copy.deepcopy(self.scope)
        bad["hybrid"].append("KSI-XXX-YYY")
        with self.assertRaises(ksi_data.RecordError):
            ksi_data.check_scope(bad, self.ksis)

    def test_seven_repos_without_cli(self):
        repos = ksi_data.load_repo_scope()
        self.assertEqual(len(repos), 7)
        self.assertNotIn("openshift-online/rosa-seaplane-cli", repos)
        self.assertIn("openshift-online/rosa-seaplane-internal", repos)


class Records(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ksis = fedramp_data.load_ksis()

    def rec(self, **decisions):
        return {"ksi": "KSI-CMT-VTD", "target-types": ["github-repository"],
                "measures": "", "automation-verification": "", "validation": "",
                "control-decisions": decisions}

    def test_shipped_records_load(self):
        records = ksi_data.load_records(self.ksis)
        self.assertEqual(sorted(records), ["KSI-CMT-LMC", "KSI-CMT-VTD", "KSI-IAM-SNU"])
        for r in records.values():
            # Empty or still marked "[Proposed, pending review]": neither counts as written.
            self.assertFalse(ksi_data.narrative_written(r))

    def test_valid_decision_normalized(self):
        r = ksi_data.validate_record(
            self.rec(**{"SI-02": {"decision": "not-applicable", "rationale": " why "}}), self.ksis)
        self.assertEqual(r["control-decisions"]["si-2"]["rationale"], "why")

    def test_unknown_ksi_rejected(self):
        r = self.rec()
        r["ksi"] = "KSI-NOPE-NOPE"
        with self.assertRaises(ksi_data.RecordError):
            ksi_data.validate_record(r, self.ksis)

    def test_unrelated_control_rejected(self):
        with self.assertRaises(ksi_data.RecordError):
            ksi_data.validate_record(
                self.rec(**{"ac-2": {"decision": "inherited", "rationale": "x"}}), self.ksis)

    def test_missing_rationale_rejected(self):
        for rationale in (None, "", "   "):
            with self.assertRaises(ksi_data.RecordError):
                ksi_data.validate_record(
                    self.rec(**{"si-2": {"decision": "inherited", "rationale": rationale}}), self.ksis)

    def test_bad_decision_rejected(self):
        with self.assertRaises(ksi_data.RecordError):
            ksi_data.validate_record(
                self.rec(**{"si-2": {"decision": "addressed", "rationale": "x"}}), self.ksis)

    def test_unknown_field_rejected(self):
        r = self.rec()
        r["status"] = "done"
        with self.assertRaises(ksi_data.RecordError):
            ksi_data.validate_record(r, self.ksis)

    def test_unreviewed_text_does_not_count_as_written(self):
        r = self.rec()
        r.update({"measures": "[Proposed, pending review] a", "automation-verification": "b", "validation": "c"})
        self.assertFalse(ksi_data.narrative_written(r))
        r["measures"] = "a"
        self.assertTrue(ksi_data.narrative_written(r))

    def test_narrative_written(self):
        r = self.rec()
        r.update({"measures": "a", "automation-verification": "b", "validation": "c"})
        self.assertTrue(ksi_data.narrative_written(r))
        r["validation"] = " "
        self.assertFalse(ksi_data.narrative_written(r))


if __name__ == "__main__":
    unittest.main()
