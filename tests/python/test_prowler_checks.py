"""config/prowler/checks.yaml is the record of why each Prowler check is in or out; the
Rego holds the checks that are required. They must not drift apart."""
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import prowler_findings as pf  # noqa: E402

AR = "RSC.CMT.CTRL02.AR01"
REGO = ROOT / "opa/change-management/policy/prowler_account_change_logging.rego"
DOC = yaml.safe_load((ROOT / "config/prowler/checks.yaml").read_text())
ENTRY = DOC["assessment-requirements"][AR]


def rego_set(name: str) -> set:
    text = REGO.read_text()
    m = re.search(rf"^{name} := \{{(.*?)\n\}}", text, re.S | re.M)
    assert m, f"{name} not found in {REGO.name}"
    return set(re.findall(r'"([a-z0-9_]+)"', m.group(1)))


class Record(unittest.TestCase):
    def test_the_rego_requires_exactly_the_checks_in_the_record(self):
        self.assertEqual(rego_set("required_checks"), {c["id"] for c in ENTRY["checks"]})

    def test_per_region_checks_are_among_the_required_ones(self):
        self.assertTrue(rego_set("per_region_checks") <= rego_set("required_checks"))

    def test_every_check_has_a_reason_and_none_is_both_in_and_out(self):
        ins = [c["id"] for c in ENTRY["checks"]]
        outs = [c["id"] for c in ENTRY["considered-and-left-out"]]
        self.assertFalse(set(ins) & set(outs))
        self.assertEqual(len(set(ins + outs)), len(ins + outs), "a check is listed twice")
        for c in ENTRY["checks"] + ENTRY["considered-and-left-out"]:
            self.assertGreater(len(c["why"].strip()), 20, c["id"])

    def test_all_sixteen_candidates_were_considered(self):
        self.assertEqual(len(ENTRY["checks"]) + len(ENTRY["considered-and-left-out"]), 16)

    def test_what_the_set_does_not_cover_is_stated(self):
        self.assertGreaterEqual(len(ENTRY["does-not-cover"]), 3)

    def test_the_version_is_pinned_once_and_the_readme_says_the_same(self):
        version = DOC["prowler-version"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertIn(f"prowler=={version}", (ROOT / "README.md").read_text())
        self.assertEqual(pf.load_checks(AR)[0], version)

    def test_the_catalog_and_policy_stay_neutral(self):
        for f in ("gemara/change-management/controls.yaml", "gemara/change-management/policy.yaml"):
            text = (ROOT / f).read_text().lower().replace("prowler_account_change_logging.rego", "")
            for pattern in (r"\bfedramp\b", r"\bksi\b", r"800-53", r"\bnist\b"):
                self.assertIsNone(re.search(pattern, text), f"{pattern} in {f}")


if __name__ == "__main__":
    unittest.main()
