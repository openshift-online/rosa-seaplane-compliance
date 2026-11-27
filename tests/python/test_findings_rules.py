"""The rules catalog and the limits sidecar must stay in step with the policies and collectors."""
import re
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "evidence/lib"))

import build_findings as bf  # noqa: E402
import argocd_health  # noqa: E402
import build_trace  # noqa: E402
import deployment_pipeline  # noqa: E402
import iam_key_usage  # noqa: E402

REGO_FILES = [p for p in sorted(ROOT.glob("opa/*/policy/*.rego")) if not p.name.endswith("_test.rego")]
WITH_RULE = re.compile(r'with_rule\(\s*"([^"]+)"')
DENY = re.compile(r"^deny contains msg if", re.M)
MSG_ASSIGN = re.compile(r'msg := with_rule\(\s*"([^"]+)"')


def rego_rule_ids():
    ids = []
    for p in REGO_FILES:
        ids += MSG_ASSIGN.findall(p.read_text())
    return ids


class RuleCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = bf.load_rules()
        _, cls.ars = build_trace.load_catalogs(ROOT)

    def test_every_deny_carries_a_rule_id(self):
        for p in REGO_FILES:
            text = p.read_text()
            self.assertEqual(len(DENY.findall(text)), len(MSG_ASSIGN.findall(text)),
                             f"{p.name}: every `deny` must set msg := with_rule(\"<id>\", ...)")

    def test_rule_ids_in_rego_are_unique(self):
        ids = rego_rule_ids()
        self.assertEqual(len(ids), len(set(ids)), "a rule id is used by more than one deny")

    def test_every_rego_rule_is_in_the_catalog_and_the_catalog_has_nothing_unused(self):
        used, known = set(rego_rule_ids()), set(self.rules["rules"])
        self.assertEqual(used - known, set(), "rule ids used in Rego but missing from config/findings/rules.yaml")
        self.assertEqual(known - used, set(), "rule ids in config/findings/rules.yaml that no Rego deny uses")

    def test_every_rule_has_a_title_and_a_fix_hint(self):
        for section in ("rules", "collection"):
            for rid, entry in self.rules[section].items():
                self.assertTrue(str(entry.get("title") or "").strip(), f"{rid} has no title")
                self.assertGreater(len(str(entry.get("fix") or "").split()), 4, f"{rid} needs a real fix hint")

    def test_kinds_are_valid_and_collection_rules_are_never_a_violation(self):
        for rid, entry in self.rules["rules"].items():
            self.assertIn(entry["kind"], ("violation", "incomplete-evidence"), rid)
        for rid, entry in self.rules["collection"].items():
            self.assertEqual(entry["kind"], "not-reached", rid)

    def test_every_rule_belongs_to_a_known_ar(self):
        for rid, entry in self.rules["rules"].items():
            self.assertIn(entry["ar"], self.ars, rid)

    def test_each_example_is_tagged_with_its_own_id_and_the_subject_pattern_matches_it(self):
        for rid, entry in self.rules["rules"].items():
            rule, message = bf.parse_denial(entry["example"], self.rules)
            self.assertEqual(rule, rid, f"{rid}: example is not tagged with its own id")
            if entry["_subject"] is not None:
                subject = bf.subject_of(entry, message, "TARGET")
                self.assertNotEqual(subject, "TARGET", f"{rid}: subject pattern does not match its example")
                self.assertTrue(subject.strip())

    def test_rule_ids_look_like_ids(self):
        for rid in list(self.rules["rules"]) + list(self.rules["collection"]):
            self.assertRegex(rid, r"^[a-z0-9\-]+(\.[a-z0-9\-]+)+$")


class Limits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.ars = build_trace.load_catalogs(ROOT)
        cls.plans = build_trace.load_plans(ROOT)
        cls.sidecar = yaml.safe_load(bf.LIMITS_FILE.read_text())
        cls.limits = bf.load_limits()

    def test_every_key_is_a_known_ar_and_every_entry_is_plain_text(self):
        for ar, items in self.sidecar.items():
            self.assertIn(ar, self.ars)
            self.assertTrue(items)
            self.assertTrue(all(isinstance(i, str) and i.strip() for i in items), f"{ar}: quote items that contain a colon")

    def test_every_automated_requirement_states_its_limits(self):
        for ar, plan in self.plans.items():
            if plan.get("mode") == "Automated":
                self.assertTrue(self.limits.get(ar), f"{ar} has no limits recorded in evidence/known-gaps.yaml")

    def test_the_collectors_own_recorded_limitations_are_in_the_sidecar(self):
        listed = [" ".join(t.split()) for t in self.sidecar["RSC.IAM.CTRL01.AR02"]]
        for limitation in iam_key_usage.LIMITATIONS:
            self.assertIn(" ".join(limitation.split()), listed, "the collector records a limit the sidecar does not")

    def test_the_deployment_collectors_own_recorded_limitations_are_in_the_sidecar(self):
        listed = [" ".join(t.split()) for t in self.sidecar["RSC.CMT.CTRL03.AR01"]]
        for limitation in deployment_pipeline.LIMITATIONS:
            self.assertIn(" ".join(limitation.split()), listed, "the collector records a limit the sidecar does not")

    def test_the_health_collectors_own_recorded_limitations_are_in_the_sidecar(self):
        listed = [" ".join(t.split()) for t in self.sidecar["RSC.CMT.CTRL03.AR02"]]
        for limitation in argocd_health.LIMITATIONS:
            self.assertIn(" ".join(limitation.split()), listed, "the collector records a limit the sidecar does not")

    def test_prowler_does_not_cover_items_are_added_for_their_requirement(self):
        texts = [x["text"] for x in self.limits["RSC.CMT.CTRL02.AR01"]]
        self.assertTrue(any("Alarms on specific kinds of change" in t for t in texts))
        self.assertTrue(all(isinstance(t, str) for t in texts))

    def test_wording_stays_generic_because_the_repository_is_public(self):
        for path in (bf.LIMITS_FILE, bf.RULES_FILE):
            text = path.read_text().lower()
            for needle in ("openshift-online", "rosa-seaplane", "dana", "erin", "konflux", "e2e"):
                self.assertNotIn(needle, text, f"{path.name} must not name {needle!r}")
            self.assertIsNone(re.search(r"[0-9]{12}", text))

    def test_a_non_string_limit_is_rejected_not_printed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "gaps.yaml"
            p.write_text("RSC.X.AR1:\n  - Who receives it: the check confirms it exists.\n")
            with self.assertRaises(bf.FindingsError):
                bf.load_limits(p, Path(t) / "none.yaml")


if __name__ == "__main__":
    unittest.main()
