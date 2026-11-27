import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_record as br  # noqa: E402


def policy_ars():
    ars = set()
    for p in sorted((ROOT / "gemara").glob("*/policy.yaml")):
        doc = yaml.safe_load(p.read_text())
        stack = [doc]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                stack.extend(x.values())
            elif isinstance(x, list):
                stack.extend(x)
            elif isinstance(x, str) and x.startswith("RSC.") and ".AR" in x:
                ars.add(x)
    return ars


class ArBasis(unittest.TestCase):
    def test_every_assessment_requirement_declares_a_basis_and_nothing_extra(self):
        declared = set(br.load_basis())
        ars = policy_ars()
        self.assertTrue(ars)
        self.assertEqual(sorted(ars - declared), [], "AR in a policy without a declared basis")
        self.assertEqual(sorted(declared - ars), [], "basis declared for an AR no policy uses")

    def test_state_rules_exist_in_the_findings_rules_under_that_ar(self):
        rules = yaml.safe_load((ROOT / "config/findings/rules.yaml").read_text())
        text = yaml.safe_dump(rules)
        for ar, b in br.load_basis().items():
            for rule in b["state_rules"]:
                self.assertIn(rule, text, f"{ar}: state rule {rule} not in config/findings/rules.yaml")


if __name__ == "__main__":
    unittest.main()
