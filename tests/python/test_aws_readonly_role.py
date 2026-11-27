import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import aws_readonly_role as r  # noqa: E402

# Fake IDs are built at run time so that no 12-digit number is ever committed
# (tests/python/test_no_account_ids.py enforces that for the whole repo).
FAKE_ID = "1" * 12
OTHER_FAKE_ID = "2" * 12

GOOD = """role-name: x
trust: same-account
managed-policies:
  - arn: arn:aws:iam::aws:policy/SecurityAudit
    needed-by: [a check]
actions:
  - action: iam:GetCredentialReport
    needed-by: a check
"""


def load(text):
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "d.yaml"
        p.write_text(text)
        return r.load_definition(p)


class Definition(unittest.TestCase):
    def test_shipped_definition_is_valid(self):
        d = r.load_definition()
        self.assertEqual(d["trust"], "same-account")
        self.assertTrue(all(a["needed-by"] for a in d["actions"]))

    def test_shipped_definition_has_no_account_ids(self):
        text = r.DEFINITION.read_text()
        self.assertIsNone(r.ID_RE.search(text))

    def test_good_example_loads(self):
        self.assertEqual(load(GOOD)["role-name"], "x")

    def test_account_ids_are_rejected(self):
        for bad in (GOOD + f"# arn:aws:iam::{FAKE_ID}:role/x\n", GOOD.replace("x\ntrust", f"x{FAKE_ID}\ntrust")):
            with self.assertRaises(r.DefinitionError):
                load(bad)

    def test_account_scoped_arn_is_rejected(self):
        with self.assertRaises(r.DefinitionError):
            load(GOOD.replace("arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::acct:policy/Mine"))

    def test_write_actions_are_rejected(self):
        for act in ("iam:CreateUser", "s3:PutObject", "ec2:TerminateInstances", "iam:*"):
            with self.assertRaises(r.DefinitionError, msg=act):
                load(GOOD.replace("iam:GetCredentialReport", act))

    def test_every_permission_must_say_why(self):
        with self.assertRaises(r.DefinitionError):
            load(GOOD.replace("    needed-by: a check\n", ""))
        with self.assertRaises(r.DefinitionError):
            load(GOOD.replace("    needed-by: [a check]\n", ""))

    def test_tags_must_use_characters_iam_accepts(self):
        for bad in ("a (b)", "a;b", "a,b"):
            with self.assertRaises(r.DefinitionError, msg=bad):
                load(GOOD + f"tags:\n  managed-by: \"{bad}\"\n")
        load(GOOD + "tags:\n  managed-by: ok-value_1.2:x/y=z+w@q\n")

    def test_only_same_account_trust_is_supported(self):
        with self.assertRaises(r.DefinitionError):
            load(GOOD.replace("same-account", "anyone"))


class Policies(unittest.TestCase):
    def test_trust_policy_names_only_the_account_root(self):
        p = r.trust_policy(OTHER_FAKE_ID)
        self.assertEqual(p["Statement"][0]["Principal"], {"AWS": f"arn:aws:iam::{OTHER_FAKE_ID}:root"})
        self.assertEqual(p["Statement"][0]["Action"], "sts:AssumeRole")

    def test_inline_policy_is_the_declared_actions_only(self):
        d = r.load_definition()
        stmt = r.inline_policy(d)["Statement"][0]
        self.assertEqual(stmt["Effect"], "Allow")
        self.assertEqual(stmt["Action"], sorted(a["action"] for a in d["actions"]))

    def test_mask_hides_ids(self):
        self.assertEqual(r.mask(f"arn:aws:iam::{FAKE_ID}:role/x"), "arn:aws:iam::<ID>:role/x")


class Safety(unittest.TestCase):
    def test_writes_need_an_explicit_yes(self):
        import argparse
        for fn in (r.cmd_apply, r.cmd_delete):
            with self.assertRaises(SystemExit):
                fn(argparse.Namespace(profile="p", yes=False), r.load_definition())

    def test_main_refuses_to_write_without_yes_before_touching_aws(self):
        from unittest import mock
        for cmd in ("apply", "delete"):
            with mock.patch.object(sys, "argv", ["x", cmd, "--env", "integration"]):
                with mock.patch.object(r.aws_access, "aws_environment", side_effect=AssertionError("touched AWS")):
                    with self.assertRaises(SystemExit) as cm:
                        r.main()
                    self.assertIn("--yes", str(cm.exception))

    def test_unknown_account_is_rejected_before_touching_aws(self):
        from unittest import mock
        with mock.patch.object(sys, "argv", ["x", "plan", "--env", "integration", "--account", "nope"]):
            with mock.patch.object(r.aws_access, "aws_environment", side_effect=AssertionError("touched AWS")):
                with self.assertRaises(SystemExit) as cm:
                    r.main()
                self.assertIn("unknown account", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
