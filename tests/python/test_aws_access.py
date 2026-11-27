import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import aws_access  # noqa: E402
import environment  # noqa: E402

# Fake account IDs are built at run time: no 12-digit number is ever committed.
CENTRAL, REGIONAL, MC01, MC02 = ("1" * 12, "2" * 12, "3" * 12, "4" * 12)


def snapshot(tmp: Path, mc02=False) -> Path:
    mcs = {"mc01": MC01, **({"mc02": MC02} if mc02 else {})}
    p = tmp / "terragrunt-accounts.json"
    p.write_text(json.dumps({"control_account_id": CENTRAL,
                             "us-east-1": {"rc_account_id": REGIONAL, "mc_account_ids": mcs}}))
    return p


class Resolution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_accounts_resolve_from_the_snapshot_paths(self):
        env = environment.load("integration", {})
        got = aws_access.resolve_accounts(env, snapshot(self.dir))
        self.assertEqual(got, {"central": CENTRAL, "regional": REGIONAL, "management-mc01": MC01})

    def test_stage_resolves_both_management_accounts(self):
        env = environment.load("stage", {})
        got = aws_access.resolve_accounts(env, snapshot(self.dir, mc02=True))
        self.assertEqual((got["management-mc01"], got["management-mc02"]), (MC01, MC02))

    def test_an_account_missing_from_the_snapshot_is_reported_not_guessed(self):
        env = environment.load("stage", {})
        got = aws_access.resolve_accounts(env, snapshot(self.dir, mc02=False))
        self.assertIsNone(got["management-mc02"])
        with self.assertRaises(aws_access.AccessError):
            aws_access.config_text(env, got, Path("/x"))

    def test_missing_snapshot_explains_how_to_fix_it(self):
        with self.assertRaises(aws_access.AccessError) as cm:
            aws_access.resolve_accounts(environment.load("integration", {}), self.dir / "nope.json")
        self.assertIn("sibling", str(cm.exception))
        self.assertIn("RSC_ACCOUNTS_FILE", str(cm.exception))

    def test_snapshot_location_defaults_to_the_sibling_checkout_and_can_be_overridden(self):
        env = environment.load("integration", {})
        default = aws_access.snapshot_file(env, {})
        self.assertTrue(str(default).endswith("rosa-seaplane-internal/infra/accounts/int/terragrunt-accounts.json"))
        self.assertEqual(aws_access.snapshot_file(env, {"RSC_ACCOUNTS_FILE": "/elsewhere.json"}), Path("/elsewhere.json"))

    def test_describe_never_exposes_ids(self):
        env = environment.load("integration", {})
        out = aws_access.describe(env, {"RSC_ACCOUNTS_FILE": str(snapshot(self.dir))})
        self.assertEqual(out["resolved"], {"central": True, "regional": True, "management-mc01": True})
        self.assertNotIn(CENTRAL, json.dumps(out))


class Config(unittest.TestCase):
    def text(self):
        env = environment.load("integration", {})
        accounts = {"central": CENTRAL, "regional": REGIONAL, "management-mc01": MC01}
        return aws_access.config_text(env, accounts, Path("/seaplane"))

    def test_admin_profile_logs_in_with_the_platforms_saml_helper(self):
        t = self.text()
        self.assertIn(f"uv run /seaplane/scripts/dev/cached_saml_credentials_process.py {CENTRAL} {CENTRAL}-rosa-hyperfleet-int-admin", t)

    def test_child_accounts_chain_from_the_saml_login_through_the_admin_role(self):
        t = self.text()
        self.assertIn(f"[profile rsc-regional-admin]\nrole_arn = arn:aws:iam::{REGIONAL}:role/rosa-seaplane-account-admin\nsource_profile = rsc-admin", t)

    def test_readonly_profiles_chain_from_their_accounts_admin_profile(self):
        t = self.text()
        self.assertIn(f"[profile rsc-regional-ro]\nrole_arn = arn:aws:iam::{REGIONAL}:role/rosa-seaplane-compliance-readonly\nsource_profile = rsc-regional-admin", t)
        self.assertIn(f"[profile rsc-central-ro]\nrole_arn = arn:aws:iam::{CENTRAL}:role/rosa-seaplane-compliance-readonly\nsource_profile = rsc-admin", t)

    def test_profile_naming(self):
        self.assertEqual(aws_access.admin_profile("central"), "rsc-admin")
        self.assertEqual(aws_access.admin_profile("regional"), "rsc-regional-admin")
        self.assertEqual(aws_access.readonly_profile("management-mc01"), "rsc-management-mc01-ro")


class TemporaryEnvironment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = environment.load("integration", {})
        self.environ = {"RSC_ACCOUNTS_FILE": str(snapshot(Path(self.tmp.name)))}

    def run_ctx(self):
        with mock.patch.object(aws_access.shutil, "which", return_value="/usr/bin/uv"):
            return aws_access.aws_environment(self.env, self.environ)

    def test_config_lives_in_a_temp_dir_removed_afterwards_and_never_under_dot_aws(self):
        with self.run_ctx() as ctx:
            cfg = Path(os.environ["AWS_CONFIG_FILE"])
            self.assertTrue(cfg.is_file())
            self.assertNotIn(str(Path.home() / ".aws"), str(cfg))
            self.assertEqual(oct(Path(ctx["config_dir"]).stat().st_mode)[-3:], "700")
            kept = ctx["config_dir"]
        self.assertFalse(Path(kept).exists())

    def test_inherited_aws_variables_cannot_override_the_generated_profiles(self):
        with mock.patch.dict(os.environ, {"AWS_PROFILE": "personal", "AWS_ACCESS_KEY_ID": "x", "AWS_REGION": "eu-west-1"}):
            with self.run_ctx():
                for k in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_REGION"):
                    self.assertNotIn(k, os.environ)
            self.assertEqual(os.environ["AWS_PROFILE"], "personal")  # restored for the caller

    def test_environment_is_restored_even_after_an_error(self):
        before = os.environ.get("AWS_CONFIG_FILE")
        with self.assertRaises(RuntimeError):
            with self.run_ctx():
                raise RuntimeError("boom")
        self.assertEqual(os.environ.get("AWS_CONFIG_FILE"), before)

    def test_uv_is_required(self):
        with mock.patch.object(aws_access.shutil, "which", return_value=None):
            with self.assertRaises(aws_access.AccessError):
                with aws_access.aws_environment(self.env, self.environ):
                    pass

    def test_mask(self):
        self.assertEqual(aws_access.mask(f"arn:aws:iam::{CENTRAL}:role/x"), "arn:aws:iam::<ID>:role/x")


if __name__ == "__main__":
    unittest.main()
