import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import environment  # noqa: E402


class Environments(unittest.TestCase):
    def test_shipped_environments(self):
        self.assertEqual(environment.available(), ["integration", "stage"])

    def test_integration_shape(self):
        env = environment.load("integration", {})
        self.assertEqual((env["snapshot"], env["regions"]), ("int", ["us-east-1"]))
        self.assertEqual([a["name"] for a in env["accounts"]], ["central", "regional", "management-mc01"])
        self.assertEqual(env["saml_role"], "rosa-hyperfleet-int-admin")

    def test_stage_has_two_management_accounts(self):
        names = [a["name"] for a in environment.load("stage", {})["accounts"]]
        self.assertEqual(names, ["central", "regional", "management-mc01", "management-mc02"])

    def test_account_names_are_logical_names_only(self):
        self.assertEqual(environment.account_names("integration", {}), ["central", "regional", "management-mc01"])

    def test_accounts_flag_prints_names_one_per_line(self):
        import subprocess
        out = subprocess.run([sys.executable, str(ROOT / "scripts/environment.py"), "--accounts", "stage"],
                             capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(out, ["central", "regional", "management-mc01", "management-mc02"])

    def test_default_is_integration(self):
        self.assertEqual(environment.load(environ={})["name"], "integration")

    def test_rsc_env_selects_environment(self):
        self.assertEqual(environment.load(environ={"RSC_ENV": "stage"})["name"], "stage")

    def test_stage_differs_from_integration_only_in_data(self):
        a, b = environment.load("integration", {}), environment.load("stage", {})
        self.assertEqual(a["regions"], b["regions"])
        self.assertEqual([x["snapshot_path"] for x in a["accounts"][:2]], [x["snapshot_path"] for x in b["accounts"][:2]])

    def test_unknown_or_hostile_name_rejected(self):
        for bad in ("prod", "../x", "Integration"):
            with self.assertRaises(environment.EnvironmentError_):
                environment.load(bad, {})

    def test_configs_hold_no_identifiers_or_profile_names(self):
        import re
        for p in (ROOT / "config/environments").glob("*.yaml"):
            text = p.read_text()
            self.assertIsNone(re.search(r"[0-9]{12}|arn:aws", text), p.name)
            self.assertNotIn("profile:", text)


BASE = """name: demo
regions: [us-east-1]
snapshot: demo
saml-role: demo-admin
accounts:
  central:
    snapshot-path: control_account_id
  regional:
    snapshot-path: "{region}.rc_account_id"
"""

DEPLOYMENT = """deployment:
  repository: example-org/platform
  branch: null
  allowed-lag-minutes: 90
  pipelines:
    - name: regional-pipeline
      account: central
    - name: mc01-pipeline
      account: central
"""


class DeploymentBlock(unittest.TestCase):
    def load(self, text):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "demo.yaml").write_text(text)
            return environment.load("demo", {}, Path(t))

    def test_shipped_environments_name_their_pipelines_and_the_lag(self):
        for name in ("integration", "stage"):
            dep = environment.deployment(name, {})
            self.assertEqual(dep["repository"], "openshift-online/rosa-seaplane")
            self.assertEqual([p["name"] for p in dep["pipelines"]], ["regional-pipeline", "mc01-pipeline"])
            self.assertEqual({p["account"] for p in dep["pipelines"]}, {"central"})
            self.assertEqual(dep["allowed_lag_minutes"], 120)
            self.assertIsNone(dep["branch"])

    def test_pipeline_names(self):
        self.assertEqual(environment.pipeline_names("integration", {}), ["regional-pipeline", "mc01-pipeline"])

    def test_a_valid_block_is_parsed(self):
        dep = self.load(BASE + DEPLOYMENT)["deployment"]
        self.assertEqual((dep["repository"], dep["allowed_lag_minutes"], dep["branch"]), ("example-org/platform", 90, None))
        self.assertEqual([p["name"] for p in dep["pipelines"]], ["regional-pipeline", "mc01-pipeline"])

    def test_an_environment_without_a_block_loads_but_never_guesses(self):
        env = self.load(BASE)
        self.assertIsNone(env["deployment"])
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "demo.yaml").write_text(BASE)
            self.assertEqual(environment.pipeline_names("demo", {}, Path(t)), [])
            with self.assertRaises(environment.EnvironmentError_):
                environment.deployment("demo", {}, Path(t))

    def test_invalid_blocks_are_rejected(self):
        bad = {
            "repository": DEPLOYMENT.replace("example-org/platform", "no-slash"),
            "branch": DEPLOYMENT.replace("branch: null", "branch: 'a b;c'"),
            "lag zero": DEPLOYMENT.replace("90", "0"),
            "lag huge": DEPLOYMENT.replace("90", "20000"),
            "lag a string": DEPLOYMENT.replace("90", "soon"),
            "lag a bool": DEPLOYMENT.replace("90", "true"),
            "unknown account": DEPLOYMENT.replace("account: central", "account: nowhere", 1),
            "no pipelines": "deployment:\n  repository: example-org/platform\n  branch: null\n  allowed-lag-minutes: 90\n  pipelines: []\n",
            "duplicate": DEPLOYMENT.replace("mc01-pipeline", "regional-pipeline"),
            "bad name": DEPLOYMENT.replace("mc01-pipeline", "bad name!"),
            "not a mapping": "deployment: [1, 2]\n",
        }
        for label, block in bad.items():
            with self.assertRaises(environment.EnvironmentError_, msg=label):
                self.load(BASE + block)

    def test_the_command_line_prints_pipelines_and_the_block(self):
        import json
        import subprocess
        run = lambda *a: subprocess.run([sys.executable, str(ROOT / "scripts/environment.py"), *a], capture_output=True, text=True)
        self.assertEqual(run("--pipelines", "integration").stdout.split(), ["regional-pipeline", "mc01-pipeline"])
        self.assertEqual(json.loads(run("--deployment", "integration").stdout)["allowed_lag_minutes"], 120)
        self.assertNotEqual(run("--deployment", "nonexistent").returncode, 0)


HEALTH = """  health:
    account: regional
    clusters: [regional, mc01]
    lookback-minutes: 20
    freshness-seconds: 120
    step-seconds: 30
"""


class HealthBlock(unittest.TestCase):
    def load(self, text):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "demo.yaml").write_text(text)
            return environment.load("demo", {}, Path(t))

    def test_shipped_environments_name_their_clusters_and_the_window(self):
        for name in ("integration", "stage"):
            h = environment.health(name, {})
            self.assertEqual((h["account"], h["clusters"]), ("regional", ["regional", "mc01"]))
            self.assertEqual((h["lookback_minutes"], h["freshness_seconds"], h["step_seconds"]), (30, 300, 60))
            self.assertEqual(environment.cluster_names(name, {}), ["regional", "mc01"])

    def test_a_valid_block_is_parsed_with_its_values(self):
        h = self.load(BASE + DEPLOYMENT + HEALTH)["deployment"]["health"]
        self.assertEqual((h["account"], h["clusters"], h["lookback_minutes"], h["freshness_seconds"], h["step_seconds"]),
                         ("regional", ["regional", "mc01"], 20, 120, 30))

    def test_defaults_when_only_the_required_fields_are_given(self):
        text = BASE + DEPLOYMENT + "  health:\n    account: regional\n    clusters: [regional]\n"
        h = self.load(text)["deployment"]["health"]
        self.assertEqual((h["lookback_minutes"], h["freshness_seconds"], h["step_seconds"]), (30, 300, 60))

    def test_no_health_block_loads_but_never_guesses(self):
        env = self.load(BASE + DEPLOYMENT)
        self.assertIsNone(env["deployment"]["health"])
        self.assertIsNone(self.load(BASE)["deployment"])

    def test_invalid_blocks_are_rejected(self):
        bad = {
            "unknown account": HEALTH.replace("account: regional", "account: elsewhere"),
            "no clusters": HEALTH.replace("clusters: [regional, mc01]", "clusters: []"),
            "duplicate cluster": HEALTH.replace("[regional, mc01]", "[mc01, mc01]"),
            "bad cluster name": HEALTH.replace("[regional, mc01]", '["a b"]'),
            "lookback too small": HEALTH.replace("lookback-minutes: 20", "lookback-minutes: 1"),
            "lookback not a number": HEALTH.replace("lookback-minutes: 20", "lookback-minutes: soon"),
            "freshness too large": HEALTH.replace("freshness-seconds: 120", "freshness-seconds: 99999"),
            "step too small": HEALTH.replace("step-seconds: 30", "step-seconds: 1"),
            "boolean number": HEALTH.replace("step-seconds: 30", "step-seconds: true"),
        }
        for why, block in bad.items():
            with self.assertRaises(environment.EnvironmentError_, msg=why):
                self.load(BASE + DEPLOYMENT + block)

    def test_cluster_names_is_empty_without_a_block_and_health_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "demo.yaml").write_text(BASE + DEPLOYMENT)
            self.assertEqual(environment.cluster_names("demo", {}, Path(t)), [])
            with self.assertRaises(environment.EnvironmentError_):
                environment.health("demo", {}, Path(t))


if __name__ == "__main__":
    unittest.main()
