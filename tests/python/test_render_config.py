import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import render_complytime_config as rc  # noqa: E402

spec = importlib.util.spec_from_file_location("entrypoint", ROOT / "containers/complyctl/entrypoint.py")
entrypoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entrypoint)


def make_domains(root: Path, names):
    for n in names:
        (root / n).mkdir(parents=True)
        (root / n / "policy.yaml").write_text("metadata: {id: x}\n")
    (root / "no-policy").mkdir()  # not a domain


class Render(unittest.TestCase):
    def test_discovers_domains(self):
        with tempfile.TemporaryDirectory() as t:
            make_domains(Path(t), ["b-domain", "a-domain"])
            self.assertEqual(rc.domains(Path(t)), ["a-domain", "b-domain"])

    def test_every_domain_gets_a_policy_and_the_target_uses_all(self):
        text = rc.render(["a", "b"], "http://localhost:5050/x/", "v1", "v2")
        cfg = yaml.safe_load(text)
        self.assertEqual([p["id"] for p in cfg["policies"]], ["a", "b"])
        self.assertEqual(cfg["policies"][0]["url"], "http://localhost:5050/x/policies/a:v1")
        self.assertEqual(cfg["complypacks"][0]["url"], "http://localhost:5050/x/complypacks/rosa-seaplane:v2")
        self.assertEqual(len(cfg["targets"]), 1)
        self.assertEqual(cfg["targets"][0]["policies"], ["a", "b"])
        self.assertEqual(cfg["targets"][0]["variables"]["input_path"], "${RSC_EVIDENCE_DIR}")

    def test_marked_generated(self):
        self.assertIn("GENERATED", rc.render(["a"], "r", "v", "v").splitlines()[0])

    def test_no_domains_is_an_error(self):
        with self.assertRaises(SystemExit):
            rc.render([], "r", "v", "v")


class EntrypointDomains(unittest.TestCase):
    def test_policy_ids_follow_domains(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as t:
            make_domains(Path(t) / "gemara", ["one", "two"])
            os.chdir(t)
            try:
                self.assertEqual(entrypoint.policy_ids(), ["one", "two"])
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()


class ComplypackSources(unittest.TestCase):
    """complypack has no glob support for gemara sources, so complypack.yaml
    lists them by hand. Fail loudly when a domain is forgotten."""

    def test_every_domain_is_a_complypack_source(self):
        cfg = yaml.safe_load((ROOT / "complypack.yaml").read_text())
        sources = {s["source"] for s in cfg["gemara"]["sources"]}
        for d in rc.domains(ROOT / "gemara"):
            for f in ("controls.yaml", "policy.yaml"):
                self.assertIn(f"file://gemara/{d}/{f}", sources,
                              f"add gemara/{d}/{f} to complypack.yaml gemara.sources")
