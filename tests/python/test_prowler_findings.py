import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import prowler_findings as pf  # noqa: E402

AR = "RSC.CMT.CTRL02.AR01"
FAKE_ID = "1" * 12  # built at run time: no 12-digit number is ever committed
PINNED = pf.load_checks(AR)[0]
CHECKS = pf.load_checks(AR)[1]


def ocsf(check, status, name="example-trail", rtype="AwsCloudTrailTrail", region="us-east-1", detail="ok"):
    """One finding in the shape of real Prowler JSON-OCSF output (trimmed)."""
    return {"metadata": {"event_code": check, "product": {"name": "Prowler"}}, "status_code": status,
            "status_detail": detail, "message": detail,
            "cloud": {"account": {"uid": FAKE_ID}, "region": region, "provider": "aws"},
            "resources": [{"name": name, "type": rtype, "region": region, "uid": f"arn:aws:x:{region}:{FAKE_ID}:{name}"}],
            "unmapped": {"compliance": {"CIS-1.4": ["x"]}, "provider_uid": FAKE_ID},
            "finding_info": {"uid": f"prowler-aws-{check}-{FAKE_ID}-{region}-{name}"}}


def all_passing():
    return [ocsf(c, "PASS") for c in CHECKS]


# A stand-in for the prowler executable: records its arguments, then writes the OCSF file
# named by the environment (or fails), the way the real one writes under --output-directory.
STUB = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
Path(os.environ["FAKE_PROWLER_DIR"], "args.json").write_text(json.dumps(args))
if os.environ.get("FAKE_PROWLER_FAIL"):
    print("An error occurred (AccessDenied) in account " + "1" * 12, file=sys.stderr)
    sys.exit(1)
if os.environ.get("FAKE_PROWLER_NO_OUTPUT"):
    sys.exit(0)
outdir = args[args.index("--output-directory") + 1]
Path(outdir, "rsc.ocsf.json").write_text(Path(os.environ["FAKE_PROWLER_DIR"], "output.json").read_text())
Path(os.environ["FAKE_PROWLER_DIR"], "outdir").write_text(outdir)
sys.exit(0)
'''


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.dir = t / "fake"
        self.dir.mkdir()
        self.bin = t / "bin"
        self.bin.mkdir()
        self.prowler = self.bin / "prowler"
        self.prowler.write_text(STUB)
        self.prowler.chmod(self.prowler.stat().st_mode | stat.S_IEXEC)
        self.set_version(PINNED)
        self.output(all_passing())
        env = {"FAKE_PROWLER_DIR": str(self.dir)}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)

    def set_version(self, version):
        """A dist-info on PYTHONPATH is how importlib.metadata finds 'prowler' for the stub."""
        d = Path(self.tmp.name) / "site"
        for old in d.glob("*.dist-info") if d.exists() else []:
            for f in old.iterdir():
                f.unlink()
            old.rmdir()
        info = d / f"prowler-{version}.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: prowler\nVersion: {version}\n")
        self.site = str(d)

    def output(self, findings):
        (self.dir / "output.json").write_text(json.dumps(findings))

    def collect(self, **kw):
        with mock.patch.dict(os.environ, {"PYTHONPATH": self.site}):
            return pf.collect(AR, kw.get("target", "regional"), kw.get("profile", "rsc-regional-ro"),
                              kw.get("regions", ["us-east-1"]), str(self.prowler), 60)

    def args_used(self):
        return json.loads((self.dir / "args.json").read_text())


class Collect(Base):
    def test_evidence_is_normalized_and_declares_its_ar(self):
        ev = self.collect()
        self.assertEqual((ev["assessment_requirement"], ev["target"], ev["target_type"]), (AR, "regional", "aws_accounts"))
        self.assertEqual(ev["collection"]["complete"], True)
        self.assertEqual(ev["collection"]["prowler_version"], PINNED)
        self.assertEqual(ev["collection"]["required_checks"], CHECKS)
        self.assertEqual(sorted({f["check_id"] for f in ev["findings"]}), sorted(CHECKS))
        self.assertEqual(set(ev["findings"][0]), {"check_id", "status", "region", "resource_type", "resource_name", "detail"})

    def test_runs_only_the_chosen_checks_through_the_readonly_profile_for_the_given_regions(self):
        self.collect(regions=["us-east-1", "us-west-2"])
        a = self.args_used()
        self.assertEqual(a[a.index("--profile") + 1], "rsc-regional-ro")
        self.assertEqual(a[a.index("--checks") + 1:a.index("--checks") + 1 + len(CHECKS)], CHECKS)
        self.assertEqual(a[a.index("--region") + 1:a.index("--region") + 3], ["us-east-1", "us-west-2"])
        self.assertEqual(a[a.index("--output-formats") + 1], "json-ocsf")
        self.assertEqual(a[0], "aws")

    def test_only_readonly_profiles_are_accepted(self):
        for bad in ("rsc-admin", "rsc-regional-admin", "default", "rsc-regional-ro-admin"):
            with self.assertRaises(pf.ProwlerError, msg=bad):
                self.collect(profile=bad)
        self.assertFalse((self.dir / "args.json").exists())  # never even started Prowler

    def test_a_status_other_than_pass_or_fail_is_carried_through_not_rewritten(self):
        self.output([ocsf(CHECKS[0], "MANUAL"), ocsf(CHECKS[1], "FAIL")])
        ev = self.collect()
        self.assertEqual(sorted(f["status"] for f in ev["findings"]), ["FAIL", "MANUAL"])

    def test_a_check_with_no_finding_is_simply_absent_so_the_policy_can_deny_it(self):
        self.output([f for f in all_passing() if f["metadata"]["event_code"] != CHECKS[0]])
        ev = self.collect()
        self.assertNotIn(CHECKS[0], {f["check_id"] for f in ev["findings"]})
        self.assertIn(CHECKS[0], ev["collection"]["required_checks"])

    def test_findings_for_checks_we_did_not_ask_for_are_dropped(self):
        self.output(all_passing() + [ocsf("some_other_check", "FAIL")])
        self.assertNotIn("some_other_check", {f["check_id"] for f in self.collect()["findings"]})

    def test_raw_output_ids_arns_and_compliance_text_never_reach_the_evidence(self):
        self.output([ocsf(CHECKS[0], "PASS", name=f"trail-{FAKE_ID}", detail=f"Trail in account {FAKE_ID} is logging")])
        text = json.dumps(self.collect())
        self.assertNotIn(FAKE_ID, text)
        for leak in ("arn:aws", "CIS-1.4", "provider_uid", "finding_info", "unmapped", "prowler-aws-"):
            self.assertNotIn(leak, text)
        self.assertIn("<account>", text)

    def test_the_temporary_output_directory_is_removed(self):
        self.collect()
        outdir = (self.dir / "outdir").read_text()
        self.assertFalse(Path(outdir).exists())

    def test_long_details_are_truncated(self):
        self.output([ocsf(CHECKS[0], "FAIL", detail="x" * 2000)])
        self.assertLessEqual(len(self.collect()["findings"][0]["detail"]), pf.DETAIL_MAX)


class Safeguards(Base):
    def test_a_different_prowler_version_is_refused_before_anything_runs(self):
        self.set_version("9.9.9")
        with self.assertRaises(pf.ProwlerError) as cm:
            self.collect()
        self.assertIn("9.9.9", str(cm.exception))
        self.assertIn(PINNED, str(cm.exception))
        self.assertFalse((self.dir / "args.json").exists())

    def test_prowler_not_installed_is_an_error(self):
        self.prowler.unlink()
        with self.assertRaises(pf.ProwlerError):
            self.collect()

    def test_a_failed_run_is_an_error_not_an_empty_result(self):
        with mock.patch.dict(os.environ, {"FAKE_PROWLER_FAIL": "1"}):
            with self.assertRaises(pf.ProwlerError) as cm:
                self.collect()
        self.assertIn("exit 1", str(cm.exception))
        self.assertNotIn(FAKE_ID, str(cm.exception))  # error text is masked too

    def test_a_run_that_wrote_nothing_is_incomplete(self):
        with mock.patch.dict(os.environ, {"FAKE_PROWLER_NO_OUTPUT": "1"}):
            ev = self.collect()
        self.assertIs(ev["collection"]["complete"], False)
        self.assertEqual(ev["findings"], [])

    def test_unreadable_output_is_incomplete(self):
        (self.dir / "output.json").write_text("not json")
        self.assertIs(self.collect()["collection"]["complete"], False)

    def test_output_that_is_not_a_list_is_incomplete(self):
        (self.dir / "output.json").write_text('{"a": 1}')
        self.assertIs(self.collect()["collection"]["complete"], False)

    def test_an_empty_result_list_is_incomplete(self):
        self.output([])
        self.assertIs(self.collect()["collection"]["complete"], False)

    def test_a_timeout_is_an_error(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": self.site}):
            with mock.patch.object(pf.subprocess, "run", side_effect=[
                    mock.Mock(returncode=0, stdout=PINNED + "\n", stderr=""),
                    pf.subprocess.TimeoutExpired("prowler", 1)]):
                with self.assertRaises(pf.ProwlerError) as cm:
                    pf.collect(AR, "regional", "rsc-regional-ro", ["us-east-1"], "prowler", 1)
        self.assertIn("did not finish", str(cm.exception))

    def test_unknown_ar_or_missing_config_is_an_error(self):
        with self.assertRaises(pf.ProwlerError):
            pf.load_checks("RSC.NOPE.CTRL01.AR01")


# The shell collector end to end, with Prowler and the SAML re-exec stubbed.
class ShellCollector(Base):
    def run_collector(self, **extra):
        env = dict(os.environ, RSC_AWS_READY="1", RSC_ENV="integration", RSC_EVIDENCE_DIR=str(Path(self.tmp.name) / "out"),
                   RSC_PROWLER=str(self.prowler), PYTHONPATH=self.site, **extra)
        return subprocess.run([str(ROOT / "evidence" / f"{AR}.sh")], env=env, capture_output=True, text=True)

    def manifest(self):
        m = json.loads((Path(self.tmp.name) / "out" / AR / "manifest.json").read_text())
        return {t["name"]: t for t in m["targets"]}

    def test_targets_are_the_environments_logical_accounts_and_evidence_declares_its_ar(self):
        res = self.run_collector()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(sorted(self.manifest()), ["central", "management-mc01", "regional"])
        self.assertTrue(all(t["status"] == "collected" for t in self.manifest().values()))
        ev = json.loads((Path(self.tmp.name) / "out" / AR / "regional.json").read_text())
        self.assertEqual((ev["assessment_requirement"], ev["target"]), (AR, "regional"))
        self.assertNotIn("assessment_requirement", json.loads((Path(self.tmp.name) / "out" / AR / "manifest.json").read_text()))

    def test_a_failing_run_is_a_manifest_error_with_no_evidence_to_mistake_for_a_pass(self):
        res = self.run_collector(FAKE_PROWLER_FAIL="1")
        self.assertNotEqual(res.returncode, 0)  # no account could be collected
        self.assertTrue(all(t["status"] == "error" for t in self.manifest().values()))
        self.assertFalse((Path(self.tmp.name) / "out" / AR / "regional.json").exists())

    def test_a_version_mismatch_is_a_manifest_error(self):
        self.set_version("1.0.0")
        res = self.run_collector()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("pinned", " ".join(t.get("error", "") for t in self.manifest().values()))

    def test_the_collector_makes_no_aws_calls_of_its_own_and_uses_only_ro_profiles(self):
        calls = Path(self.tmp.name) / "aws-calls.log"
        aws = self.bin / "aws"
        aws.write_text(f"#!/usr/bin/env bash\necho \"$@\" >> {calls}\nexit 0\n")
        aws.chmod(aws.stat().st_mode | stat.S_IEXEC)
        self.run_collector(PATH=f"{self.bin}:{os.environ['PATH']}")
        self.assertFalse(calls.exists())  # Prowler is the only thing that talks to AWS
        self.assertIn("-ro", " ".join(self.args_used()))
        self.assertNotIn("admin", " ".join(self.args_used()))


if __name__ == "__main__":
    unittest.main()
