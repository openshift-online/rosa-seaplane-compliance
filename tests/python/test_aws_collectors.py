import base64
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AR = "RSC.IAM.CTRL01.AR01"
HEADER = "user,arn,password_enabled,access_key_1_active,access_key_2_active"

# A stand-in for the aws CLI keyed on the profile: what each integration account returns.
FAKE_AWS = r"""#!/usr/bin/env bash
args="$*"
profile="$(sed -n 's/.*--profile \([^ ]*\).*/\1/p' <<<"$args")"
echo "$profile $args" >> "${FAKE_AWS_DIR}/calls.log"
case "$args" in
  *generate-credential-report*)
    [[ -f "${FAKE_AWS_DIR}/${profile}.never-ready" ]] && { echo "INPROGRESS"; exit 0; }
    [[ -f "${FAKE_AWS_DIR}/${profile}.denied" ]] && { echo "An error occurred (AccessDenied)" >&2; exit 1; }
    echo "COMPLETE" ;;
  *get-credential-report*)
    cat "${FAKE_AWS_DIR}/${profile}.report" ;;
  *) echo "unexpected aws call: $args" >&2; exit 2 ;;
esac
"""


def report(*rows, header=HEADER):
    text = "\n".join([header, *rows]) + "\n"
    return json.dumps({"Content": base64.b64encode(text.encode()).decode(), "GeneratedTime": "2026-11-24T10:00:00+00:00"})


ROOT_ROW = "<root_account>,arn:x,not_supported,false,false"
CLEAN = report(ROOT_ROW, "svc,arn:y,false,false,false")
ACTIVE_KEY = report(ROOT_ROW, "svc,arn:y,false,true,false")


class AwsCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        aws = t / "bin" / "aws"
        aws.write_text(FAKE_AWS)
        aws.chmod(aws.stat().st_mode | stat.S_IEXEC)
        self.fake = t / "fake"
        self.fake.mkdir()
        self.out = t / "out"

    def account(self, name, report_text=None, denied=False, never_ready=False):
        if report_text is not None:
            (self.fake / f"rsc-{name}-ro.report").write_text(report_text)
        if denied:
            (self.fake / f"rsc-{name}-ro.denied").write_text("")
        if never_ready:
            (self.fake / f"rsc-{name}-ro.never-ready").write_text("")

    def run_collector(self):
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", FAKE_AWS_DIR=str(self.fake),
                   RSC_AWS_READY="1",  # skip the re-exec into the temporary AWS config: the stub stands in for it
                   RSC_ENV="integration", RSC_EVIDENCE_DIR=str(self.out),
                   RSC_CREDENTIAL_REPORT_TRIES="2", RSC_CREDENTIAL_REPORT_SLEEP="0")
        return subprocess.run([str(ROOT / "evidence" / f"{AR}.sh")], env=env, capture_output=True, text=True)

    def manifest(self):
        return {t["name"]: t for t in json.loads((self.out / AR / "manifest.json").read_text())["targets"]}

    def evidence(self, name):
        return json.loads((self.out / AR / f"{name}.json").read_text())

    def test_targets_are_the_environments_logical_accounts(self):
        for a in ("central", "regional", "management-mc01"):
            self.account(a, CLEAN)
        res = self.run_collector()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(sorted(self.manifest()), ["central", "management-mc01", "regional"])
        self.assertTrue(all(t["status"] == "collected" for t in self.manifest().values()))

    def test_evidence_is_normalized_and_declares_its_ar(self):
        for a in ("central", "regional", "management-mc01"):
            self.account(a, ACTIVE_KEY if a == "regional" else CLEAN)
        self.run_collector()
        ev = self.evidence("regional")
        self.assertEqual((ev["assessment_requirement"], ev["target"], ev["collection"]["complete"]), (AR, "regional", True))
        svc = next(p for p in ev["principals"] if p["name"] == "svc")
        self.assertEqual([c["active"] for c in svc["credentials"]], [True, False])
        self.assertNotIn("assessment_requirement", json.loads((self.out / AR / "manifest.json").read_text()))

    def test_one_failing_account_does_not_stop_the_others_and_is_never_a_pass(self):
        self.account("central", CLEAN)
        self.account("regional", denied=True)
        self.account("management-mc01", CLEAN)
        res = self.run_collector()
        self.assertEqual(res.returncode, 0, res.stderr)
        m = self.manifest()
        self.assertEqual((m["central"]["status"], m["regional"]["status"], m["management-mc01"]["status"]),
                         ("collected", "error", "collected"))
        self.assertFalse((self.out / AR / "regional.json").exists())  # no evidence to mistake for a pass

    def test_a_report_that_never_completes_is_an_error_not_evidence(self):
        self.account("central", CLEAN)
        self.account("regional", never_ready=True)
        self.account("management-mc01", CLEAN)
        self.run_collector()
        self.assertEqual(self.manifest()["regional"]["status"], "error")
        self.assertIn("not ready", self.manifest()["regional"]["error"])
        self.assertFalse((self.out / AR / "regional.json").exists())

    def test_a_malformed_report_is_an_error_not_evidence(self):
        self.account("central", CLEAN)
        self.account("regional", report("only-a-user,arn:y,false,false,false"))  # no root row
        self.account("management-mc01", CLEAN)
        self.run_collector()
        self.assertEqual(self.manifest()["regional"]["status"], "error")
        self.assertFalse((self.out / AR / "regional.json").exists())

    def test_all_accounts_failing_fails_the_collector(self):
        for a in ("central", "regional", "management-mc01"):
            self.account(a, denied=True)
        self.assertNotEqual(self.run_collector().returncode, 0)

    def test_only_read_only_profiles_are_used_and_no_write_calls_are_made(self):
        for a in ("central", "regional", "management-mc01"):
            self.account(a, CLEAN)
        self.run_collector()
        calls = (self.fake / "calls.log").read_text().splitlines()
        self.assertTrue(calls)
        for line in calls:
            profile = line.split()[0]
            self.assertTrue(profile.startswith("rsc-") and profile.endswith("-ro"), line)
            self.assertNotIn("-admin", line)
            self.assertTrue(("generate-credential-report" in line) or ("get-credential-report" in line), line)

    def test_stale_evidence_is_cleared(self):
        for a in ("central", "regional", "management-mc01"):
            self.account(a, CLEAN)
        self.run_collector()
        self.account("regional", denied=True)
        self.run_collector()
        self.assertFalse((self.out / AR / "regional.json").exists())


class Wiring(unittest.TestCase):
    def test_collectors_reexec_inside_the_temporary_aws_config(self):
        text = (ROOT / "evidence" / f"{AR}.sh").read_text()
        self.assertIn('rsc_aws_reexec "$0"', text)
        self.assertNotIn("~/.aws", text)
        self.assertNotIn("AWS_PROFILE", text)

    def test_the_reexec_goes_through_aws_access(self):
        self.assertIn("scripts/aws_access.py", (ROOT / "evidence/lib/aws.sh").read_text())


if __name__ == "__main__":
    unittest.main()
