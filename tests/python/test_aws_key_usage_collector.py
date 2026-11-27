import json
import os
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AR = "RSC.IAM.CTRL01.AR02"
ACCOUNTS = ("central", "regional", "management-mc01")
KEY = "AKIA" + "Q" * 12 + "QQQ9"  # built at run time like every fake identifier
# The day collected: three days ago (a backfill, so no settle delay applies), found at run time so the
# 90-day limit never expires the test data.
TODAY = datetime.now(timezone.utc).date()
DAY_DATE = (TODAY - timedelta(days=3)).isoformat()

# A stand-in for the aws CLI. What each read-only profile returns is a JSON file; every call is logged.
FAKE_AWS = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
profile = a[a.index("--profile") + 1]
rest = a[a.index("json") + 1:] if "json" in a else []
fake = os.environ["FAKE_AWS_DIR"]
open(os.path.join(fake, "calls.log"), "a").write(profile + " " + " ".join(rest) + "\n")
cfg = json.load(open(os.path.join(fake, profile + ".json")))
line = " ".join(rest)
if any(d in line for d in cfg.get("deny", [])):
    sys.stderr.write("An error occurred (AccessDenied) when calling the operation: nope\n"); sys.exit(254)
if rest[:2] == ["iam", "list-users"]:
    print(json.dumps({"Users": [{"UserName": u} for u in cfg.get("users", [])]}))
elif rest[:2] == ["iam", "list-access-keys"]:
    user = rest[rest.index("--user-name") + 1]
    print(json.dumps({"AccessKeyMetadata": [{"AccessKeyId": k, "Status": s} for k, s in cfg.get("keys", {}).get(user, [])]}))
elif rest[:2] == ["iam", "get-access-key-last-used"]:
    print(json.dumps({"AccessKeyLastUsed": cfg.get("last_used", {}).get(rest[rest.index("--access-key-id") + 1], {})}))
elif rest[:2] == ["iam", "get-account-summary"]:
    print(json.dumps({"SummaryMap": {"AccountAccessKeysPresent": cfg.get("root_keys", 0)}}))
elif rest[:2] == ["cloudtrail", "lookup-events"]:
    value = rest[rest.index("--lookup-attributes") + 1].split("AttributeValue=")[1]
    print(json.dumps({"Events": cfg.get("events", {}).get(value, [])}))
else:
    sys.stderr.write("unexpected aws call: " + line + "\n"); sys.exit(2)
'''


def trail_event(user="svc"):
    detail = {"userIdentity": {"type": "IAMUser", "userName": user, "accessKeyId": KEY},
              "sourceIPAddress": "203.0.113.9", "userAgent": "agent/1.0"}
    return {"EventTime": f"{DAY_DATE}T10:00:00+00:00", "EventName": "AssumeRole", "EventSource": "sts.amazonaws.com",
            "Username": user, "AccessKeyId": KEY, "CloudTrailEvent": json.dumps(detail)}


QUIET = {"users": ["svc"], "keys": {"svc": [[KEY, "Inactive"]]}, "events": {}}
BUSY = {"users": ["svc"], "keys": {"svc": [[KEY, "Active"]]}, "events": {KEY: [trail_event()]},
        "last_used": {KEY: {"LastUsedDate": f"{DAY_DATE}T10:00:00+00:00", "Region": "us-east-1"}}}


class KeyUsageCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        aws = t / "bin" / "aws"
        aws.write_text(FAKE_AWS)
        aws.chmod(aws.stat().st_mode | stat.S_IEXEC)
        self.fake, self.out = t / "fake", t / "out"
        self.fake.mkdir()

    def account(self, name, cfg):
        (self.fake / f"rsc-{name}-ro.json").write_text(json.dumps(cfg))

    def run_collector(self, **extra):
        extra = {"RSC_DATE": DAY_DATE, **extra}
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", FAKE_AWS_DIR=str(self.fake),
                   RSC_AWS_READY="1", RSC_ENV="integration", RSC_EVIDENCE_DIR=str(self.out),
                   RSC_LOOKUP_INTERVAL="0", RSC_LOOKUP_BACKOFF="0", **extra)
        return subprocess.run([str(ROOT / "evidence" / f"{AR}.sh")], env=env, capture_output=True, text=True)

    def manifest(self):
        return {t["name"]: t for t in json.loads((self.out / AR / "manifest.json").read_text())["targets"]}

    def evidence(self, name):
        return json.loads((self.out / AR / f"{name}.json").read_text())

    def all_quiet(self):
        for a in ACCOUNTS:
            self.account(a, QUIET)

    def test_one_evidence_file_per_logical_account_and_a_manifest(self):
        self.all_quiet()
        res = self.run_collector()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(sorted(self.manifest()), sorted(ACCOUNTS))
        ev = self.evidence("regional")
        self.assertEqual((ev["assessment_requirement"], ev["target"], ev["target_type"]), (AR, "regional", "aws-account"))
        self.assertTrue(ev["collection"]["complete"])
        self.assertNotIn("assessment_requirement", json.loads((self.out / AR / "manifest.json").read_text()))

    def test_a_used_key_produces_findings_in_the_evidence(self):
        self.all_quiet()
        self.account("regional", BUSY)
        self.run_collector()
        ev = self.evidence("regional")
        self.assertEqual([e["credential_type"] for e in ev["events"]], ["long-term"])
        self.assertEqual(ev["keys"][0]["events_found"], 1)
        self.assertEqual(self.evidence("central")["events"], [])

    def test_a_failing_account_does_not_stop_the_others_and_has_no_evidence(self):
        self.all_quiet()
        self.account("regional", {"deny": ["list-users"]})
        res = self.run_collector()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.manifest()["regional"]["status"], "error")
        self.assertEqual(self.manifest()["central"]["status"], "collected")
        self.assertFalse((self.out / AR / "regional.json").exists())

    def test_a_failing_lookup_is_incomplete_evidence_not_a_pass(self):
        self.all_quiet()
        self.account("regional", dict(QUIET, deny=["lookup-events"]))
        self.run_collector()
        self.assertFalse(self.evidence("regional")["collection"]["complete"])
        self.assertEqual(self.manifest()["regional"]["status"], "collected")  # collected, and the policy denies it

    def test_all_accounts_failing_fails_the_collector(self):
        for a in ACCOUNTS:
            self.account(a, {"deny": ["list-users"]})
        self.assertNotEqual(self.run_collector().returncode, 0)

    def test_the_day_is_recorded_and_asked_of_cloudtrail(self):
        self.all_quiet()
        self.run_collector()
        ev = self.evidence("regional")
        self.assertEqual((ev["covers_date"], ev["window"]["start"]), (DAY_DATE, f"{DAY_DATE}T00:00:00Z"))
        self.assertEqual(json.loads((self.out / AR / "manifest.json").read_text())["covers_date"], DAY_DATE)
        lookup = [l for l in (self.fake / "calls.log").read_text().splitlines() if "lookup-events" in l][0]
        self.assertIn(f"--start-time {DAY_DATE}T00:00:00Z --end-time {(TODAY - timedelta(days=2)).isoformat()}T00:00:00Z", lookup)

    def test_the_default_day_is_yesterday(self):
        self.all_quiet()
        res = self.run_collector(RSC_DATE="", RSC_ALLOW_EARLY="1")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.evidence("regional")["covers_date"], (TODAY - timedelta(days=1)).isoformat())

    def test_a_day_that_is_not_collectable_fails_before_anything_is_called(self):
        self.all_quiet()
        for bad in (TODAY.isoformat(), (TODAY + timedelta(days=1)).isoformat(), "2026-13-45", "yesterday",
                    (TODAY - timedelta(days=91)).isoformat()):
            res = self.run_collector(RSC_DATE=bad)
            self.assertNotEqual(res.returncode, 0, bad)
            self.assertIn("ERROR", res.stderr)
        self.assertFalse((self.fake / "calls.log").exists())

    def test_an_early_run_is_refused_unless_allowed(self):
        self.all_quiet()
        yesterday = (TODAY - timedelta(days=1)).isoformat()
        res = self.run_collector(RSC_DATE=yesterday, RSC_SETTLE_MINUTES="100000")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RSC_ALLOW_EARLY", res.stderr)
        self.assertEqual(self.run_collector(RSC_DATE=yesterday, RSC_SETTLE_MINUTES="100000", RSC_ALLOW_EARLY="1").returncode, 0)

    def test_the_environments_regions_are_recorded(self):
        self.all_quiet()
        self.run_collector()
        self.assertIn("us-east-1", self.evidence("regional")["collection"]["regions"])

    def test_only_read_only_profiles_and_read_verbs_are_used(self):
        self.all_quiet()
        self.account("regional", BUSY)
        self.run_collector()
        lines = (self.fake / "calls.log").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            profile, service, verb = line.split()[:3]
            self.assertTrue(profile.startswith("rsc-") and profile.endswith("-ro"), line)
            self.assertNotIn("-admin", line)
            self.assertTrue(verb.startswith(("list-", "get-", "lookup-")), line)

    def test_evidence_holds_no_ips_user_agents_or_full_key_ids(self):
        self.all_quiet()
        self.account("regional", BUSY)
        self.run_collector()
        text = (self.out / AR / "regional.json").read_text()
        for secret in ("203.0.113.9", "agent/1.0", KEY):
            self.assertNotIn(secret, text)

    def test_stale_evidence_is_cleared(self):
        self.all_quiet()
        self.run_collector()
        self.account("regional", {"deny": ["list-users"]})
        self.run_collector()
        self.assertFalse((self.out / AR / "regional.json").exists())

    def test_the_collector_reexecs_inside_the_temporary_aws_config(self):
        self.assertIn('rsc_aws_reexec "$0"', (ROOT / "evidence" / f"{AR}.sh").read_text())


if __name__ == "__main__":
    unittest.main()
