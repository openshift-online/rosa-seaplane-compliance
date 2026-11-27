import json
import os
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AR = "RSC.CMT.CTRL03.AR01"
PIPELINES = ("regional-pipeline", "mc01-pipeline")
HEAD = "a" * 40  # fake commit ids, built at run time like every fake identifier

# A stand-in for the aws CLI: what the read-only profile returns is a JSON file; every call is logged.
FAKE_AWS = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
profile = a[a.index("--profile") + 1]
rest = a[a.index("json") + 1:] if "json" in a else []
fake = os.environ["FAKE_AWS_DIR"]
open(os.path.join(fake, "aws-calls.log"), "a").write(profile + " " + " ".join(rest) + "\n")
cfg = json.load(open(os.path.join(fake, profile + ".json")))
line = " ".join(rest)
if any(d in line for d in cfg.get("deny", [])):
    sys.stderr.write("An error occurred (AccessDeniedException) when calling the operation: nope\n"); sys.exit(254)
if rest[:2] == ["codepipeline", "list-pipeline-executions"]:
    name = rest[rest.index("--pipeline-name") + 1]
    print(json.dumps({"pipelineExecutionSummaries": cfg["executions"].get(name, [])}))
elif rest[:2] == ["codepipeline", "list-action-executions"]:
    eid = rest[rest.index("--filter") + 1].split("=", 1)[1]
    rec = cfg.get("outputs", {}).get(eid)
    variables = {} if rec is None else {"APPLIED": str(rec[0]).lower(), "APPLIED_SHA": rec[1]}
    print(json.dumps({"actionExecutionDetails": [{"actionName": "Apply", "output": {"outputVariables": variables}}]}))
else:
    sys.stderr.write("unexpected aws call: " + line + "\n"); sys.exit(2)
'''

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, re, sys
a = sys.argv[2:]   # after: gh api
fake = os.environ["FAKE_GH_DIR"]
open(os.path.join(fake, "gh-calls.log"), "a").write(" ".join(a)[:200] + "\n")
cfg = json.load(open(os.path.join(fake, "gh.json")))
if a[0] == "graphql":
    print(json.dumps({"data": {"repository": {"pullRequests": {"pageInfo": {"hasNextPage": False, "endCursor": ""}, "nodes": cfg["prs"]}}}}))
elif re.fullmatch(r"repos/[^/]+/[^/]+/commits/\S+", a[0]):
    print(json.dumps({"sha": cfg["head"]["sha"], "commit": {"message": "secret", "committer": {"date": cfg["head"]["date"], "email": "x@example.com"}}}))
elif "/compare/" in a[0]:
    print(json.dumps({"status": cfg.get("compare", {}).get(a[0].split("/compare/")[1], "diverged")}))
elif re.fullmatch(r"repos/[^/]+/[^/]+", a[0]):
    print(json.dumps({"b": cfg.get("default_branch", "main")}))
else:
    sys.stderr.write("unexpected gh call: " + " ".join(a) + "\n"); sys.exit(2)
'''


# The day collected: three days ago (a backfill, so no settle delay applies), found at run time so the
# 90-day limit never expires the test data.
TODAY = datetime.now(timezone.utc).date()
DAY_DATE = (TODAY - timedelta(days=3)).isoformat()


def stamp(clock, day=DAY_DATE):
    return f"{day}T{clock}+00:00"


def run_summary(eid, status, clock, commit):
    return {"pipelineExecutionId": eid, "status": status, "startTime": stamp(clock), "lastUpdateTime": stamp(clock),
            "trigger": {"triggerType": "WebhookV2"}, "sourceRevisions": [{"revisionId": commit}]}


GOOD_ACCOUNT = {"executions": {p: [run_summary("e-" + p, "Succeeded", "10:01:00", HEAD)] for p in PIPELINES},
                "outputs": {"e-" + p: [True, HEAD] for p in PIPELINES}}
GOOD_GH = {"prs": [{"mergedAt": stamp("10:00:00"), "updatedAt": stamp("10:00:00"), "mergeCommit": {"oid": HEAD}}],
           "head": {"sha": HEAD, "date": stamp("10:00:00")}}


class DeploymentCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        for name, text in (("aws", FAKE_AWS), ("gh", FAKE_GH)):
            f = t / "bin" / name
            f.write_text(text)
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        self.fake, self.out = t / "fake", t / "out"
        self.fake.mkdir()
        self.account(GOOD_ACCOUNT)
        self.gh(GOOD_GH)

    def account(self, cfg, profile="rsc-central-ro"):
        (self.fake / f"{profile}.json").write_text(json.dumps(cfg))

    def gh(self, cfg):
        (self.fake / "gh.json").write_text(json.dumps(cfg))

    def run_collector(self, token="x", **extra):
        extra = {"RSC_DATE": DAY_DATE, **extra}
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", FAKE_AWS_DIR=str(self.fake),
                   FAKE_GH_DIR=str(self.fake), RSC_AWS_READY="1", RSC_ENV="integration", RSC_EVIDENCE_DIR=str(self.out),
                   RSC_LOOKUP_INTERVAL="0", RSC_PIPELINE_INTERVAL="0", RSC_LOOKUP_BACKOFF="0", **extra)
        env.pop("GITHUB_TOKEN", None)
        if token:
            env["GITHUB_TOKEN"] = token
        return subprocess.run([str(ROOT / "evidence" / f"{AR}.sh")], env=env, capture_output=True, text=True)

    def manifest(self):
        return {t["name"]: t for t in json.loads((self.out / AR / "manifest.json").read_text())["targets"]}

    def evidence(self, name):
        return json.loads((self.out / AR / f"{name}.json").read_text())

    def test_one_evidence_file_per_pipeline_of_the_environment_and_a_manifest(self):
        res = self.run_collector()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(sorted(self.manifest()), sorted(PIPELINES))
        ev = self.evidence("regional-pipeline")
        self.assertEqual((ev["assessment_requirement"], ev["target"], ev["target_type"]), (AR, "regional-pipeline", "deployment-pipeline"))
        self.assertTrue(ev["collection"]["complete"])
        self.assertEqual(ev["collection"]["allowed_lag_minutes"], 120)    # from config/environments/integration.yaml
        self.assertEqual(ev["repository"], "openshift-online/rosa-seaplane")
        self.assertTrue(ev["head"]["deployed"])
        self.assertNotIn("assessment_requirement", json.loads((self.out / AR / "manifest.json").read_text()))

    def test_a_failing_pipeline_does_not_stop_the_other_and_has_no_evidence(self):
        self.account(dict(GOOD_ACCOUNT, deny=["--pipeline-name mc01-pipeline"]))
        res = self.run_collector()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.manifest()["mc01-pipeline"]["status"], "error")
        self.assertEqual(self.manifest()["regional-pipeline"]["status"], "collected")
        self.assertFalse((self.out / AR / "mc01-pipeline.json").exists())

    def test_every_pipeline_failing_fails_the_collector(self):
        self.account(dict(GOOD_ACCOUNT, deny=["list-pipeline-executions"]))
        self.assertNotEqual(self.run_collector().returncode, 0)

    def test_an_undeployed_head_is_recorded_for_the_policy_to_judge(self):
        broken = dict(GOOD_ACCOUNT, executions={p: [run_summary("f-" + p, "Failed", "10:01:00", HEAD)] for p in PIPELINES},
                      outputs={})
        self.account(broken)
        self.run_collector()
        ev = self.evidence("regional-pipeline")
        self.assertFalse(ev["head"]["deployed"])
        self.assertEqual(ev["latest_execution"]["status"], "failed")

    def test_only_the_read_only_profile_and_read_verbs_are_used(self):
        self.run_collector()
        for line in (self.fake / "aws-calls.log").read_text().splitlines():
            self.assertTrue(line.startswith("rsc-central-ro "), line)
            self.assertTrue(line.split()[1:3] in (["codepipeline", "list-pipeline-executions"], ["codepipeline", "list-action-executions"]), line)
        for line in (self.fake / "gh-calls.log").read_text().splitlines():
            self.assertNotIn(" -X", line)

    def test_a_github_token_is_required_before_anything_is_called(self):
        res = self.run_collector(token="")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("GITHUB_TOKEN", res.stderr)
        self.assertFalse((self.fake / "aws-calls.log").exists())

    def test_the_default_branch_is_looked_up_when_the_environment_names_none(self):
        self.run_collector()
        self.assertTrue(any(l.startswith("repos/openshift-online/rosa-seaplane --jq") for l in (self.fake / "gh-calls.log").read_text().splitlines()))
        self.assertEqual(self.evidence("regional-pipeline")["branch"], "main")

    def test_the_day_is_recorded_in_the_evidence_and_the_manifest(self):
        self.run_collector()
        ev = self.evidence("regional-pipeline")
        self.assertEqual((ev["covers_date"], ev["window"]), (DAY_DATE, {"start": f"{DAY_DATE}T00:00:00Z",
                                                                       "end": f"{(TODAY - timedelta(days=2)).isoformat()}T00:00:00Z"}))
        self.assertEqual([c["merged_at"] for c in ev["merged_commits"]], [f"{DAY_DATE}T10:00:00Z"])
        self.assertEqual(json.loads((self.out / AR / "manifest.json").read_text())["covers_date"], DAY_DATE)

    def test_a_merge_on_another_day_is_not_in_this_days_evidence(self):
        other = (TODAY - timedelta(days=4)).isoformat()
        self.gh(dict(GOOD_GH, prs=[{"mergedAt": stamp("23:59:59", other), "updatedAt": stamp("23:59:59", other), "mergeCommit": {"oid": HEAD}}]))
        self.run_collector()
        self.assertEqual(self.evidence("regional-pipeline")["merged_commits"], [])

    def test_the_default_day_is_yesterday(self):
        res = self.run_collector(RSC_DATE="", RSC_ALLOW_EARLY="1")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.evidence("regional-pipeline")["covers_date"], (TODAY - timedelta(days=1)).isoformat())

    def test_a_day_that_is_not_collectable_fails_before_anything_is_called(self):
        for bad in (TODAY.isoformat(), (TODAY + timedelta(days=1)).isoformat(), "2026-13-45", "yesterday",
                    (TODAY - timedelta(days=91)).isoformat()):
            res = self.run_collector(RSC_DATE=bad)
            self.assertNotEqual(res.returncode, 0, bad)
            self.assertIn("ERROR", res.stderr)
        self.assertFalse((self.fake / "aws-calls.log").exists())

    def test_an_early_run_is_refused_unless_allowed(self):
        yesterday = (TODAY - timedelta(days=1)).isoformat()
        res = self.run_collector(RSC_DATE=yesterday, RSC_SETTLE_MINUTES="100000")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("RSC_ALLOW_EARLY", res.stderr)
        self.assertEqual(self.run_collector(RSC_DATE=yesterday, RSC_SETTLE_MINUTES="100000", RSC_ALLOW_EARLY="1").returncode, 0)

    def test_nothing_sensitive_reaches_the_evidence_files(self):
        self.run_collector()
        text = (self.out / AR / "regional-pipeline.json").read_text()
        for needle in ("secret", "x@example.com", "arn:aws"):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
