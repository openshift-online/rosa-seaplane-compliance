"""The real collector script, end to end, with a fake aws CLI and canned metrics responses.

No network: a sitecustomize.py placed on PYTHONPATH replaces urllib.request.urlopen, so the
real SigV4 signing, queries, judgement and manifest all run.
"""
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AR = "RSC.CMT.CTRL03.AR02"
CLUSTERS = ("regional", "mc01")

FAKE_AWS = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
profile = a[a.index("--profile") + 1]
rest = a[a.index("json") + 1:] if "json" in a else []
fake = os.environ["FAKE_DIR"]
open(os.path.join(fake, "aws-calls.log"), "a").write(profile + " " + " ".join(rest) + "\n")
if os.path.exists(os.path.join(fake, "aws-deny")):
    sys.stderr.write("An error occurred (AccessDeniedException) when calling the operation: nope\n"); sys.exit(254)
if rest[:2] == ["apigateway", "get-rest-apis"]:
    print(json.dumps({"items": [{"id": "gw0000test", "name": "regional-api"}, {"id": "gw1111test", "name": "regional-rhobs"}]}))
elif rest[:2] == ["apigateway", "get-stages"]:
    print(json.dumps({"item": [{"stageName": "prod"}]}))
elif rest[:2] == ["configure", "export-credentials"]:
    print(json.dumps({"Version": 1, "AccessKeyId": "AKIDEXAMPLE", "SecretAccessKey": "secret", "SessionToken": "token"}))
else:
    sys.stderr.write("unexpected aws call: " + " ".join(rest) + "\n"); sys.exit(2)
'''

SITECUSTOMIZE = r'''
import importlib.util, io, json, os, sys, urllib.parse, urllib.request, urllib.error
# Some Pythons (Homebrew's) ship their own sitecustomize that sets up site-packages; this one
# shadows it on PYTHONPATH, so run the real one first.
_here = os.path.abspath(os.path.dirname(__file__))
for _p in sys.path:
    _cand = os.path.join(_p, "sitecustomize.py")
    if os.path.abspath(_p) != _here and os.path.isfile(_cand):
        _spec = importlib.util.spec_from_file_location("_real_sitecustomize", _cand)
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        break
_cfg = os.environ.get("FAKE_METRICS")
if _cfg:
    def _urlopen(request, timeout=None):
        cfg = json.load(open(_cfg))
        u = urllib.parse.urlsplit(request.full_url)
        q = urllib.parse.parse_qs(u.query)["query"][0]
        cluster = q.split('cluster="')[1].split('"')[0]
        open(os.path.join(os.path.dirname(_cfg), "http.log"), "a").write(request.get_method() + " " + u.path + " " + request.headers.get("Authorization", "")[:16] + "\n")
        c = cfg[cluster]
        if c.get("http_status", 200) != 200:
            raise urllib.error.HTTPError(request.full_url, c["http_status"], "x", {}, None)
        if u.path.endswith("/query_range"):
            result = c["matrix"]
        elif q.startswith("time()"):
            result = [] if c["age"] is None else [{"metric": {}, "value": [0, str(c["age"])]}]
        else:
            result = c["current"]
        body = json.dumps({"status": "success", "data": {"resultType": "x", "result": result}}).encode()
        class R(io.BytesIO):
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return R(body)
    urllib.request.urlopen = _urlopen
'''

HEALTH = {"Synced": "Healthy"}


def metric(name, sync, health):
    return {"name": name, "project": "default", "sync_status": sync, "health_status": health, "dest_server": "https://k.example.invalid"}


def matrix_whole(name, sync, health, now):
    end = int(now)
    return {"metric": metric(name, sync, health), "values": [[end - 1800 + i * 60, "1"] for i in range(31)]}


def good_cluster(now):
    return {"age": 10.0,
            "current": [{"metric": metric("a", "Synced", "Healthy"), "value": [now, "1"]}],
            "matrix": [matrix_whole("a", "Synced", "Healthy", now)]}


class HealthCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        aws = t / "bin" / "aws"
        aws.write_text(FAKE_AWS)
        aws.chmod(aws.stat().st_mode | stat.S_IEXEC)
        (t / "site").mkdir()
        (t / "site" / "sitecustomize.py").write_text(SITECUSTOMIZE)
        self.t, self.out = t, t / "out"
        self.now = datetime.now(timezone.utc).timestamp()

    def run_collector(self, clusters, env=None):
        (self.t / "metrics.json").write_text(json.dumps(clusters))
        e = dict(os.environ, PATH=f"{self.t / 'bin'}:{os.environ['PATH']}", FAKE_DIR=str(self.t),
                 FAKE_METRICS=str(self.t / "metrics.json"), PYTHONPATH=str(self.t / "site"),
                 RSC_AWS_READY="1", RSC_ENV="integration", RSC_EVIDENCE_DIR=str(self.out))
        e.update(env or {})
        return subprocess.run([str(ROOT / "evidence" / f"{AR}.sh")], env=e, capture_output=True, text=True)

    def evidence(self, cluster):
        return json.loads((self.out / AR / f"{cluster}.json").read_text())

    def manifest(self):
        return {t["name"]: t for t in json.loads((self.out / AR / "manifest.json").read_text())["targets"]}

    def test_a_healthy_environment_passes_through_to_complete_evidence(self):
        res = self.run_collector({c: good_cluster(self.now) for c in CLUSTERS})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual({n: t["status"] for n, t in self.manifest().items()}, {c: "collected" for c in CLUSTERS})
        for c in CLUSTERS:
            e = self.evidence(c)
            self.assertEqual((e["assessment_requirement"], e["target"]), (AR, c))
            self.assertTrue(e["collection"]["complete"])
            self.assertEqual(e["collection"]["window_minutes"], 30)

    def test_an_unhealthy_application_is_flagged_for_its_cluster_only(self):
        broken = good_cluster(self.now)
        broken["current"].append({"metric": metric("broken", "Synced", "Degraded"), "value": [self.now, "1"]})
        broken["matrix"].append(matrix_whole("broken", "Synced", "Degraded", self.now))
        self.run_collector({"regional": broken, "mc01": good_cluster(self.now)})
        flagged = {a["name"] for a in self.evidence("regional")["applications"] if a["unhealthy_for_window"]}
        self.assertEqual(flagged, {"broken"})
        self.assertFalse(any(a["unhealthy_for_window"] for a in self.evidence("mc01")["applications"]))

    def test_stale_metrics_are_collected_but_incomplete(self):
        stale = good_cluster(self.now)
        stale["age"] = 3600.0
        res = self.run_collector({"regional": stale, "mc01": good_cluster(self.now)})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(self.evidence("regional")["collection"]["complete"])
        self.assertTrue(self.evidence("mc01")["collection"]["complete"])

    def test_an_api_error_is_incomplete_evidence_not_a_missing_target(self):
        broken = good_cluster(self.now)
        broken["http_status"] = 403
        self.run_collector({"regional": broken, "mc01": good_cluster(self.now)})
        e = self.evidence("regional")
        self.assertFalse(e["collection"]["complete"])
        self.assertIn("HTTP 403", " ".join(e["collection"]["problems"]))

    def test_an_expected_cluster_that_reports_nothing_is_incomplete(self):
        empty = {"age": None, "current": [], "matrix": []}
        self.run_collector({"regional": empty, "mc01": good_cluster(self.now)})
        self.assertFalse(self.evidence("regional")["collection"]["complete"])

    def test_failing_to_find_the_gateway_is_an_error_with_no_evidence(self):
        (self.t / "aws-deny").write_text("")
        res = self.run_collector({c: good_cluster(self.now) for c in CLUSTERS})
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual({t["status"] for t in self.manifest().values()}, {"error"})
        self.assertEqual([p.name for p in (self.out / AR).glob("*.json")], ["manifest.json"])

    def test_only_the_regional_read_only_profile_is_used_and_only_reads_are_made(self):
        self.run_collector({c: good_cluster(self.now) for c in CLUSTERS})
        calls = (self.t / "aws-calls.log").read_text().splitlines()
        self.assertTrue(calls)
        for line in calls:
            profile, *rest = line.split(" ")
            self.assertEqual(profile, "rsc-regional-ro")
            self.assertTrue(rest[0] == "apigateway" and rest[1].startswith("get-") or rest[:2] == ["configure", "export-credentials"], line)

    def test_every_request_is_a_signed_get(self):
        self.run_collector({c: good_cluster(self.now) for c in CLUSTERS})
        lines = (self.t / "http.log").read_text().splitlines()
        self.assertTrue(lines)
        self.assertTrue(all(l.startswith("GET /prod/api/v1/query") and "AWS4-HMAC-SHA256" in l for l in lines), lines)

    def test_evidence_and_manifest_never_contain_ids_urls_or_the_gateway_id(self):
        self.run_collector({c: good_cluster(self.now) for c in CLUSTERS})
        text = "".join(p.read_text() for p in (self.out / AR).glob("*.json"))
        self.assertNotIn("gw1111test", text)
        self.assertNotIn("example.invalid", text)
        self.assertIsNone(re.search(r"https?://|arn:aws|(?<![0-9])[0-9]{12}(?![0-9])", text))

    def test_an_environment_that_cannot_be_resolved_fails_clearly_and_collects_nothing(self):
        res = self.run_collector({c: good_cluster(self.now) for c in CLUSTERS}, env={"RSC_ENV": "nonexistent"})
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse((self.t / "aws-calls.log").exists())


if __name__ == "__main__":
    unittest.main()
