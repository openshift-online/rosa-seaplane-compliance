import io
import json
import sys
import unittest
import urllib.error
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import argocd_health as h  # noqa: E402

AR = "RSC.CMT.CTRL03.AR02"
NOW = datetime(2026, 11, 25, 10, 0, 0, tzinfo=timezone.utc)
END = int(NOW.timestamp())
STEP, MINUTES = 60, 30
STEPS = MINUTES * 60 // STEP + 1
START = END - MINUTES * 60
OK, DEGRADED, PROGRESSING = ("synced", "healthy"), ("synced", "degraded"), ("synced", "progressing")
OUT_OF_SYNC = ("out-of-sync", "healthy")
SUSPENDED = ("synced", "suspended")


def series(name, state, indexes, project="default"):
    """A range-query series for one application in one state at the given step indexes."""
    sync = {"synced": "Synced", "out-of-sync": "OutOfSync", "unknown": "Unknown"}[state[0]]
    health = state[1].capitalize()
    return {"metric": {"name": name, "project": project, "sync_status": sync, "health_status": health,
                       "dest_server": "https://kubernetes.example.invalid"},
            "values": [[START + i * STEP, "1"] for i in indexes]}


def whole(name, state):
    return series(name, state, range(STEPS))


def instant(name, state, project="default"):
    s = series(name, state, [0], project)
    return {"metric": s["metric"], "value": [END, "1"]}


class FakeMetrics:
    def __init__(self, age=12.0, current=None, matrix=None, fail=None):
        self.age, self.current, self.matrix, self.fail = age, current or [], matrix or [], fail
        self.queries = []

    def instant(self, promql, at):
        self.queries.append(promql)
        if self.fail:
            raise h.MetricsError(self.fail)
        if promql.startswith("time()"):
            return [] if self.age is None else [{"metric": {}, "value": [at, str(self.age)]}]
        return self.current

    def range(self, promql, start, end, step):
        self.queries.append(promql)
        if self.fail:
            raise h.MetricsError(self.fail)
        return self.matrix


def collect(metrics):
    return h.collect(metrics, AR, "example-cluster", NOW, MINUTES, 300, STEP)


def app(evidence, name):
    return next(a for a in evidence["applications"] if a["name"] == name)


class Normalization(unittest.TestCase):
    def test_sync_and_health_vocabulary(self):
        self.assertEqual([h.norm_sync(x) for x in ("Synced", "OutOfSync", "Unknown", None, "weird")],
                         ["synced", "out-of-sync", "unknown", "unknown", "unknown"])
        self.assertEqual([h.norm_health(x) for x in ("Healthy", "Progressing", "Degraded", "Missing", "Suspended", "Unknown", None, "x")],
                         ["healthy", "progressing", "degraded", "missing", "suspended", "unknown", "unknown", "unknown"])

    def test_step_classes(self):
        self.assertEqual(h.step_class({OK}), "ok")
        self.assertEqual(h.step_class({SUSPENDED}), "ok")
        self.assertEqual(h.step_class({PROGRESSING}), "progressing")
        self.assertEqual(h.step_class({DEGRADED}), "bad")
        self.assertEqual(h.step_class({OUT_OF_SYNC}), "bad")
        self.assertEqual(h.step_class({("synced", "missing")}), "bad")
        self.assertEqual(h.step_class({("unknown", "healthy")}), "bad")
        # overlapping states while a change propagates: any bad state makes the step bad
        self.assertEqual(h.step_class({OK, DEGRADED}), "bad")
        self.assertEqual(h.step_class({OK, PROGRESSING}), "progressing")


class WholeWindowJudgement(unittest.TestCase):
    def judged(self, name, per_step_states):
        per_step = {i: {s} for i, s in enumerate(per_step_states)}
        return h.judge(per_step, len(per_step_states))

    def test_healthy_the_whole_window_is_fine(self):
        self.assertEqual(self.judged("a", [OK] * STEPS)["unhealthy_for_window"], False)

    def test_bad_the_whole_window_is_unhealthy(self):
        j = self.judged("a", [DEGRADED] * STEPS)
        self.assertTrue(j["unhealthy_for_window"])
        self.assertFalse(j["stuck_progressing_for_window"])

    def test_out_of_sync_the_whole_window_is_unhealthy(self):
        self.assertTrue(self.judged("a", [OUT_OF_SYNC] * STEPS)["unhealthy_for_window"])

    def test_a_blip_that_cleared_is_tolerated(self):
        self.assertFalse(self.judged("a", [OK] * 10 + [DEGRADED] * 5 + [OK] * 16)["unhealthy_for_window"])

    def test_a_rollout_that_settled_is_tolerated(self):
        j = self.judged("a", [PROGRESSING] * 20 + [OK] * 11)
        self.assertFalse(j["unhealthy_for_window"] or j["stuck_progressing_for_window"])

    def test_a_break_that_began_inside_the_window_is_tolerated(self):
        self.assertFalse(self.judged("a", [OK] * 20 + [DEGRADED] * 11)["unhealthy_for_window"])

    def test_progressing_the_whole_window_is_stuck_not_unhealthy(self):
        j = self.judged("a", [PROGRESSING] * STEPS)
        self.assertTrue(j["stuck_progressing_for_window"])
        self.assertFalse(j["unhealthy_for_window"])

    def test_progressing_and_bad_without_ever_being_ok_is_unhealthy(self):
        j = self.judged("a", [PROGRESSING] * 15 + [DEGRADED] * 16)
        self.assertTrue(j["unhealthy_for_window"])
        self.assertFalse(j["stuck_progressing_for_window"])

    def test_suspended_counts_as_ok(self):
        j = self.judged("a", [SUSPENDED] * STEPS)
        self.assertFalse(j["unhealthy_for_window"] or j["stuck_progressing_for_window"])

    def test_an_application_seen_at_few_steps_is_not_judged(self):
        j = h.judge({i: {DEGRADED} for i in range(5)}, STEPS)
        self.assertTrue(j["partially_observed"])
        self.assertFalse(j["unhealthy_for_window"] or j["stuck_progressing_for_window"])
        self.assertLess(j["observed_fraction"], h.OBSERVED_MIN)

    def test_the_observation_threshold_is_ninety_percent(self):
        just_enough = h.judge({i: {DEGRADED} for i in range(28)}, 31)      # 28/31 = 90.3%
        too_few = h.judge({i: {DEGRADED} for i in range(27)}, 31)          # 27/31 = 87.1%
        self.assertTrue(just_enough["unhealthy_for_window"])
        self.assertTrue(too_few["partially_observed"] and not too_few["unhealthy_for_window"])

    def test_nothing_observed_is_not_judged(self):
        j = h.judge({}, STEPS)
        self.assertTrue(j["partially_observed"])
        self.assertFalse(j["unhealthy_for_window"])


class RangeParsing(unittest.TestCase):
    def test_state_changes_split_one_application_across_series(self):
        result = [series("a", DEGRADED, range(0, 10)), series("a", OK, range(10, STEPS))]
        t = h.timeline(result, START, STEP, STEPS)
        self.assertEqual(set(t), {("a", "default")})
        self.assertEqual(len(t[("a", "default")]), STEPS)
        self.assertEqual(t[("a", "default")][3], {DEGRADED})
        self.assertEqual(t[("a", "default")][20], {OK})

    def test_overlapping_series_at_a_step_keep_both_states(self):
        result = [series("a", OK, range(0, 12)), series("a", DEGRADED, range(10, STEPS))]
        t = h.timeline(result, START, STEP, STEPS)[("a", "default")]
        self.assertEqual(t[11], {OK, DEGRADED})

    def test_samples_outside_the_window_and_series_without_a_name_are_ignored(self):
        result = [{"metric": {"sync_status": "Synced"}, "values": [[START, "1"]]},
                  {"metric": series("a", OK, [0])["metric"], "values": [[START - 600, "1"], [END + 600, "1"], [START, "1"]]}]
        t = h.timeline(result, START, STEP, STEPS)
        self.assertEqual(list(t), [("a", "default")])
        self.assertEqual(list(t[("a", "default")]), [0])

    def test_same_name_in_two_projects_are_two_applications(self):
        t = h.timeline([series("a", OK, [0], "p1"), series("a", DEGRADED, [0], "p2")], START, STEP, STEPS)
        self.assertEqual(set(t), {("a", "p1"), ("a", "p2")})

    def test_age_parsing(self):
        self.assertEqual(h.parse_age([{"metric": {}, "value": [1, "12.5"]}]), 12.5)
        self.assertIsNone(h.parse_age([]))
        self.assertIsNone(h.parse_age([{"metric": {}, "value": [1, "NaN"]}]))
        self.assertIsNone(h.parse_age([{"metric": {}}]))


class Evidence(unittest.TestCase):
    def healthy_matrix(self):
        return [whole("a", OK), whole("b", OK)]

    def test_a_clean_window_is_complete_and_flags_nothing(self):
        e = collect(FakeMetrics(current=[instant("a", OK), instant("b", OK)], matrix=self.healthy_matrix()))
        self.assertTrue(e["collection"]["complete"])
        self.assertEqual(e["collection"]["problems"], [])
        self.assertTrue(all(not a["unhealthy_for_window"] and not a["stuck_progressing_for_window"] for a in e["applications"]))
        self.assertEqual((e["target"], e["target_type"], e["assessment_requirement"]), ("example-cluster", "deployment-cluster", AR))
        self.assertEqual((e["collection"]["window_minutes"], e["collection"]["steps"]), (MINUTES, STEPS))

    def test_whole_window_flags_land_on_the_right_application(self):
        matrix = [whole("a", OK), whole("broken", DEGRADED), whole("drifted", OUT_OF_SYNC), whole("slow", PROGRESSING),
                  series("blip", DEGRADED, range(0, 5)), series("blip", OK, range(5, STEPS))]
        current = [instant("a", OK), instant("broken", DEGRADED), instant("drifted", OUT_OF_SYNC), instant("slow", PROGRESSING),
                   instant("blip", OK)]
        e = collect(FakeMetrics(current=current, matrix=matrix))
        self.assertTrue(e["collection"]["complete"])
        self.assertTrue(app(e, "broken")["unhealthy_for_window"])
        self.assertTrue(app(e, "drifted")["unhealthy_for_window"])
        self.assertTrue(app(e, "slow")["stuck_progressing_for_window"])
        self.assertFalse(app(e, "blip")["unhealthy_for_window"])
        self.assertFalse(app(e, "a")["unhealthy_for_window"])
        self.assertEqual((app(e, "broken")["sync_state"], app(e, "broken")["health_state"]), ("synced", "degraded"))

    def test_stale_metrics_are_incomplete_never_a_pass(self):
        e = collect(FakeMetrics(age=900.0, current=[instant("a", OK)], matrix=[whole("a", OK)]))
        self.assertFalse(e["collection"]["complete"])
        self.assertTrue(any("900 seconds old" in p for p in e["collection"]["problems"]))

    def test_metrics_just_inside_the_freshness_limit_are_trusted(self):
        e = collect(FakeMetrics(age=299.0, current=[instant("a", OK)], matrix=[whole("a", OK)]))
        self.assertTrue(e["collection"]["complete"])

    def test_no_samples_at_all_is_incomplete(self):
        e = collect(FakeMetrics(age=None, current=[], matrix=[]))
        self.assertFalse(e["collection"]["complete"])
        self.assertTrue(e["collection"]["problems"])

    def test_a_cluster_that_reports_no_applications_is_incomplete(self):
        e = collect(FakeMetrics(age=5.0, current=[], matrix=[]))
        self.assertFalse(e["collection"]["complete"])
        self.assertTrue(any("no applications" in p for p in e["collection"]["problems"]))
        self.assertEqual(e["applications"], [])

    def test_a_failing_query_is_incomplete_and_names_the_failure_without_a_url(self):
        e = collect(FakeMetrics(fail="the metrics API answered HTTP 403"))
        self.assertFalse(e["collection"]["complete"])
        self.assertEqual(e["collection"]["problems"], ["could not read the metrics: the metrics API answered HTTP 403"])
        self.assertNotIn("http", json.dumps(e["collection"]["problems"]).replace("HTTP", ""))

    def test_gaps_in_the_window_make_the_collection_incomplete(self):
        matrix = [series("a", OK, range(0, 15))]  # only the first half of the window has samples
        e = collect(FakeMetrics(current=[instant("a", OK)], matrix=matrix))
        self.assertFalse(e["collection"]["complete"])
        self.assertTrue(any("gaps" in p for p in e["collection"]["problems"]))
        self.assertTrue(app(e, "a")["partially_observed"])

    def test_a_new_application_is_recorded_as_partially_observed_not_judged(self):
        matrix = [whole("a", OK), series("new", DEGRADED, range(25, STEPS))]
        e = collect(FakeMetrics(current=[instant("a", OK), instant("new", DEGRADED)], matrix=matrix))
        self.assertTrue(e["collection"]["complete"])
        self.assertTrue(app(e, "new")["partially_observed"])
        self.assertFalse(app(e, "new")["unhealthy_for_window"])

    def test_an_application_that_disappeared_in_the_window_is_counted_not_judged(self):
        matrix = [whole("a", OK), series("gone", DEGRADED, range(0, 10))]
        e = collect(FakeMetrics(current=[instant("a", OK)], matrix=matrix))
        self.assertEqual(e["collection"]["applications_gone_in_window"], 1)
        self.assertEqual([a["name"] for a in e["applications"]], ["a"])

    def test_the_worst_current_state_is_shown_when_states_overlap(self):
        e = collect(FakeMetrics(current=[instant("a", OK), instant("a", DEGRADED)], matrix=[whole("a", OK)]))
        self.assertEqual(app(e, "a")["health_state"], "degraded")

    def test_queries_are_scoped_to_the_cluster(self):
        m = FakeMetrics(current=[instant("a", OK)], matrix=[whole("a", OK)])
        collect(m)
        self.assertTrue(all('cluster="example-cluster"' in q for q in m.queries))

    def test_a_cluster_name_cannot_inject_promql(self):
        for bad in ('x"} or vector(1) #', "a b", "", "a" * 64):
            with self.assertRaises(h.CollectionError):
                h.collect(FakeMetrics(), AR, bad, NOW, MINUTES, 300, STEP)

    def test_evidence_never_carries_ids_urls_arns_or_the_tools_cluster_url(self):
        e = collect(FakeMetrics(current=[instant("a", OK)], matrix=[whole("a", OK)]))
        text = json.dumps(e)
        for needle in ("http", "arn:", "execute-api", "kubernetes.example.invalid", "dest_server"):
            self.assertNotIn(needle, text)
        self.assertNotRegex(text, r"(?<![0-9])[0-9]{12}(?![0-9])")

    def test_the_limits_are_recorded(self):
        e = collect(FakeMetrics(current=[instant("a", OK)], matrix=[whole("a", OK)]))
        self.assertEqual(e["collection"]["limitations"], h.LIMITATIONS)


class Response:
    def __init__(self, status=200, body=b""):
        self.status, self._body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


CREDS = {"AccessKeyId": "AKIDEXAMPLE", "SecretAccessKey": "secret", "SessionToken": "token"}


class Client(unittest.TestCase):
    def metrics(self, urlopen):
        return h.Metrics("https://gw.example.invalid/prod", CREDS, "us-east-1", urlopen=urlopen)

    def test_a_query_is_a_signed_get_with_the_encoded_promql(self):
        seen = {}

        def urlopen(request, timeout):
            seen.update(url=request.full_url, method=request.get_method(), headers=dict(request.header_items()))
            return Response(200, json.dumps({"status": "success", "data": {"result": [{"metric": {}, "value": [1, "2"]}]}}).encode())

        result = self.metrics(urlopen).instant('sum by (a, b) (up{x="y"})', 100)
        self.assertEqual(result, [{"metric": {}, "value": [1, "2"]}])
        self.assertEqual(seen["method"], "GET")
        self.assertIn("/prod/api/v1/query?", seen["url"])
        self.assertIn("query=sum%20by%20%28a%2C%20b%29%20%28up%7Bx%3D%22y%22%7D%29", seen["url"])
        self.assertIn("AWS4-HMAC-SHA256", seen["headers"]["Authorization"])
        self.assertEqual(seen["headers"]["X-amz-security-token"], "token")

    def test_range_queries_use_the_range_endpoint(self):
        seen = {}

        def urlopen(request, timeout):
            seen["url"] = request.full_url
            return Response(200, b'{"status":"success","data":{"result":[]}}')

        self.metrics(urlopen).range("up", 10, 100, 60)
        self.assertIn("/api/v1/query_range?", seen["url"])
        self.assertIn("step=60", seen["url"])

    def failing(self, urlopen):
        with self.assertRaises(h.MetricsError) as cm:
            self.metrics(urlopen).instant("up", 1)
        message = str(cm.exception)
        self.assertNotIn("gw.example.invalid", message)  # never a URL in a message
        return message

    def test_http_errors_become_metrics_errors(self):
        def urlopen(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)

        self.assertEqual(self.failing(urlopen), "the metrics API answered HTTP 403")

    def test_unreachable_api(self):
        def urlopen(request, timeout):
            raise urllib.error.URLError("no route")

        self.assertIn("could not be reached", self.failing(urlopen))

    def test_timeouts(self):
        def urlopen(request, timeout):
            raise TimeoutError()

        self.assertIn("could not be reached", self.failing(urlopen))

    def test_non_json_and_query_errors(self):
        self.assertIn("not JSON", self.failing(lambda r, timeout: Response(200, b"<html>")))
        self.assertIn("query failed", self.failing(lambda r, timeout: Response(200, b'{"status":"error","errorType":"bad_data"}')))

    def test_a_non_200_status_is_an_error(self):
        self.assertEqual(self.failing(lambda r, timeout: Response(204, b"")), "the metrics API answered HTTP 204")


class FakeAws:
    """Answers the discovery calls and records every call: reads and the credential export only."""

    def __init__(self, apis=None, stages=None, creds=None, pages=None):
        self.apis, self.stages, self.creds, self.pages = apis, stages, creds, pages
        self.calls = []

    def call(self, *args, region=None):
        self.calls.append(args)
        if args[:2] == ("apigateway", "get-rest-apis"):
            if self.pages:
                position = args[args.index("--position") + 1] if "--position" in args else None
                return self.pages[position]
            return {"items": self.apis or []}
        if args[:2] == ("apigateway", "get-stages"):
            return {"item": [{"stageName": s} for s in (self.stages if self.stages is not None else ["prod"])]}
        if args[:2] == ("configure", "export-credentials"):
            if self.creds is None:
                raise h.AwsError("no credentials")
            return self.creds
        raise AssertionError(f"unexpected aws call {args}")


class Discovery(unittest.TestCase):
    def test_the_gateway_is_found_by_name_and_its_stage(self):
        aws = FakeAws(apis=[{"id": "abc123", "name": "regional-api"}, {"id": "xyz789", "name": "regional-rhobs"}])
        self.assertEqual(h.discover_base_url(aws, "us-east-1"), "https://xyz789.execute-api.us-east-1.amazonaws.com/prod")

    def test_pagination(self):
        aws = FakeAws(pages={None: {"items": [{"id": "a1", "name": "x"}], "position": "p2"},
                             "p2": {"items": [{"id": "b2", "name": "Regional-RHOBS"}]}})
        self.assertIn("b2.execute-api", h.discover_base_url(aws, "us-east-1"))

    def test_no_gateway_and_two_gateways_are_errors_not_guesses(self):
        with self.assertRaises(h.CollectionError):
            h.discover_base_url(FakeAws(apis=[{"id": "a", "name": "other"}]), "us-east-1")
        with self.assertRaises(h.CollectionError):
            h.discover_base_url(FakeAws(apis=[{"id": "a", "name": "rhobs-1"}, {"id": "b", "name": "rhobs-2"}]), "us-east-1")

    def test_stage_selection(self):
        apis = [{"id": "abc", "name": "rhobs"}]
        self.assertTrue(h.discover_base_url(FakeAws(apis=apis, stages=["dev", "prod"]), "us-east-1").endswith("/prod"))
        self.assertTrue(h.discover_base_url(FakeAws(apis=apis, stages=["live"]), "us-east-1").endswith("/live"))
        with self.assertRaises(h.CollectionError):
            h.discover_base_url(FakeAws(apis=apis, stages=["a", "b"]), "us-east-1")
        with self.assertRaises(h.CollectionError):
            h.discover_base_url(FakeAws(apis=apis, stages=[]), "us-east-1")

    def test_an_aws_failure_during_discovery_is_a_collection_error(self):
        class Denied(FakeAws):
            def call(self, *args, region=None):
                raise h.AwsError("access denied")

        with self.assertRaises(h.CollectionError):
            h.discover_base_url(Denied(), "us-east-1")

    def test_credentials(self):
        self.assertEqual(h.read_credentials(FakeAws(creds=CREDS)), CREDS)
        with self.assertRaises(h.CollectionError):
            h.read_credentials(FakeAws(creds=None))
        with self.assertRaises(h.CollectionError):
            h.read_credentials(FakeAws(creds={"AccessKeyId": "x"}))


class Main(unittest.TestCase):
    def run_main(self, argv, aws=None, metrics=None):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["argocd_health.py", *argv]), \
                mock.patch.object(h, "Aws", return_value=aws or FakeAws(apis=[{"id": "abc123", "name": "regional-rhobs"}], creds=CREDS)), \
                mock.patch.object(h, "Metrics", return_value=metrics or FakeMetrics(current=[instant("a", OK)], matrix=[whole("a", OK)])), \
                redirect_stdout(out):
            h.main()
        return json.loads(out.getvalue())

    BASE = ["--ar", AR, "--target", "example-cluster", "--profile", "rsc-regional-ro", "--region", "us-east-1"]

    def test_prints_evidence_and_makes_only_read_calls(self):
        aws = FakeAws(apis=[{"id": "abc123", "name": "regional-rhobs"}], creds=CREDS)
        evidence = self.run_main(self.BASE, aws=aws)
        self.assertEqual(evidence["target"], "example-cluster")
        for call in aws.calls:
            self.assertTrue(call[0] == "apigateway" and call[1].startswith("get-") or call[:2] == ("configure", "export-credentials"), call)
        self.assertNotIn("abc123", json.dumps(evidence))

    def test_only_read_only_profiles_are_accepted(self):
        for profile in ("rsc-regional-admin", "rsc-admin", "default", "rsc-regional-ro; rm", "personal"):
            with self.assertRaises(SystemExit) as cm:
                self.run_main(["--ar", AR, "--target", "example-cluster", "--profile", profile, "--region", "us-east-1"])
            self.assertIn("read-only", str(cm.exception))

    def test_discovery_failure_is_an_error_and_prints_no_evidence(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_main(self.BASE, aws=FakeAws(apis=[]))
        self.assertIn("ERROR", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
