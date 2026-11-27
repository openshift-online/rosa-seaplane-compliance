import json
import re
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import deployment_pipeline as d  # noqa: E402
from aws_cli import Aws, AwsError  # noqa: E402

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
AR = "RSC.CMT.CTRL03.AR01"
REPO = "example-org/platform"


def sha(n: int) -> str:
    return f"{n:040x}"


def at(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def summary(eid, status, hours_ago, commit, trigger="WebhookV2"):
    return {"pipelineExecutionId": eid, "status": status, "startTime": at(hours_ago),
            "lastUpdateTime": at(hours_ago - 0.1), "trigger": {"triggerType": trigger},
            "sourceRevisions": [{"revisionId": commit, "actionName": "Source"}]}


class FakeAws:
    """Replaces subprocess.run for the aws CLI: serves execution pages and applied records."""

    def __init__(self, pages=None, outputs=None, fail=()):
        self.pages = pages or [[]]
        self.outputs = outputs or {}    # execution id -> (APPLIED, APPLIED_SHA) or None for no record
        self.fail, self.calls = set(fail), []

    def run(self, cmd, capture_output=True, text=True):
        self.calls.append(cmd)
        a = cmd[5:]
        line = " ".join(a)
        if any(f in line for f in self.fail):
            return subprocess.CompletedProcess(cmd, 254, "", "An error occurred (AccessDeniedException): not allowed")
        if a[:2] == ["codepipeline", "list-pipeline-executions"]:
            token = a[a.index("--next-token") + 1] if "--next-token" in a else None
            i = int(token) if token else 0
            body = {"pipelineExecutionSummaries": self.pages[i]}
            if i + 1 < len(self.pages):
                body["nextToken"] = str(i + 1)
            return self.ok(body)
        if a[:2] == ["codepipeline", "list-action-executions"]:
            eid = a[a.index("--filter") + 1].split("=", 1)[1]
            rec = self.outputs.get(eid)
            variables = {} if rec is None else {"APPLIED": str(rec[0]).lower(), "APPLIED_SHA": rec[1]}
            return self.ok({"actionExecutionDetails": [
                {"actionName": "Source", "output": {"outputVariables": {"CommitId": "x", "CommitMessage": "secret message"}}},
                {"actionName": "Apply", "output": {"outputVariables": variables}}]})
        raise AssertionError(f"unexpected aws call: {line}")

    def ok(self, body):
        return subprocess.CompletedProcess([], 0, json.dumps(body), "")

    def aws(self):
        return Aws("rsc-central-ro", interval=0, retries=2, backoff=0, run=self.run, sleep=lambda s: None)


class FakeGh:
    """Replaces subprocess.run for `gh api`: merged pull requests, the branch head, compare."""

    def __init__(self, pr_pages=None, head=None, compare=None, fail=(), default_branch="main"):
        self.pr_pages = pr_pages or [[]]
        self.head = head or {"sha": sha(1), "date": at(5)}
        self.compare = compare or {}    # (earlier, later) -> "ahead" | "identical" | "behind" | "diverged"
        self.fail, self.calls, self.default_branch = set(fail), [], default_branch

    def run(self, cmd, capture_output=True, text=True):
        self.calls.append(cmd)
        a = cmd[2:]
        line = " ".join(a)
        if any(f in line for f in self.fail):
            return subprocess.CompletedProcess(cmd, 1, "", "gh: Resource not accessible (HTTP 403)")
        if a[0] == "graphql":
            fields = dict(x.split("=", 1) for x in a[1:] if "=" in x and not x.startswith("query="))
            i = 0
            if fields.get("after"):
                i = int(fields["after"])
            nodes = self.pr_pages[i]
            body = {"data": {"repository": {"pullRequests": {
                "pageInfo": {"hasNextPage": i + 1 < len(self.pr_pages), "endCursor": str(i + 1)}, "nodes": nodes}}}}
            return self.ok(body)
        if re.fullmatch(r"repos/[^/]+/[^/]+/commits/\S+", a[0]):
            return self.ok({"sha": self.head["sha"], "commit": {
                "message": "secret commit message", "author": {"name": "A Person", "email": "person@example.com"},
                "committer": {"name": "A Person", "email": "person@example.com", "date": self.head["date"]}},
                "author": {"login": "someone"}})
        if "/compare/" in a[0]:
            earlier, later = a[0].split("/compare/")[1].split("...")
            return self.ok({"status": self.compare.get((earlier, later), "diverged")})
        if re.fullmatch(r"repos/[^/]+/[^/]+", a[0]):
            return self.ok({"b": self.default_branch})
        raise AssertionError(f"unexpected gh call: {line}")

    def ok(self, body):
        return subprocess.CompletedProcess([], 0, json.dumps(body), "")

    def gh(self):
        return d.Gh(run=self.run, sleep=lambda s: None, retries=1)


def pr(commit, hours_ago, updated_hours_ago=None):
    return {"mergedAt": at(hours_ago), "updatedAt": at(updated_hours_ago if updated_hours_ago is not None else hours_ago),
            "mergeCommit": {"oid": commit}}


def span(days=30):
    """A collection window ending at NOW and starting `days` earlier (the collector accepts any half-open window)."""
    return {"covers_date": "2026-11-23", "start": (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": NOW.strftime("%Y-%m-%dT%H:%M:%SZ")}


def collect(fa, fg, days=30, lag=120, day=None):
    return d.collect(fa.aws(), fg.gh(), AR, "example-pipeline", REPO, "main", lag, day or span(days), ["us-east-1"], NOW)


def healthy():
    """Two merged changes, each applied by its own successful run; the head is the newer one."""
    e = [summary("e2", "Succeeded", 5, sha(2)), summary("e1", "Succeeded", 29, sha(1))]
    return (FakeAws([e], {"e2": (True, sha(2)), "e1": (True, sha(1))}),
            FakeGh([[pr(sha(2), 5.2), pr(sha(1), 29.2)]], head={"sha": sha(2), "date": at(5.2)}))


class Healthy(unittest.TestCase):
    def test_every_change_applied_by_its_own_run_is_deployed_and_the_head_too(self):
        ev = collect(*healthy())
        self.assertTrue(ev["collection"]["complete"])
        self.assertEqual([c["deployed"] for c in ev["merged_commits"]], [True, True])
        self.assertEqual([c["deployed_by"] for c in ev["merged_commits"]], ["applied-itself"] * 2)
        self.assertTrue(ev["head"]["deployed"])
        self.assertEqual(ev["assessment_requirement"], AR)
        self.assertEqual((ev["target"], ev["target_type"]), ("example-pipeline", "deployment-pipeline"))

    def test_executions_are_newest_first_and_the_latest_is_the_newest(self):
        ev = collect(*healthy())
        self.assertEqual([e["commit"] for e in ev["executions"]], [sha(2), sha(1)])
        self.assertEqual(ev["latest_execution"]["commit"], sha(2))

    def test_output_variables_are_read_from_the_apply_step(self):
        ev = collect(*healthy())
        self.assertEqual([(e["applied"], e["applied_sha"]) for e in ev["executions"]], [(True, sha(2)), (True, sha(1))])

    def test_statuses_and_triggers_are_normalized(self):
        e = [summary("a", "Superseded", 3, sha(3), "WebhookV2"), summary("b", "Stopping", 4, sha(4), "StartPipelineExecution"),
             summary("c", "Cancelled", 5, sha(5), "Something"), summary("d", "Weird", 6, sha(6))]
        ev = collect(FakeAws([e], {}), FakeGh([[]], head={"sha": sha(9), "date": at(1)}))
        self.assertEqual([x["status"] for x in ev["executions"]], ["superseded", "stopped", "stopped", "unknown"])
        self.assertEqual([x["trigger"] for x in ev["executions"]], ["webhook", "manual", "other", "webhook"])

    def test_zero_merges_is_complete_and_has_nothing_to_judge(self):
        fa, _ = healthy()
        ev = collect(fa, FakeGh([[]], head={"sha": sha(2), "date": at(5.2)}))
        self.assertEqual(ev["merged_commits"], [])
        self.assertTrue(ev["collection"]["complete"])


class ContainedInALaterRun(unittest.TestCase):
    def test_a_change_overtaken_by_a_later_run_that_contains_it_is_deployed(self):
        # superseded mode: the run for sha(2) never ran; sha(3)'s run applied it
        e = [summary("e3", "Succeeded", 5, sha(3)), summary("e2", "Superseded", 7, sha(2))]
        fa = FakeAws([e], {"e3": (True, sha(3))})
        fg = FakeGh([[pr(sha(3), 5.2), pr(sha(2), 7.2)]], head={"sha": sha(3), "date": at(5.2)},
                    compare={(sha(2), sha(3)): "ahead"})
        ev = collect(fa, fg)
        by = {c["sha"]: c for c in ev["merged_commits"]}
        self.assertTrue(by[sha(2)]["deployed"])
        self.assertEqual((by[sha(2)]["deployed_by"], by[sha(2)]["deployed_by_execution_status"]), ("contained-in-later", "succeeded"))
        self.assertEqual(by[sha(3)]["deployed_by"], "applied-itself")
        self.assertTrue(ev["collection"]["complete"])

    def test_a_later_commit_that_does_not_contain_it_does_not_count(self):
        e = [summary("e3", "Succeeded", 5, sha(3))]
        fg = FakeGh([[pr(sha(2), 7.2)]], head={"sha": sha(3), "date": at(5.2)}, compare={(sha(2), sha(3)): "diverged"})
        ev = collect(FakeAws([e], {"e3": (True, sha(3))}), fg)
        self.assertFalse(ev["merged_commits"][0]["deployed"])
        self.assertEqual(ev["merged_commits"][0]["deployed_by"], "none")

    def test_only_a_bounded_number_of_later_runs_are_compared(self):
        later = [summary(f"e{i}", "Succeeded", 10 - i, sha(10 + i)) for i in range(1, 6)]   # 5 later successes
        outputs = {f"e{i}": (True, sha(10 + i)) for i in range(1, 6)}
        compare = {(sha(2), sha(10 + 5)): "ahead"}  # only the FIFTH contains it: beyond the bound
        fg = FakeGh([[pr(sha(2), 20)]], head={"sha": sha(15), "date": at(5)}, compare=compare)
        ev = collect(FakeAws([later], outputs), fg)
        self.assertFalse(ev["merged_commits"][0]["deployed"])
        compares = [c for c in fg.calls if "/compare/" in " ".join(c)]
        self.assertLessEqual(len([c for c in compares if f"{sha(2)}..." in " ".join(c)]), d.MAX_CANDIDATES)

    def test_a_run_started_before_the_merge_cannot_have_deployed_it(self):
        e = [summary("e1", "Succeeded", 30, sha(3))]          # older than the merge below
        fg = FakeGh([[pr(sha(2), 20)]], head={"sha": sha(3), "date": at(30)}, compare={(sha(2), sha(3)): "ahead"})
        ev = collect(FakeAws([e], {"e1": (True, sha(3))}), fg)
        self.assertFalse(ev["merged_commits"][0]["deployed"])
        self.assertEqual(ev["merged_commits"][0]["deployed_by_execution_status"], "none")


class NeverDeployed(unittest.TestCase):
    def test_a_change_whose_only_run_failed_is_not_deployed_and_says_why(self):
        e = [summary("e1", "Failed", 6, sha(2))]
        ev = collect(FakeAws([e], {"e1": None}), FakeGh([[pr(sha(2), 6.5)]], head={"sha": sha(2), "date": at(6.5)}))
        c = ev["merged_commits"][0]
        self.assertEqual((c["deployed"], c["deployed_by"], c["deployed_by_execution_status"]), (False, "none", "failed"))
        self.assertFalse(ev["head"]["deployed"])
        self.assertEqual(ev["head"]["deployed_by_execution_status"], "failed")

    def test_a_change_no_run_ever_started_for_reports_none(self):
        ev = collect(FakeAws([[]], {}), FakeGh([[pr(sha(2), 6.5)]], head={"sha": sha(2), "date": at(6.5)}))
        self.assertEqual(ev["merged_commits"][0]["deployed_by_execution_status"], "none")
        self.assertIsNone(ev["latest_execution"])

    def test_superseded_runs_are_not_counted_as_attempts(self):
        e = [summary("e1", "Superseded", 6, sha(2))]
        ev = collect(FakeAws([e], {}), FakeGh([[pr(sha(2), 6.5)]], head={"sha": sha(2), "date": at(6.5)}))
        self.assertEqual(ev["merged_commits"][0]["deployed_by_execution_status"], "none")

    def test_a_failed_head_with_an_older_success_is_not_deployed(self):
        e = [summary("e2", "Failed", 3, sha(2)), summary("e1", "Succeeded", 29, sha(1))]
        ev = collect(FakeAws([e], {"e2": None, "e1": (True, sha(1))}), FakeGh([[pr(sha(2), 3.2)]], head={"sha": sha(2), "date": at(3.2)}))
        self.assertFalse(ev["head"]["deployed"])
        self.assertEqual(ev["latest_execution"]["status"], "failed")


class FailedThenRecovered(unittest.TestCase):
    def test_a_failed_run_followed_by_a_success_of_the_same_commit_is_recovered_and_kept_visible(self):
        e = [summary("e2", "Succeeded", 5, sha(2)), summary("e1", "Failed", 6, sha(2))]
        ev = collect(FakeAws([e], {"e2": (True, sha(2)), "e1": None}), FakeGh([[pr(sha(2), 6.5)]], head={"sha": sha(2), "date": at(6.5)}))
        failed = [x for x in ev["executions"] if x["status"] == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertIs(failed[0]["recovered"], True)
        self.assertTrue(ev["merged_commits"][0]["deployed"])

    def test_a_failed_run_followed_by_a_success_of_a_later_commit_that_contains_it_is_recovered(self):
        e = [summary("e2", "Succeeded", 5, sha(3)), summary("e1", "Failed", 7, sha(2))]
        fg = FakeGh([[pr(sha(3), 5.2)]], head={"sha": sha(3), "date": at(5.2)}, compare={(sha(2), sha(3)): "ahead"})
        ev = collect(FakeAws([e], {"e2": (True, sha(3)), "e1": None}), fg)
        self.assertIs([x for x in ev["executions"] if x["status"] == "failed"][0]["recovered"], True)

    def test_a_failure_never_followed_by_a_success_is_not_recovered(self):
        e = [summary("e1", "Failed", 6, sha(2))]
        ev = collect(FakeAws([e], {"e1": None}), FakeGh([[pr(sha(2), 6.5)]], head={"sha": sha(2), "date": at(6.5)}))
        self.assertIs(ev["executions"][0]["recovered"], False)

    def test_recovered_is_unknown_when_the_comparison_fails(self):
        e = [summary("e2", "Succeeded", 5, sha(3)), summary("e1", "Failed", 7, sha(2))]
        fg = FakeGh([[]], head={"sha": sha(3), "date": at(5.2)}, fail=["compare"])
        ev = collect(FakeAws([e], {"e2": (True, sha(3)), "e1": None}), fg)
        self.assertIsNone([x for x in ev["executions"] if x["status"] == "failed"][0]["recovered"])


class Paging(unittest.TestCase):
    def test_executions_are_paged_until_the_window_start_is_reached(self):
        old = 24 * 40
        pages = [[summary("a", "Succeeded", 5, sha(2))], [summary("b", "Succeeded", 29, sha(1))],
                 [summary("c", "Succeeded", old, sha(0))], [summary("never-read", "Succeeded", old + 5, sha(8))]]
        fa = FakeAws(pages, {"a": (True, sha(2)), "b": (True, sha(1))})
        ev = collect(fa, FakeGh([[pr(sha(2), 5.2), pr(sha(1), 29.2)]], head={"sha": sha(2), "date": at(5.2)}))
        pages_read = len([c for c in fa.calls if "list-pipeline-executions" in " ".join(c)])
        self.assertEqual(pages_read, 3)                      # the third page reached back past the window
        self.assertEqual([e["commit"] for e in ev["executions"]], [sha(2), sha(1)])   # the old one is outside the window
        self.assertTrue(ev["collection"]["complete"])

    def test_history_that_never_reaches_the_window_start_within_the_page_cap_is_incomplete(self):
        original = d.MAX_EXECUTION_PAGES
        d.MAX_EXECUTION_PAGES = 2
        try:
            pages = [[summary(f"p{i}", "Succeeded", 5 + i, sha(2))] for i in range(5)]
            ev = collect(FakeAws(pages, {f"p{i}": (True, sha(2)) for i in range(5)}),
                         FakeGh([[]], head={"sha": sha(2), "date": at(5)}))
        finally:
            d.MAX_EXECUTION_PAGES = original
        self.assertFalse(ev["collection"]["complete"])
        self.assertTrue(any("pages" in p for p in ev["collection"]["problems"]))

    def test_merged_pull_requests_are_paged_until_updates_predate_the_window(self):
        old = 24 * 40
        pr_pages = [[pr(sha(2), 5.2)], [pr(sha(1), 29.2)], [pr(sha(0), old)], [pr(sha(8), old + 5)]]
        fg = FakeGh(pr_pages, head={"sha": sha(2), "date": at(5.2)})
        ev = collect(FakeAws([[summary("a", "Succeeded", 5, sha(2))]], {"a": (True, sha(2))}), fg)
        graphql = [c for c in fg.calls if c[2] == "graphql"]
        self.assertEqual(len(graphql), 3)
        self.assertEqual([c["sha"] for c in ev["merged_commits"]], [sha(1), sha(2)])   # oldest first, window only

    def test_the_pull_request_page_cap_makes_the_collection_incomplete(self):
        original = d.MAX_PR_PAGES
        d.MAX_PR_PAGES = 2
        try:
            fg = FakeGh([[pr(sha(2), 5.2, 5.2)], [pr(sha(3), 6, 6)], [pr(sha(4), 7, 7)]], head={"sha": sha(2), "date": at(5.2)})
            ev = collect(FakeAws([[summary("a", "Succeeded", 5, sha(2))]], {"a": (True, sha(2))}), fg)
        finally:
            d.MAX_PR_PAGES = original
        self.assertFalse(ev["collection"]["complete"])

    def test_duplicates_and_pull_requests_without_a_merge_commit_are_dropped(self):
        nodes = [pr(sha(2), 5.2), pr(sha(2), 5.2), {"mergedAt": at(6), "updatedAt": at(6), "mergeCommit": None},
                 {"mergedAt": None, "updatedAt": at(6), "mergeCommit": {"oid": sha(7)}}]
        ev = collect(FakeAws([[summary("a", "Succeeded", 5, sha(2))]], {"a": (True, sha(2))}),
                     FakeGh([nodes], head={"sha": sha(2), "date": at(5.2)}))
        self.assertEqual([c["sha"] for c in ev["merged_commits"]], [sha(2)])


class IncompleteIsNeverAPass(unittest.TestCase):
    def test_an_applied_record_that_cannot_be_read_makes_it_incomplete(self):
        fa, fg = healthy()
        fa.fail = ["list-action-executions"]
        ev = collect(fa, fg)
        self.assertFalse(ev["collection"]["complete"])
        self.assertTrue(any("applied record" in p for p in ev["collection"]["problems"]))

    def test_a_comparison_that_fails_makes_it_incomplete_and_the_change_unknown(self):
        e = [summary("e3", "Succeeded", 5, sha(3))]
        fg = FakeGh([[pr(sha(2), 7.2)]], head={"sha": sha(3), "date": at(5.2)}, fail=["compare"])
        ev = collect(FakeAws([e], {"e3": (True, sha(3))}), fg)
        self.assertFalse(ev["collection"]["complete"])
        self.assertEqual(ev["merged_commits"][0]["deployed_by"], "unknown")
        self.assertFalse(ev["merged_commits"][0]["deployed"])

    def test_a_later_page_that_cannot_be_read_makes_it_incomplete(self):
        class Flaky(FakeAws):
            def run(self, cmd, **kw):
                if "--next-token" in cmd:
                    return subprocess.CompletedProcess(cmd, 254, "", "An error occurred (InternalFailure): boom")
                return super().run(cmd, **kw)
        pages = [[summary("a", "Succeeded", 5, sha(2))], [summary("b", "Succeeded", 29, sha(1))]]
        ev = collect(Flaky(pages, {"a": (True, sha(2))}), FakeGh([[]], head={"sha": sha(2), "date": at(5)}))
        self.assertFalse(ev["collection"]["complete"])

    def test_too_many_executions_to_read_every_record_is_incomplete(self):
        original = d.MAX_ACTION_LOOKUPS
        d.MAX_ACTION_LOOKUPS = 1
        try:
            fa, fg = healthy()
            ev = collect(fa, fg)
        finally:
            d.MAX_ACTION_LOOKUPS = original
        self.assertFalse(ev["collection"]["complete"])

    def test_not_being_able_to_read_the_pipeline_at_all_is_an_error_with_no_evidence(self):
        fa, fg = healthy()
        fa.fail = ["list-pipeline-executions"]
        with self.assertRaises(d.CollectionError):
            collect(fa, fg)

    def test_not_being_able_to_read_the_repository_is_an_error_with_no_evidence(self):
        for needle in ("commits/main", "graphql"):
            fa, fg = healthy()
            fg.fail = [needle]
            with self.assertRaises(d.CollectionError, msg=needle):
                collect(fa, fg)

    def test_a_graphql_error_payload_is_an_error(self):
        class Errors(FakeGh):
            def run(self, cmd, **kw):
                if cmd[2] == "graphql":
                    return self.ok({"errors": [{"message": "nope"}], "data": {"repository": None}})
                return super().run(cmd, **kw)
        fa, _ = healthy()
        with self.assertRaises(d.CollectionError):
            collect(fa, Errors([[]]))


class WhatIsRecorded(unittest.TestCase):
    def evidence_text(self):
        fa, fg = healthy()
        return json.dumps(collect(fa, fg))

    def test_no_commit_messages_authors_or_emails(self):
        text = self.evidence_text()
        for needle in ("secret message", "secret commit message", "A Person", "person@example.com", "someone"):
            self.assertNotIn(needle, text)

    def test_no_account_ids_or_arns(self):
        text = self.evidence_text()
        self.assertIsNone(re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", text))
        self.assertNotIn("arn:aws", text)

    def test_limitations_are_recorded_with_the_evidence(self):
        ev = collect(*healthy())
        self.assertEqual(ev["collection"]["limitations"], d.LIMITATIONS)
        self.assertTrue(any("health" in x for x in d.LIMITATIONS))

    def test_the_allowed_lag_the_day_and_its_window_are_recorded(self):
        ev = collect(*healthy(), lag=45, days=7)
        self.assertEqual(ev["collection"]["allowed_lag_minutes"], 45)
        self.assertEqual(ev["covers_date"], "2026-11-23")
        self.assertEqual(ev["window"], {"start": "2026-11-17T12:00:00Z", "end": "2026-11-24T12:00:00Z"})
        self.assertNotIn("window_days", ev["collection"])


class OnlyReads(unittest.TestCase):
    def test_only_read_verbs_through_the_given_profile_and_get_requests(self):
        fa, fg = healthy()
        collect(fa, fg)
        for cmd in fa.calls:
            self.assertEqual(cmd[2], "rsc-central-ro")
            self.assertIn(cmd[5:7], (["codepipeline", "list-pipeline-executions"], ["codepipeline", "list-action-executions"]))
        for cmd in fg.calls:
            self.assertNotIn("-X", cmd)
            self.assertNotIn("--method", cmd)
            self.assertNotIn("POST", cmd)


class ParallelComparisons(unittest.TestCase):
    def scenario(self):
        e = [summary("e9", "Succeeded", 2, sha(9))] + [summary(f"x{i}", "Superseded", 20 - i, sha(30 + i)) for i in range(6)]
        prs = [pr(sha(30 + i), 20.2 - i) for i in range(6)]
        compare = {(sha(30 + i), sha(9)): "ahead" for i in range(6)}
        return FakeAws([e], {"e9": (True, sha(9))}), FakeGh([prs], head={"sha": sha(9), "date": at(2)}, compare=compare)

    def test_prefetching_in_parallel_gives_the_same_evidence_as_one_by_one(self):
        results = []
        for workers in (1, 8):
            fa, fg = self.scenario()
            gh = fg.gh()
            containment = d.Containment(gh, REPO, workers=workers)
            executions = [d.normalize_execution(s) for s in fa.pages[0]]
            for e in executions:
                e["applied"], e["applied_sha"] = (True, sha(9)) if e["status"] == "succeeded" else (None, None)
            changes, _ = d.read_merged_changes(gh, REPO, "main", NOW - timedelta(days=30), NOW)
            ev = d.build_evidence(AR, "p", REPO, "main", 120, span(30), NOW, ["us-east-1"], executions,
                                  d.read_head(gh, REPO, "main"), changes, [], containment)
            results.append(json.dumps(ev, sort_keys=True))
        self.assertEqual(results[0], results[1])
        self.assertIn('"contained-in-later"', results[0])

    def test_a_failed_prefetch_is_asked_again_lazily_and_then_marks_incomplete(self):
        fa, fg = self.scenario()
        fg.fail = ["compare"]
        gh = fg.gh()
        containment = d.Containment(gh, REPO, workers=4)
        containment.prefetch([(sha(30), sha(9))])
        self.assertEqual(containment.cache, {})
        with self.assertRaises(d.GhError):
            containment(sha(30), sha(9))


DAY = {"covers_date": "2026-11-23", "start": "2026-11-23T00:00:00Z", "end": "2026-11-24T00:00:00Z"}


class OneDay(unittest.TestCase):
    """The evidence covers one UTC day, [start, end): merges outside it are not in it."""

    def merges(self, *when):
        prs = [{"mergedAt": w, "updatedAt": w, "mergeCommit": {"oid": sha(10 + i)}} for i, w in enumerate(when)]
        return FakeGh([prs], head={"sha": sha(1), "date": at(5)})

    def evidence(self, *when):
        e = [summary("a", "Succeeded", 5, sha(1))]
        return collect(FakeAws([e], {"a": (True, sha(1))}), self.merges(*when), day=DAY)

    def test_half_open_boundaries(self):
        ev = self.evidence("2026-11-22T23:59:59Z", "2026-11-23T00:00:00Z", "2026-11-23T23:59:59Z", "2026-11-24T00:00:00Z")
        self.assertEqual([c["merged_at"] for c in ev["merged_commits"]], ["2026-11-23T00:00:00Z", "2026-11-23T23:59:59Z"])

    def test_a_day_with_no_merge_is_a_complete_empty_collection(self):
        ev = self.evidence("2026-11-20T10:00:00Z", "2026-11-25T10:00:00Z")
        self.assertEqual(ev["merged_commits"], [])
        self.assertTrue(ev["collection"]["complete"])

    def test_the_day_and_its_window_are_in_the_evidence(self):
        ev = self.evidence()
        self.assertEqual((ev["covers_date"], ev["window"]), ("2026-11-23", {"start": "2026-11-23T00:00:00Z", "end": "2026-11-24T00:00:00Z"}))

    def test_executions_after_the_day_are_read_so_a_late_merge_can_be_deployed(self):
        e = [summary("late", "Succeeded", 5, sha(10)), summary("before", "Succeeded", 24 * 5, sha(9))]
        ev = collect(FakeAws([e], {"late": (True, sha(10)), "before": (True, sha(9))}),
                     self.merges("2026-11-23T23:30:00Z"), day=DAY)
        self.assertEqual([c["deployed"] for c in ev["merged_commits"]], [True])
        self.assertEqual([x["commit"] for x in ev["executions"]], [sha(10)])      # the run before the day is not read in

    def test_the_cli_takes_a_date_and_refuses_a_malformed_one(self):
        res = subprocess.run([sys.executable, str(ROOT / "evidence/lib/deployment_pipeline.py"), "--ar", AR, "--target", "p",
                              "--profile", "x", "--region", "us-east-1", "--repository", REPO, "--date", "2026-13-01"],
                             capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)


class Arguments(unittest.TestCase):
    def test_an_empty_branch_means_the_repositorys_default_branch(self):
        self.assertEqual(d.default_branch(FakeGh(default_branch="trunk").gh(), REPO), "trunk")

    def test_parse_time_accepts_z_offsets_and_epochs(self):
        self.assertEqual(d.parse_time("2026-11-24T12:00:00Z"), NOW)
        self.assertEqual(d.parse_time(NOW.timestamp()), NOW)

    def test_gh_retries_5xx_but_not_4xx(self):
        calls = []

        def run(cmd, capture_output=True, text=True):
            calls.append(1)
            return subprocess.CompletedProcess(cmd, 1, "", "gh: Bad Gateway (HTTP 502)" if len(calls) < 2 else "gh: Not Found (HTTP 404)")

        with self.assertRaises(d.GhError):
            d.Gh(run=run, sleep=lambda s: None, retries=3).api("repos/x/y")
        self.assertEqual(len(calls), 2)  # one retry after the 502, none after the 404

    def test_aws_errors_never_carry_account_ids(self):
        def run(cmd, capture_output=True, text=True):
            return subprocess.CompletedProcess(cmd, 254, "", "AccessDenied for arn:aws:iam::" + "1" * 12 + ":role/x")
        with self.assertRaises(AwsError) as cm:
            Aws("p", interval=0, retries=0, run=run, sleep=lambda s: None).call("codepipeline", "list-pipelines")
        self.assertNotIn("1" * 12, str(cm.exception))


if __name__ == "__main__":
    unittest.main()
