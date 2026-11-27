import json
import os
from datetime import datetime, timedelta, timezone
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "evidence/lib"))
AR1, AR2 = "RSC.CMT.CTRL01.AR01", "RSC.CMT.CTRL01.AR02"

# A stand-in for `gh` keyed on the repository name: *ok* works, *unprot* is a
# branch with no protection, anything else is refused.
FAKE_GH = r"""#!/usr/bin/env bash
args="$*"
case "$args" in
  *"api graphql"*"-f oid="*)
    # follow-up page of a commit's status contexts
    oid="$(sed -n 's/.*-f oid=\([^ ]*\).*/\1/p' <<<"$args")"
    after="$(sed -n 's/.*-f after=\([^ ]*\).*/\1/p' <<<"$args")"
    f="${FAKE_GH_DIR}/ctx.${oid}.${after}.json"
    if [[ -f "$f" ]]; then cat "$f"; exit 0; fi
    echo "gh: no such contexts page (HTTP 500)" >&2; exit 1
    ;;
  *"api graphql"*)
    name="$(sed -n 's/.*-f name=\([^ ]*\).*/\1/p' <<<"$args")"
    # A private repository and a fine-grained token: the contexts connection is refused.
    if [[ "$args" == *"contexts(first"* && "$name" == *priv* ]]; then
      echo "gh: Resource not accessible by personal access token" >&2; exit 1
    fi
    file="${FAKE_GH_DIR}/${name}.json"
    [[ "$args" == *"-f after="* ]] && file="${FAKE_GH_DIR}/${name}.2.json"
    if [[ -f "$file" ]]; then cat "$file"; exit 0; fi
    [[ "$name" == *ok* || "$name" == *unprot* ]] || { echo "gh: Resource not accessible by personal access token" >&2; exit 1; }
    cat "${FAKE_GH_DIR}/default.json"
    ;;
  *"/commits/"*"/status"*)
    # REST combined status of a commit (the fallback for private repositories)
    oid="$(sed -n 's#.*/commits/\([^/]*\)/status.*#\1#p' <<<"$args")"
    f="${FAKE_GH_DIR}/status.${oid}.json"
    if [[ -f "$f" ]]; then cat "$f"; exit 0; fi
    echo "gh: Not Found (HTTP 404)" >&2; exit 1
    ;;
  *"repos/openshift/release/contents/"*)
    path="$(sed -n 's#.*contents/\([^ ]*\).*#\1#p' <<<"$args")"
    f="${FAKE_GH_DIR}/prow/$(sed 's#.*02_config/##; s#/#__#g' <<<"$path")"
    if [[ -f "${FAKE_GH_DIR}/prow-forbidden" ]]; then echo "gh: Resource not accessible (HTTP 403)" >&2; exit 1; fi
    if [[ -f "$f" ]]; then cat "$f"; exit 0; fi
    echo "gh: Not Found (HTTP 404)" >&2; exit 1
    ;;
  *"/protection"*)
    name="$(sed -n 's#.*repos/[^/]*/\([^/]*\)/branches.*#\1#p' <<<"$args")"
    if [[ -f "${FAKE_GH_DIR}/protection-${name}.err" ]]; then cat "${FAKE_GH_DIR}/protection-${name}.err" >&2; exit 1; fi
    if [[ -f "${FAKE_GH_DIR}/protection-${name}.json" ]]; then cat "${FAKE_GH_DIR}/protection-${name}.json"; exit 0; fi
    case "$args" in
      *ok*) echo '{"enforce_admins":{"enabled":true}}' ;;
      *unprot*) echo "gh: Branch not protected (HTTP 404)" >&2; exit 1 ;;
      *) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
    esac
    ;;
  *) echo "unexpected gh call: $args" >&2; exit 2 ;;
esac
"""


# The day collected: three days ago (a backfill, so no settle delay applies), found at run time so the
# 90-day limit never expires the test data.
TODAY = datetime.now(timezone.utc).date()
DAY_DATE = (TODAY - timedelta(days=3)).isoformat()
DAY_AT = f"{DAY_DATE}T12:00:00Z"
DAY_BEFORE = f"{(TODAY - timedelta(days=4)).isoformat()}T12:00:00Z"


def user(login, bot=False):
    return {"login": login, "__typename": "Bot" if bot else "User"}


def sc(context, state):
    """A StatusContext as GraphQL returns it."""
    return {"__typename": "StatusContext", "context": context, "state": state}


def cr(name, status="COMPLETED", conclusion="SUCCESS"):
    """A CheckRun as GraphQL returns it."""
    return {"__typename": "CheckRun", "name": name, "status": status, "conclusion": conclusion}


def pr(number, author="alice", author_bot=False, merged_by="openshift-merge-bot", commits=(), labels=(), comments=(), reviews=(), opinionated=(), at=None, truncated=False,
       contexts=(), more_contexts=False, cursor="cur1", oid="oid1", rollup="SUCCESS", no_rollup=False):
    """A GraphQL pull request node. comments/reviews are (login, body[, time]); contexts are sc()/cr()."""
    t = at or DAY_AT
    return {
        "number": number, "mergedAt": t, "updatedAt": t,
        "author": user(author, author_bot), "mergedBy": {"login": merged_by},
        "labels": {"nodes": [{"name": n} for n in labels]},
        "latestOpinionatedReviews": {"nodes": [{"state": st, "author": user(a)} for a, st in opinionated]},
        "comments": {"pageInfo": {"hasNextPage": truncated},
                     "nodes": [{"author": user(c[0], len(c) > 3), "body": c[1], "createdAt": c[2] if len(c) > 2 else "2026-01-01T00:00:00Z"}
                               for c in comments]},
        "reviews": {"pageInfo": {"hasNextPage": False},
                    "nodes": [{"author": user(r[0]), "body": r[1], "submittedAt": r[2] if len(r) > 2 else "2026-01-01T00:00:00Z"}
                              for r in reviews]},
        "commits": {"nodes": [{"commit": {"oid": oid, "statusCheckRollup": None if no_rollup else {
            "state": rollup,
            "contexts": {"pageInfo": {"hasNextPage": more_contexts, "endCursor": cursor}, "nodes": list(contexts)}}}}]},
        "allCommits": {"totalCount": len(commits), "nodes": [
            {"commit": {"author": {"user": {"login": c[0]} if c[0] else None}, "signature": {"isValid": c[1]}}} for c in commits]},
    }


def page(nodes, has_next=False, cursor="c1"):
    return {"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}, "nodes": nodes}}}}


class Collectors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        gh = t / "bin" / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
        self.out = t / "out"
        self.fake_dir = t / "fake"
        self.fake_dir.mkdir()
        self.graphql("default", page([pr(7, labels=["lgtm", "approved"], comments=[("bob", "/lgtm")])]))

    def graphql(self, name, body):
        (self.fake_dir / f"{name}.json").write_text(json.dumps(body))

    def run_collector(self, ar, repos, extra_env=None):
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", GITHUB_TOKEN="x",
                   RSC_REPOS=" ".join(repos), RSC_EVIDENCE_DIR=str(self.out), RSC_BASE_REF="main",
                   RSC_ENV="integration", FAKE_GH_DIR=str(self.fake_dir), **{"RSC_DATE": DAY_DATE, **(extra_env or {})})
        return subprocess.run([str(ROOT / "evidence" / f"{ar}.sh")], env=env, capture_output=True, text=True)

    def manifest(self, ar):
        return json.loads((self.out / ar / "manifest.json").read_text())

    def test_one_failing_repo_does_not_stop_the_others(self):
        for ar in (AR1, AR2):
            res = self.run_collector(ar, ["o/ok-a", "o/denied", "o/ok-b"])
            self.assertEqual(res.returncode, 0, res.stderr)
            targets = {t["name"]: t for t in self.manifest(ar)["targets"]}
            self.assertEqual(targets["o/ok-a"]["status"], "collected")
            self.assertEqual(targets["o/ok-b"]["status"], "collected")
            self.assertEqual(targets["o/denied"]["status"], "error")
            self.assertIn("not", targets["o/denied"]["error"].lower())
            self.assertTrue((self.out / ar / "ok-a.json").is_file())
            self.assertFalse((self.out / ar / "denied.json").exists())

    def test_evidence_declares_ar_and_repo_but_manifest_does_not(self):
        self.run_collector(AR2, ["o/ok-a"])
        ev = json.loads((self.out / AR2 / "ok-a.json").read_text())
        self.assertEqual((ev["assessment_requirement"], ev["repository"]), (AR2, "o/ok-a"))
        m = self.manifest(AR2)
        self.assertNotIn("assessment_requirement", m)  # the Rego would judge it as evidence
        self.assertEqual((m["ar"], m["environment"]), (AR2, "integration"))
        self.assertIn("generated_at", m)

    def test_unprotected_branch_is_evidence_not_an_error(self):
        res = self.run_collector(AR1, ["o/unprot", "o/ok"])
        self.assertEqual(res.returncode, 0, res.stderr)
        targets = {t["name"]: t["status"] for t in self.manifest(AR1)["targets"]}
        self.assertEqual(targets["o/unprot"], "collected")
        ev = json.loads((self.out / AR1 / "unprot.json").read_text())
        self.assertIs(ev["protected"], False)
        self.assertEqual(ev["protection"], {})
        self.assertIs(json.loads((self.out / AR1 / "ok.json").read_text())["protected"], True)

    def test_all_repos_failing_fails_the_collector(self):
        res = self.run_collector(AR2, ["o/denied-a", "o/denied-b"])
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual([t["status"] for t in self.manifest(AR2)["targets"]], ["error", "error"])

    def test_stale_evidence_is_cleared(self):
        self.run_collector(AR2, ["o/ok-a", "o/ok-b"])
        self.run_collector(AR2, ["o/ok-a"])
        self.assertFalse((self.out / AR2 / "ok-b.json").exists())

    def test_repos_default_to_scope_file(self):
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", GITHUB_TOKEN="x",
                   RSC_EVIDENCE_DIR=str(self.out), RSC_BASE_REF="main", FAKE_GH_DIR=str(self.fake_dir), RSC_DATE=DAY_DATE)
        env.pop("RSC_REPOS", None)
        subprocess.run([str(ROOT / "evidence" / f"{AR2}.sh")], env=env, capture_output=True, text=True)
        names = {t["name"] for t in self.manifest(AR2)["targets"]}
        self.assertEqual(len(names), 7)
        self.assertIn("openshift-online/rosa-seaplane-internal", names)


TIDE = """tide:
  queries:
  - labels: [approved, lgtm, jira/valid-reference]
    missingLabels: [do-not-merge/hold]
    repos: [o/ok-g]
"""
TIDE_BOT_WITHOUT_LABELS = TIDE + """  - author: dep-bot
    labels: [approved]
    repos: [o/ok-g]
"""


class ApprovalGate(unittest.TestCase):
    """How the AR01 collector normalizes the approval requirement and its enforcement."""

    def collect(self, protection=None, prow=None, forbid_prow=False):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql  # noqa: B018 (shared fixture dir)
        (c.fake_dir / "protection-ok-g.json").write_text(json.dumps(protection or {"enforce_admins": {"enabled": False}}))
        if prow is not None:
            (c.fake_dir / "prow").mkdir()
            (c.fake_dir / "prow" / "o__ok-g___prowconfig.yaml").write_text(prow)
        if forbid_prow:
            (c.fake_dir / "prow-forbidden").write_text("")
        res = c.run_collector(AR1, ["o/ok-g"])
        self.c = c
        return res

    def gate(self):
        return json.loads((self.c.out / AR1 / "ok-g.json").read_text())["approval_gate"]

    def test_tide_gate_not_enforced_on_github(self):
        self.assertEqual(self.collect(prow=TIDE).returncode, 0)
        g = self.gate()
        self.assertEqual((g["mechanism"], g["requires_approval"], g["enforced_on_github"]), ("prow-tide", True, False))

    def test_tide_gate_enforced_by_merge_restrictions(self):
        self.collect(protection={"restrictions": {"users": [], "teams": [], "apps": []}}, prow=TIDE)
        self.assertIs(self.gate()["enforced_on_github"], True)

    def test_tide_gate_enforced_by_requiring_the_tide_status(self):
        self.collect(protection={"required_status_checks": {"strict": False, "contexts": ["ci/x", "tide"]}}, prow=TIDE)
        self.assertIs(self.gate()["enforced_on_github"], True)

    def test_other_status_contexts_do_not_enforce_the_gate(self):
        self.collect(protection={"required_status_checks": {"strict": False, "contexts": ["ci/prow/x"]}}, prow=TIDE)
        self.assertIs(self.gate()["enforced_on_github"], False)

    def test_a_merge_rule_without_approval_labels_means_no_approval_requirement(self):
        self.collect(prow=TIDE_BOT_WITHOUT_LABELS)
        g = self.gate()
        self.assertIs(g["requires_approval"], False)
        self.assertEqual(g["queries_without_approval"], ["dep-bot"])

    def test_no_prow_config_means_no_gate(self):
        self.collect()
        self.assertEqual(self.gate(), {"mechanism": "none", "requires_approval": False, "enforced_on_github": False})

    def test_github_required_reviews_are_a_gate_enforced_by_github(self):
        self.collect(protection={"required_pull_request_reviews": {"required_approving_review_count": 1}})
        self.assertEqual(self.gate(), {"mechanism": "github-required-reviews", "requires_approval": True,
                                       "enforced_on_github": True})

    def test_failing_to_read_prow_config_is_an_error_not_no_gate(self):
        res = self.collect(prow=TIDE, forbid_prow=True)
        self.assertNotEqual(res.returncode, 0)  # the only repo failed
        m = json.loads((self.c.out / AR1 / "manifest.json").read_text())
        self.assertEqual(m["targets"][0]["status"], "error")
        self.assertFalse((self.c.out / AR1 / "ok-g.json").exists())


class Approval(unittest.TestCase):
    """How the AR02 collector normalizes GitHub and Prow approvals."""

    def collect(self, node, repo="o/ok-x"):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([node]))
        res = c.run_collector(AR2, [repo])
        self.assertEqual(res.returncode, 0, res.stderr)
        prs = json.loads((c.out / AR2 / "ok-x.json").read_text())["pull_requests"]
        self.assertEqual(len(prs), 1)
        return prs[0]

    LABELS = ("lgtm", "approved")

    def test_github_review_approval(self):
        p = self.collect(pr(1, opinionated=[("bob", "APPROVED")]))
        self.assertEqual((p["approved_by"], p["approval_sources"]), (["bob"], ["github-review"]))

    def test_prow_approval_from_comment(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("bob", "looks good\n/lgtm\r\n/approve")]))
        self.assertEqual((p["approved_by"], p["approval_sources"]), (["bob"], ["prow"]))

    def test_prow_approval_from_review_body(self):
        p = self.collect(pr(1, labels=self.LABELS, reviews=[("bob", "/lgtm\n/approve")]))
        self.assertEqual(p["approved_by"], ["bob"])

    def test_approve_command_from_a_non_author_counts(self):
        # Two-person Prow flow, as on rosa-seaplane PR 994: a reviewer /lgtm, an approver /approve.
        p = self.collect(pr(1, labels=self.LABELS, comments=[("carol", "/lgtm"), ("dave", "/approve")]))
        self.assertEqual(p["approved_by"], ["carol", "dave"])

    def test_authors_own_approve_never_counts(self):
        p = self.collect(pr(1, author="alice", labels=self.LABELS, comments=[("alice", "/approve")]))
        self.assertEqual(p["approved_by"], [])

    def test_commands_after_the_merge_do_not_count(self):
        # rosa-seaplane PR 968: merged by hand, then /lgtm and /approve on the closed PR.
        late = ("dana", "/lgtm\n/approve", "2099-01-01T00:00:00Z")
        self.assertEqual(self.collect(pr(1, labels=self.LABELS, comments=[late]))["approved_by"], [])
        early = ("dana", "/lgtm\n/approve", "2000-01-01T00:00:00Z")
        self.assertEqual(self.collect(pr(1, labels=self.LABELS, comments=[early]))["approved_by"], ["dana"])

    def test_author_is_bot_is_recorded(self):
        self.assertIs(self.collect(pr(1, author="dep-bot", author_bot=True))["author_is_bot"], True)
        self.assertIs(self.collect(pr(1))["author_is_bot"], False)

    def test_both_sources(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("carol", "/lgtm")], opinionated=[("bob", "APPROVED")]))
        self.assertEqual(p["approved_by"], ["bob", "carol"])
        self.assertEqual(p["approval_sources"], ["github-review", "prow"])

    def test_authors_own_lgtm_never_counts(self):
        p = self.collect(pr(1, author="alice", labels=self.LABELS, comments=[("alice", "/lgtm")]))
        self.assertEqual(p["approved_by"], [])

    def test_authors_own_github_approval_never_counts(self):
        p = self.collect(pr(1, author="alice", opinionated=[("alice", "APPROVED")]))
        self.assertEqual(p["approved_by"], [])

    def test_command_without_labels_did_not_take_effect(self):
        # The real shape of rosa-seaplane PR 968: /lgtm in a comment, no labels.
        for labels in ((), ("lgtm",), ("approved",)):
            p = self.collect(pr(1, labels=labels, comments=[("bob", "/lgtm\n/approve")]))
            self.assertEqual(p["approved_by"], [], labels)

    def test_labels_without_any_human_command_do_not_prove_an_approver(self):
        # A bot author applying its own labels, as dependency-update bots do.
        p = self.collect(pr(1, author="dep-bot", labels=self.LABELS, comments=[("openshift-ci", "[APPROVALNOTIFIER]", "2026-01-01T00:00:00Z", "bot")]))
        self.assertEqual(p["approved_by"], [])

    def test_cancelled_lgtm_does_not_count_but_a_later_relgtm_does(self):
        cancelled = pr(1, labels=self.LABELS, comments=[("bob", "/lgtm", "2026-01-01T00:00:01Z"), ("bob", "/lgtm cancel", "2026-01-01T00:00:02Z")])
        self.assertEqual(self.collect(cancelled)["approved_by"], [])
        again = pr(1, labels=self.LABELS, comments=[("bob", "/lgtm cancel", "2026-01-01T00:00:01Z"), ("bob", "/lgtm", "2026-01-01T00:00:02Z")])
        self.assertEqual(self.collect(again)["approved_by"], ["bob"])

    def test_commands_must_start_a_line(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("bob", "please do not /lgtm yet\n> /lgtm quoted")]))
        self.assertEqual(p["approved_by"], [])

    def test_bot_commenters_are_not_approvers(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("some-bot", "/lgtm", "2026-01-01T00:00:00Z", "bot")]))
        self.assertEqual(p["approved_by"], [])

    def test_truncated_history_is_flagged(self):
        self.assertIs(self.collect(pr(1, truncated=True))["history_truncated"], True)
        self.assertIs(self.collect(pr(1))["history_truncated"], False)

    def test_no_review_decision_or_comment_text_in_evidence(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("bob", "secret-ish text\n/lgtm")]))
        self.assertNotIn("review_decision", p)
        self.assertNotIn("secret-ish", json.dumps(p))

    def test_prs_outside_the_day_are_dropped(self):
        old = DAY_BEFORE
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([pr(1), pr(2, at=old)]))
        c.run_collector(AR2, ["o/ok-x"])
        prs = json.loads((c.out / AR2 / "ok-x.json").read_text())["pull_requests"]
        self.assertEqual([p["number"] for p in prs], [1])

    def test_pagination_follows_until_the_day_is_covered(self):
        old = DAY_BEFORE
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([pr(1), pr(2)], has_next=True))
        c.graphql("ok-x.2", page([pr(3), pr(4, at=old)], has_next=True, cursor="c2"))
        c.run_collector(AR2, ["o/ok-x"])
        prs = json.loads((c.out / AR2 / "ok-x.json").read_text())["pull_requests"]
        self.assertEqual([p["number"] for p in prs], [1, 2, 3])


class OneDay(unittest.TestCase):
    """AR02 is an event collector: the evidence holds exactly the PRs merged in [day 00:00:00Z, next day 00:00:00Z)."""

    def collect(self, nodes, has_next=False, extra_env=None, repo="o/ok-x"):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page(nodes, has_next=has_next))
        res = c.run_collector(AR2, [repo], extra_env)
        self.c, self.res = c, res
        f = c.out / AR2 / "ok-x.json"
        return json.loads(f.read_text()) if f.is_file() else None

    def test_half_open_boundaries(self):
        nodes = [pr(1, at=f"{(TODAY - timedelta(days=4)).isoformat()}T23:59:59Z"), pr(2, at=f"{DAY_DATE}T00:00:00Z"),
                 pr(3, at=f"{DAY_DATE}T23:59:59Z"), pr(4, at=f"{(TODAY - timedelta(days=2)).isoformat()}T00:00:00Z")]
        doc = self.collect(nodes)
        self.assertEqual([p["number"] for p in doc["pull_requests"]], [2, 3])

    def test_the_day_and_window_are_in_the_evidence_and_the_manifest(self):
        doc = self.collect([pr(1)])
        self.assertEqual(doc["covers_date"], DAY_DATE)
        self.assertEqual(doc["window"], {"start": f"{DAY_DATE}T00:00:00Z", "end": f"{(TODAY - timedelta(days=2)).isoformat()}T00:00:00Z"})
        self.assertNotIn("window_days", doc)
        self.assertEqual(self.c.manifest(AR2)["covers_date"], DAY_DATE)

    def test_a_day_with_no_merge_is_a_complete_empty_collection(self):
        doc = self.collect([pr(1, at=DAY_BEFORE)])
        self.assertEqual(doc["pull_requests"], [])
        self.assertEqual(doc["summary"]["merged"], 0)
        self.assertEqual(self.c.manifest(AR2)["targets"][0]["status"], "collected")

    def test_a_repository_that_cannot_be_read_is_not_an_empty_day(self):
        doc = self.collect([], repo="o/denied-x")
        self.assertIsNone(doc)
        self.assertEqual(self.c.manifest(AR2)["targets"][0]["status"], "error")

    def test_reading_down_to_the_day_is_capped_and_a_capped_read_is_an_error_not_an_empty_day(self):
        nodes = [pr(1, at=f"{(TODAY - timedelta(days=1)).isoformat()}T12:00:00Z")]
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        for name in ["ok-x"] + [f"ok-x.{i}" for i in range(2, 3)]:
            c.graphql(name, page(nodes, has_next=True))
        # the fake serves the same page for every cursor, always newer than the day: the cap is reached
        c.run_collector(AR2, ["o/ok-x"])
        self.assertEqual(c.manifest(AR2)["targets"][0]["status"], "error")
        self.assertFalse((c.out / AR2 / "ok-x.json").exists())

    def test_a_bad_date_fails_before_anything_is_collected(self):
        for bad in (TODAY.isoformat(), "2026-02-30", "last tuesday"):
            c = Collectors("test_one_failing_repo_does_not_stop_the_others")
            c.setUp()
            self.addCleanup(c.tmp.cleanup)
            res = c.run_collector(AR2, ["o/ok-a"], {"RSC_DATE": bad})
            self.assertNotEqual(res.returncode, 0, bad)
            self.assertFalse((c.out / AR2 / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()


class Retry(unittest.TestCase):
    """rsc_retry must report the command's real failure, and retry only 5xx."""

    def run_retry(self, script):
        out = subprocess.run(["bash", "-c", f'source "{ROOT}/evidence/lib/collect.sh"; sleep() {{ :; }}; {script}'],
                             capture_output=True, text=True)
        return out

    def test_failure_is_not_swallowed(self):
        res = self.run_retry('rsc_retry bash -c "echo gh: forbidden \\(HTTP 403\\) >&2; exit 1"; echo rc=$?')
        self.assertIn("rc=1", res.stdout)
        self.assertIn("HTTP 403", res.stderr)

    def test_success_passes_output_through(self):
        self.assertEqual(self.run_retry("rsc_retry echo hello").stdout, "hello")

    def test_5xx_is_retried_then_succeeds(self):
        script = ('n=$(mktemp); rsc_retry bash -c "c=\\$(cat $n 2>/dev/null || echo 0); echo \\$((c+1)) > $n; '
                  '[ \\$c -ge 2 ] && echo ok || { echo gh: HTTP 504 >&2; exit 1; }"; echo " rc=$?"')
        self.assertIn("ok rc=0", self.run_retry(script).stdout)

    def test_a_truncated_response_is_retried_then_succeeds(self):
        script = ('n=$(mktemp); rsc_retry bash -c "c=\\$(cat $n 2>/dev/null || echo 0); echo \\$((c+1)) > $n; '
                  '[ \\$c -ge 1 ] && echo ok || { echo unexpected end of JSON input >&2; exit 1; }"; echo " rc=$?"')
        self.assertIn("ok rc=0", self.run_retry(script).stdout)

    def test_a_dropped_connection_is_retried(self):
        for msg in ("unexpected EOF", "connection reset by peer", "i/o timeout", "TLS handshake timeout"):
            script = ('n=$(mktemp); rsc_retry bash -c "echo x >> $n; echo ' + msg + ' >&2; exit 1" >/dev/null 2>&1; '
                      'echo calls=$(grep -c x $n)')
            self.assertIn("calls=3", self.run_retry(script).stdout, msg)

    def test_4xx_is_not_retried(self):
        script = ('n=$(mktemp); rsc_retry bash -c "echo x >> $n; echo gh: HTTP 404 >&2; exit 1"; echo calls=$(grep -c x $n)')
        self.assertIn("calls=1", self.run_retry(script).stdout)


BOT_TIDE = """tide:
  queries:
  - author: dep-bot[bot]
    labels: [approved, lgtm]
    repos: [o/ok-x]
  - labels: [approved, lgtm, jira/valid-reference]
    repos: [o/ok-x]
"""


def ctx_page(nodes, has_next=False, cursor="cur2"):
    return {"data": {"repository": {"object": {"statusCheckRollup": {"contexts": {
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}, "nodes": nodes}}}}}}


class RequiredChecks(unittest.TestCase):
    """AR02 judges only the checks the branch protection requires, on each PR's last commit."""

    def collect(self, nodes, protection=None, protection_err=None, extra_env=None, pages=None):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page(nodes))
        if protection is not None:
            (c.fake_dir / "protection-ok-x.json").write_text(json.dumps(protection))
        if protection_err is not None:
            (c.fake_dir / "protection-ok-x.err").write_text(protection_err)
        for name, body in (pages or {}).items():
            (c.fake_dir / f"ctx.{name}.json").write_text(json.dumps(body))
        res = c.run_collector(AR2, ["o/ok-x"], extra_env=extra_env)
        self.c, self.res = c, res
        path = c.out / AR2 / "ok-x.json"
        return json.loads(path.read_text()) if path.is_file() else None

    def checks(self, doc, number=1):
        p = next(p for p in doc["pull_requests"] if p["number"] == number)
        return {x["context"]: x["result"] for x in p["required_checks"]}, p

    REQ = {"required_status_checks": {"strict": False, "contexts": ["ci/build", "ci/lint"]}}

    def test_required_contexts_come_from_both_protection_lists_sorted_and_unique(self):
        prot = {"required_status_checks": {"contexts": ["ci/b", "ci/a"], "checks": [{"context": "ci/a"}, {"context": "ci/c"}]}}
        doc = self.collect([pr(1)], protection=prot)
        self.assertEqual(doc["required_contexts"], ["ci/a", "ci/b", "ci/c"])
        self.assertIs(doc["branch_protected"], True)

    def test_unprotected_branch_means_no_required_checks_not_an_error(self):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("unprot", page([pr(1)]))
        res = c.run_collector(AR2, ["o/unprot"])
        self.assertEqual(res.returncode, 0, res.stderr)
        doc = json.loads((c.out / AR2 / "unprot.json").read_text())
        self.assertEqual((doc["branch_protected"], doc["required_contexts"], doc["pull_requests"][0]["required_checks"]),
                         (False, [], []))

    def test_protection_without_required_checks_is_an_empty_list(self):
        doc = self.collect([pr(1)], protection={"enforce_admins": {"enabled": False}})
        self.assertEqual((doc["branch_protected"], doc["required_contexts"]), (True, []))

    def test_any_other_protection_failure_is_a_collection_error_never_no_checks(self):
        doc = self.collect([pr(1)], protection_err="gh: Resource not accessible (HTTP 403)")
        self.assertIsNone(doc)
        self.assertNotEqual(self.res.returncode, 0)
        self.assertEqual(json.loads((self.c.out / AR2 / "manifest.json").read_text())["targets"][0]["status"], "error")

    def test_status_context_results(self):
        for state, want in (("SUCCESS", "success"), ("FAILURE", "failure"), ("ERROR", "failure"),
                            ("PENDING", "pending"), ("EXPECTED", "pending")):
            doc = self.collect([pr(1, contexts=[sc("ci/build", state), sc("ci/lint", "SUCCESS")])], protection=self.REQ)
            self.assertEqual(self.checks(doc)[0], {"ci/build": want, "ci/lint": "success"}, state)

    def test_check_run_results(self):
        cases = [(("COMPLETED", "SUCCESS"), "success"), (("COMPLETED", "FAILURE"), "failure"),
                 (("COMPLETED", "TIMED_OUT"), "failure"), (("COMPLETED", "CANCELLED"), "failure"),
                 (("COMPLETED", "STARTUP_FAILURE"), "failure"), (("COMPLETED", "ACTION_REQUIRED"), "failure"),
                 (("COMPLETED", "STALE"), "failure"), (("COMPLETED", "NEUTRAL"), "neutral"),
                 (("COMPLETED", "SKIPPED"), "neutral"), (("IN_PROGRESS", None), "pending"),
                 (("QUEUED", None), "pending"), (("WAITING", None), "pending")]
        for (status, conclusion), want in cases:
            doc = self.collect([pr(1, contexts=[cr("ci/build", status, conclusion), cr("ci/lint")])], protection=self.REQ)
            self.assertEqual(self.checks(doc)[0]["ci/build"], want, (status, conclusion))

    def test_a_required_context_that_never_reported_is_missing(self):
        doc = self.collect([pr(1, contexts=[cr("ci/build")])], protection=self.REQ)
        self.assertEqual(self.checks(doc)[0], {"ci/build": "success", "ci/lint": "missing"})

    def test_non_required_contexts_are_ignored_even_when_they_never_resolve(self):
        # What a merged PR really looks like: tide stays pending, optional checks are queued/skipped.
        nodes = [cr("ci/build"), cr("ci/lint"), sc("tide", "PENDING"), cr("optional-scan", "QUEUED", None),
                 cr("review-bot", "COMPLETED", "SKIPPED")]
        doc = self.collect([pr(1, contexts=nodes, rollup="PENDING")], protection=self.REQ)
        got, p = self.checks(doc)
        self.assertEqual(got, {"ci/build": "success", "ci/lint": "success"})
        self.assertEqual(p["status_check_state"], "PENDING")  # recorded for debugging, not judged
        self.assertIs(p["checks_complete"], True)

    def test_duplicate_contexts_keep_the_worst_result(self):
        doc = self.collect([pr(1, contexts=[cr("ci/build"), cr("ci/build", "COMPLETED", "FAILURE"), cr("ci/lint")])],
                           protection=self.REQ)
        self.assertEqual(self.checks(doc)[0]["ci/build"], "failure")

    def test_a_pr_with_no_rollup_at_all_has_every_required_check_missing(self):
        doc = self.collect([pr(1, no_rollup=True)], protection=self.REQ)
        got, p = self.checks(doc)
        self.assertEqual(got, {"ci/build": "missing", "ci/lint": "missing"})
        self.assertEqual(p["status_check_state"], "NONE")
        self.assertIs(p["checks_complete"], True)

    def test_contexts_beyond_the_first_page_are_followed(self):
        node = pr(1, contexts=[cr("ci/build")], more_contexts=True, cursor="c1", oid="oidA")
        pages = {"oidA.c1": ctx_page([cr("ci/lint")])}
        doc = self.collect([node], protection=self.REQ, pages=pages)
        got, p = self.checks(doc)
        self.assertEqual(got, {"ci/build": "success", "ci/lint": "success"})
        self.assertIs(p["checks_complete"], True)

    def test_paging_stops_at_the_bound_and_the_pr_is_incomplete_not_passed(self):
        node = pr(1, contexts=[cr("ci/build")], more_contexts=True, cursor="c1", oid="oidA")
        pages = {"oidA.c1": ctx_page([sc("x1", "SUCCESS")], True, "c2"), "oidA.c2": ctx_page([cr("ci/lint")], True, "c3")}
        doc = self.collect([node], protection=self.REQ, pages=pages, extra_env={"RSC_CONTEXT_PAGES_MAX": "1"})
        got, p = self.checks(doc)
        self.assertIs(p["checks_complete"], False)
        self.assertEqual(got["ci/lint"], "missing")  # on a page we did not read: the flag says so

    def test_a_failing_follow_up_page_is_a_collection_error(self):
        node = pr(1, contexts=[cr("ci/build")], more_contexts=True, cursor="c1", oid="oidMissing")
        doc = self.collect([node], protection=self.REQ)
        self.assertIsNone(doc)
        self.assertEqual(json.loads((self.c.out / AR2 / "manifest.json").read_text())["targets"][0]["status"], "error")

    def test_only_prs_with_more_contexts_trigger_follow_up_pages(self):
        a = pr(1, contexts=[cr("ci/build"), cr("ci/lint")])
        b = pr(2, contexts=[cr("ci/build")], more_contexts=True, cursor="c1", oid="oidB")
        doc = self.collect([a, b], protection=self.REQ, pages={"oidB.c1": ctx_page([cr("ci/lint")])})
        self.assertEqual(self.checks(doc, 1)[0], {"ci/build": "success", "ci/lint": "success"})
        self.assertEqual(self.checks(doc, 2)[0], {"ci/build": "success", "ci/lint": "success"})


def status_body(statuses, total=None):
    return {"total_count": len(statuses) if total is None else total,
            "statuses": [{"context": c, "state": st} for c, st in statuses]}


class PrivateRepositoryChecks(unittest.TestCase):
    """A fine-grained token cannot read check runs in a private repository: fall back to commit statuses."""

    REQ = {"required_status_checks": {"contexts": ["ci/prow/a", "ci/prow/b"]}}

    def collect(self, nodes, statuses=None, protection=REQ, extra=None):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-priv", page(nodes))
        (c.fake_dir / "protection-ok-priv.json").write_text(json.dumps(protection))
        for oid, body in (statuses or {}).items():
            (c.fake_dir / f"status.{oid}.json").write_text(json.dumps(body))
        res = c.run_collector(AR2, ["o/ok-priv"], extra_env=extra)
        self.c, self.res = c, res
        path = c.out / AR2 / "ok-priv.json"
        return json.loads(path.read_text()) if path.is_file() else None

    def test_required_statuses_are_judged_from_the_rest_fallback(self):
        doc = self.collect([pr(1, oid="o1", rollup="PENDING")],
                           {"o1": status_body([("ci/prow/a", "success"), ("ci/prow/b", "failure"), ("tide", "pending")])})
        p = doc["pull_requests"][0]
        self.assertIs(doc["check_runs_readable"], False)
        self.assertEqual({x["context"]: x["result"] for x in p["required_checks"]}, {"ci/prow/a": "success", "ci/prow/b": "failure"})
        self.assertIs(p["checks_complete"], True)
        self.assertEqual(p["status_check_state"], "PENDING")  # the overall state still comes from GraphQL

    def test_a_required_context_not_among_the_statuses_is_unknown_and_the_pr_incomplete(self):
        doc = self.collect([pr(1, oid="o1")], {"o1": status_body([("ci/prow/a", "success")])})
        p = doc["pull_requests"][0]
        self.assertEqual({x["context"]: x["result"] for x in p["required_checks"]}, {"ci/prow/a": "success", "ci/prow/b": "unknown"})
        self.assertIs(p["checks_complete"], False)

    def test_every_status_state_maps(self):
        for state, want in (("success", "success"), ("failure", "failure"), ("error", "failure"), ("pending", "pending")):
            doc = self.collect([pr(1, oid="o1")], {"o1": status_body([("ci/prow/a", state), ("ci/prow/b", "success")])})
            self.assertEqual(doc["pull_requests"][0]["required_checks"][0]["result"], want, state)

    def test_more_statuses_than_one_page_makes_the_pr_incomplete(self):
        doc = self.collect([pr(1, oid="o1")], {"o1": status_body([("ci/prow/a", "success"), ("ci/prow/b", "success")], total=150)})
        self.assertIs(doc["pull_requests"][0]["checks_complete"], False)

    def test_a_failing_status_call_is_a_collection_error(self):
        doc = self.collect([pr(1, oid="o-no-status-file")])
        self.assertIsNone(doc)
        self.assertEqual(json.loads((self.c.out / AR2 / "manifest.json").read_text())["targets"][0]["status"], "error")

    def test_only_prs_merged_on_the_day_are_looked_up(self):
        old = DAY_BEFORE
        doc = self.collect([pr(1, oid="o1"), pr(2, oid="o-old", at=old)],
                           {"o1": status_body([("ci/prow/a", "success"), ("ci/prow/b", "success")])})
        self.assertEqual([p["number"] for p in doc["pull_requests"]], [1])

    def test_public_repositories_keep_reading_check_runs(self):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-pub", page([pr(1, contexts=[cr("ci/prow/a"), cr("ci/prow/b")])]))
        (c.fake_dir / "protection-ok-pub.json").write_text(json.dumps(self.REQ))
        c.run_collector(AR2, ["o/ok-pub"])
        doc = json.loads((c.out / AR2 / "ok-pub.json").read_text())
        self.assertIs(doc["check_runs_readable"], True)

    def test_an_unrelated_graphql_failure_is_still_an_error(self):
        # "denied" repos fail with a different message and must not trigger the fallback.
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        res = c.run_collector(AR2, ["o/denied-x"])
        self.assertNotEqual(res.returncode, 0)


class AutomationExemption(unittest.TestCase):
    """The facts the collector reports for the documented automation exemption."""

    LABELS = ("lgtm", "approved")

    def collect(self, node, tide=BOT_TIDE, config=None):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([node]))
        (c.fake_dir / "prow").mkdir()
        (c.fake_dir / "prow" / "o__ok-x___prowconfig.yaml").write_text(tide)
        cfg = c.fake_dir / "automation.yaml"
        cfg.write_text(config or AUTOMATION_YAML)
        res = c.run_collector(AR2, ["o/ok-x"], extra_env={"RSC_AUTOMATION_CONFIG": str(cfg)})
        self.assertEqual(res.returncode, 0, res.stderr)
        doc = json.loads((c.out / AR2 / "ok-x.json").read_text())
        return doc["pull_requests"][0], doc["summary"]

    def good(self, **kw):
        base = dict(author="dep-bot", author_bot=True, labels=self.LABELS, commits=[("dep-bot[bot]", True)])
        base.update(kw)
        return pr(1, **base)

    FACTS = ("author_allowlisted", "gate_defined", "gate_labels_present", "merged_by_merge_automation", "all_commits_by_author")

    def test_all_five_facts_hold(self):
        p, summary = self.collect(self.good())
        self.assertEqual({k: p["automated_change"][k] for k in self.FACTS}, {k: True for k in self.FACTS})
        self.assertEqual((summary["merged"], summary["automation_exempt"]), (1, 1))
        self.assertIs(summary["exemption_approved"], False)  # nobody has approved the exemption yet

    def test_each_fact_can_fail_independently(self):
        cases = {
            "author_allowlisted": self.good(author="other-bot", commits=[("other-bot[bot]", True)]),
            "gate_defined": self.good(),  # handled below with a Tide config lacking the author
            "gate_labels_present": self.good(labels=("lgtm",)),
            "merged_by_merge_automation": self.good(merged_by="dana"),
            "all_commits_by_author": self.good(commits=[("dep-bot[bot]", True), ("alice", True)]),
        }
        for fact, node in cases.items():
            tide = TIDE if fact == "gate_defined" else BOT_TIDE
            p, summary = self.collect(node, tide=tide)
            self.assertIs(p["automated_change"][fact], False, fact)
            self.assertEqual(summary["automation_exempt"], 0, fact)

    def test_unsigned_commit_fails_the_commit_fact(self):
        p, _ = self.collect(self.good(commits=[("dep-bot[bot]", False)]))
        self.assertIs(p["automated_change"]["all_commits_by_author"], False)

    def test_commit_with_no_linked_account_fails_the_commit_fact(self):
        p, _ = self.collect(self.good(commits=[(None, True)]))
        self.assertIs(p["automated_change"]["all_commits_by_author"], False)

    def test_more_commits_than_were_fetched_fails_the_commit_fact(self):
        node = self.good()
        node["allCommits"]["totalCount"] = 150
        p, _ = self.collect(node)
        self.assertIs(p["automated_change"]["all_commits_by_author"], False)

    def test_no_commits_fails_the_commit_fact(self):
        p, _ = self.collect(self.good(commits=[]))
        self.assertIs(p["automated_change"]["all_commits_by_author"], False)

    def test_bot_suffix_is_ignored_when_comparing_logins(self):
        p, _ = self.collect(self.good(author="dep-bot", commits=[("dep-bot", True)]))
        self.assertIs(p["automated_change"]["all_commits_by_author"], True)

    def test_automation_identities_never_count_as_approvers(self):
        # A machine *user* account (not a GitHub Bot) commenting /lgtm on someone else's PR.
        node = pr(1, author="alice", labels=self.LABELS, comments=[("dep-bot", "/lgtm")])
        p, _ = self.collect(node)
        self.assertEqual(p["approved_by"], [])

    def test_a_real_person_still_approves_a_bots_pr(self):
        p, _ = self.collect(self.good(comments=[("carol", "/lgtm")]))
        self.assertEqual(p["approved_by"], ["carol"])

    def test_invalid_config_is_an_error(self):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([self.good()]))
        cfg = c.fake_dir / "bad.yaml"
        cfg.write_text("change-authors:\n  - login: dep-bot\n")  # no rationale
        res = c.run_collector(AR2, ["o/ok-x"], extra_env={"RSC_AUTOMATION_CONFIG": str(cfg)})
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(json.loads((c.out / AR2 / "manifest.json").read_text())["targets"][0]["status"], "error")

    def test_exemption_is_approved_only_when_every_author_has_an_approver(self):
        approved = AUTOMATION_YAML.replace("approved-by: []", "approved-by: [carol]")
        _, summary = self.collect(self.good(), config=approved)
        self.assertIs(summary["exemption_approved"], True)

    def test_shipped_config_is_valid_and_documents_every_entry(self):
        import automation_config
        cfg = automation_config.load()
        self.assertTrue(cfg["change_authors"] and cfg["merge_automation"])
        self.assertIs(cfg["exemption_approved"], False)


AUTOMATION_YAML = """change-authors:
  - login: dep-bot
    rationale: test bot
    approved-by: []
merge-automation:
  - login: openshift-merge-bot
    rationale: test merge bot
"""
