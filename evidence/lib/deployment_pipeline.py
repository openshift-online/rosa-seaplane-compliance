#!/usr/bin/env python3
"""Collect deployment evidence for one deployment pipeline.

    deployment_pipeline.py --ar <AR id> --target <pipeline name> --profile <read-only profile>
                           --region us-east-1 --repository owner/name [--branch main]
                           --date YYYY-MM-DD [--lag-minutes 120]

EVENT collector for ONE UTC day, the half-open [D 00:00:00Z, D+1 00:00:00Z) (lib/day_window.py).
Answers "was every change merged to the default branch on that day deployed to the
environment by the automated pipeline, did the deployment succeed, and is the
environment running the head of the branch?" from two sources:

  * the pipeline's execution history (AWS CodePipeline: status, start, trigger and the
    commit each execution built), plus the applied-commit record the pipeline's Apply
    step exports (APPLIED and APPLIED_SHA, which the build itself asserts equals the
    source commit);
  * the repository's merged pull requests and the head of the branch (GitHub).

A merged change counts as deployed when a SUCCEEDED execution applied that commit, or
applied a later commit that contains it (the pipelines run in superseded mode, so a
newer run can overtake an older waiting one). The later commit is checked with GitHub's
compare API, for at most MAX_CANDIDATES executions per change.

Read-only: list and get calls only, through the read-only profile; GitHub reads only.
Evidence is normalized (schemas/deployment-pipeline.cue). Never recorded: commit
messages, author names or e-mail addresses, account IDs or ARNs.

The executions read are those from the start of the day up to now (a change merged late on
the day is deployed after it), and lag, recovery and the state of the head are judged as of
the collection time. The head and the latest run are the present, not the day: a backfill
does not judge them (config/history/ar-basis.yaml, state_rules). A day with no merge is a
complete, empty collection and passes.

Anything that stops the collection from covering the day (history that does not
reach back to its start, a page cap hit, an applied record or a comparison that failed)
makes collection.complete false, which the policy denies as "could not tell". Failing to
read the pipeline's executions or the repository at all is an error and writes no
evidence.

Limits it cannot get around are recorded in collection.limitations (see LIMITATIONS and
evidence/known-gaps.yaml).
"""
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

from aws_cli import Aws, AwsError, mask, utc_iso
from day_window import DayError, day_for

EXECUTIONS_PER_PAGE = 100
MAX_EXECUTION_PAGES = 30
MAX_PR_PAGES = 20
MAX_CANDIDATES = 3
MAX_ACTION_LOOKUPS = 300
MAX_EXECUTIONS_KEPT = 200
SOURCE = "codepipeline-executions+github"
TARGET_TYPE = "deployment-pipeline"
LIMITATIONS = [
    "only the deployment pipelines of the selected environment are examined; a change deployed some other way is not seen",
    "it shows that the pipeline applied each merged change and finished successfully, not that the deployed system is healthy afterwards (the health of the deployed applications is checked separately, by RSC.CMT.CTRL03.AR02)",
    "a run that failed and was later followed by a successful run of the same or a later commit is recorded as recovered and is not a violation by itself",
    "the pipelines run in superseded mode, so a change can be deployed by a later run that contains it; this is checked with the commit history, for a bounded number of later runs",
    "commits pushed straight to the branch are not pull requests, so only the head of the branch is checked for them",
    "the optional pre-merge end-to-end test is a separate signal and is not measured here",
]
THROTTLE_PAUSE = 2.0

STATUS = {
    "Succeeded": "succeeded", "Failed": "failed", "InProgress": "in-progress",
    "Stopped": "stopped", "Stopping": "stopped", "Cancelled": "stopped", "Superseded": "superseded",
}
TRIGGER = {"WebhookV2": "webhook", "Webhook": "webhook", "StartPipelineExecution": "manual",
           "CreatePipeline": "other", "CloudWatchEvent": "other", "PutActionRevision": "other"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class CollectionError(RuntimeError):
    """The pipeline's executions or the repository could not be read: no evidence can be written."""


class GhError(RuntimeError):
    pass


class Gh:
    """Thin wrapper over `gh api`: JSON in, JSON out, a few retries on 5xx."""

    def __init__(self, run=subprocess.run, sleep=time.sleep, retries=3):
        self._run, self._sleep, self.retries = run, sleep, retries

    def api(self, *args: str):
        cmd = ["gh", "api", *args]
        for attempt in range(self.retries + 1):
            res = self._run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                return json.loads(res.stdout) if res.stdout.strip() else {}
            err = (res.stderr or res.stdout or "").strip()
            if re.search(r"HTTP 5[0-9][0-9]", err) and attempt < self.retries:
                self._sleep(THROTTLE_PAUSE * (attempt + 1))
                continue
            raise GhError(mask(err.splitlines()[-1] if err else "gh api failed")[:200])
        raise GhError("gh api failed")  # pragma: no cover

    def graphql(self, query: str, **fields):
        args = ["graphql", "-f", f"query={query}"]
        for k, v in fields.items():
            if v is not None:
                args += ["-f", f"{k}={v}"]
        out = self.api(*args)
        if out.get("errors") or (out.get("data") or {}).get("repository") is None:
            raise GhError("GraphQL returned errors or no repository data")
        return out


def parse_time(value) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_status(raw) -> str:
    return STATUS.get(raw, "unknown")


def normalize_trigger(raw) -> str:
    return TRIGGER.get(raw, "other")


# --- reading the sources --------------------------------------------------------

def read_executions(aws: Aws, pipeline: str, region: str, window_start: datetime) -> tuple:
    """(execution summaries newest first, problems). Pages until history reaches the start of the day."""
    out, problems, token, pages = [], [], None, 0
    while True:
        args = ["codepipeline", "list-pipeline-executions", "--pipeline-name", pipeline, "--region", region,
                "--max-results", str(EXECUTIONS_PER_PAGE)]
        if token:
            args += ["--next-token", token]
        try:
            page = aws.call(*args, region=region)
        except AwsError as e:
            if pages == 0:
                raise CollectionError(f"cannot read the executions of {pipeline}: {e}")
            problems.append("part of the execution history could not be read")
            return out, problems
        pages += 1
        out += page.get("pipelineExecutionSummaries", [])
        token = page.get("nextToken")
        oldest = min((parse_time(e["startTime"]) for e in page.get("pipelineExecutionSummaries", [])), default=None)
        if not token or (oldest is not None and oldest < window_start):
            return out, problems
        if pages >= MAX_EXECUTION_PAGES:
            problems.append(f"the execution history is longer than {MAX_EXECUTION_PAGES} pages, so the start of the window was not reached")
            return out, problems


def applied_record(aws: Aws, pipeline: str, execution_id: str, region: str) -> tuple:
    """(applied, applied_sha) exported by the pipeline's Apply step, or (None, None) when absent."""
    page = aws.call("codepipeline", "list-action-executions", "--pipeline-name", pipeline,
                    "--filter", f"pipelineExecutionId={execution_id}", "--region", region, region=region)
    applied, sha = None, None
    for detail in page.get("actionExecutionDetails", []):
        variables = (detail.get("output") or {}).get("outputVariables") or {}
        if "APPLIED" in variables or "APPLIED_SHA" in variables:
            if "APPLIED" in variables:
                applied = str(variables["APPLIED"]).lower() == "true"
            value = (variables.get("APPLIED_SHA") or "").lower()
            sha = value if SHA_RE.match(value) else None
            break
    return applied, sha


def read_merged_changes(gh: Gh, repo: str, branch: str, window_start: datetime, window_end: datetime) -> tuple:
    """([{sha, merged_at}] oldest first, problems): pull requests merged into the branch in
    [window_start, window_end).

    Pages are ordered by update time (GitHub has no merge-time sort), so paging stops at the
    first page that reaches pull requests last updated before the day began; a PR merged on
    the day was updated on or after its start.
    """
    owner, name = repo.split("/")
    query = """query($owner: String!, $name: String!, $base: String!, $after: String) {
      repository(owner: $owner, name: $name) {
        pullRequests(states: MERGED, baseRefName: $base, first: 50, after: $after,
                     orderBy: {field: UPDATED_AT, direction: DESC}) {
          pageInfo { hasNextPage endCursor }
          nodes { mergedAt updatedAt mergeCommit { oid } }
        }
      }
    }"""
    changes, problems, after = [], [], None
    for page_no in range(1, MAX_PR_PAGES + 1):
        data = gh.graphql(query, owner=owner, name=name, base=branch, after=after)
        prs = data["data"]["repository"]["pullRequests"]
        nodes = prs["nodes"]
        for n in nodes:
            merged = n.get("mergedAt")
            sha = ((n.get("mergeCommit") or {}).get("oid") or "").lower()
            if merged and window_start <= parse_time(merged) < window_end and SHA_RE.match(sha):
                changes.append({"sha": sha, "merged_at": utc_iso(merged)})
        updated = [parse_time(n["updatedAt"]) for n in nodes if n.get("updatedAt")]
        if not prs["pageInfo"]["hasNextPage"] or (updated and min(updated) < window_start):
            break
        if page_no == MAX_PR_PAGES:
            problems.append(f"more than {MAX_PR_PAGES} pages of merged pull requests, so the day was not fully read")
            break
        after = prs["pageInfo"]["endCursor"]
    changes.sort(key=lambda c: c["merged_at"])
    seen, unique = set(), []
    for c in changes:
        if c["sha"] not in seen:
            seen.add(c["sha"])
            unique.append(c)
    return unique, problems


def read_head(gh: Gh, repo: str, branch: str) -> dict:
    data = gh.api(f"repos/{repo}/commits/{branch}")
    sha = (data.get("sha") or "").lower()
    when = ((data.get("commit") or {}).get("committer") or {}).get("date")
    if not SHA_RE.match(sha) or not when:
        raise CollectionError(f"cannot read the head of {branch}")
    return {"sha": sha, "committed_at": utc_iso(when)}


# --- the assessment (pure) ---------------------------------------------------------

class Containment:
    """Does commit `later` contain commit `earlier`? Asked of GitHub's compare API, cached."""

    def __init__(self, gh: Gh, repo: str, workers: int = None):
        self.gh, self.repo, self.cache, self.calls = gh, repo, {}, 0
        self.workers = int(os.environ.get("RSC_COMPARE_WORKERS", "8")) if workers is None else workers

    def prefetch(self, pairs) -> None:
        """Ask for many (earlier, later) pairs at once: they are independent reads, and a
        month of changes would otherwise take minutes one by one. A pair that fails here is
        simply not cached, so asking for it later fails there and marks the evidence
        incomplete."""
        todo = sorted(p for p in set(pairs) if p[0] != p[1] and p not in self.cache)

        def one(pair):
            try:
                return pair, self.ask(*pair)
            except GhError:
                return pair, None

        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as pool:
            for pair, verdict in pool.map(one, todo):
                if verdict is not None:
                    self.cache[pair] = verdict
                    self.calls += 1

    def ask(self, earlier: str, later: str) -> bool:
        status = self.gh.api(f"repos/{self.repo}/compare/{earlier}...{later}", "--jq", "{status: .status}").get("status")
        return status in ("ahead", "identical")

    def __call__(self, earlier: str, later: str) -> bool:
        if earlier == later:
            return True
        key = (earlier, later)
        if key not in self.cache:
            self.cache[key] = self.ask(earlier, later)
            self.calls += 1
        return self.cache[key]


def applied_commit(e: dict):
    """The commit a succeeded execution applied, or None.

    The pipeline's Apply step exports APPLIED and APPLIED_SHA, and the build fails unless
    APPLIED_SHA equals the source commit. If the record is absent altogether (older runs,
    or one that could not be read), a succeeded run is taken to have applied its source
    commit, since the build asserts exactly that; a record that says otherwise is not.
    """
    if e["status"] != "succeeded":
        return None
    if e["applied"] is True and e["applied_sha"]:
        return e["applied_sha"]
    if e["applied"] is None:
        return e["commit"]
    return None


def assess(commit_sha: str, since: datetime, executions: list, contains) -> dict:
    """How was one commit deployed? {deployed, by, status}.

    `executions` are the normalized executions, newest first. deployed is True when a
    succeeded execution applied the commit itself, or applied a later commit that contains
    it. `status` is the status of the execution that settled it (succeeded), or the status
    of the earliest execution that tried, or "none" when nothing ran after the merge.
    A comparison that fails raises GhError; the caller marks the collection incomplete.
    """
    succeeded = [(e, applied_commit(e)) for e in executions]
    succeeded = [(e, sha) for e, sha in succeeded if sha]
    for e, sha in succeeded:
        if sha == commit_sha:
            return {"deployed": True, "by": "applied-itself", "status": "succeeded"}
    later = sorted(((e, sha) for e, sha in succeeded if parse_time(e["started"]) >= since), key=lambda x: x[0]["started"])
    for e, sha in later[:MAX_CANDIDATES]:
        if contains(commit_sha, sha):
            return {"deployed": True, "by": "contained-in-later", "status": "succeeded"}
    attempts = sorted((e for e in executions if parse_time(e["started"]) >= since and e["status"] != "superseded"),
                      key=lambda e: e["started"])
    return {"deployed": False, "by": "none", "status": attempts[0]["status"] if attempts else "none"}


def first_candidates(executions: list, items: list, containment) -> None:
    """Warm the comparison cache with the one pair most commits need: the commit and the
    first successful run after it. Anything else is asked for lazily."""
    prefetch = getattr(containment, "prefetch", None)
    if prefetch is None:
        return
    pairs = []
    for sha, since in items:
        succeeded = [(e, applied_commit(e)) for e in executions]
        succeeded = [(e, a) for e, a in succeeded if a]
        if any(a == sha for _, a in succeeded):
            continue
        later = sorted(((e, a) for e, a in succeeded if parse_time(e["started"]) >= since), key=lambda x: x[0]["started"])
        if later:
            pairs.append((sha, later[0][1]))
    prefetch(pairs)


def mark_recovered(executions: list, contains) -> None:
    """A failed or stopped execution is `recovered` when a successful run deployed its commit
    (or a later commit that contains it); null when that could not be established."""
    for e in executions:
        if e["status"] not in ("failed", "stopped") or not e["commit"]:
            continue
        try:
            e["recovered"] = assess(e["commit"], parse_time(e["started"]), executions, contains)["deployed"]
        except GhError:
            e["recovered"] = None


def build_evidence(ar: str, target: str, repo: str, branch: str, lag_minutes: int, day: dict,
                   now: datetime, regions: list, executions: list, head: dict, changes: list,
                   problems: list, containment) -> dict:
    problems = list(problems)
    merged = []

    def settle(sha, since):
        try:
            return assess(sha, since, executions, containment)
        except GhError:
            problems.append("a merged change could not be compared with a deployed commit")
            return {"deployed": False, "by": "unknown", "status": "none"}

    first_candidates(executions, [(c["sha"], parse_time(c["merged_at"])) for c in changes]
                     + [(head["sha"], parse_time(head["committed_at"]))]
                     + [(e["commit"], parse_time(e["started"])) for e in executions if e["status"] in ("failed", "stopped") and e["commit"]],
                     containment)
    for c in changes:
        res = settle(c["sha"], parse_time(c["merged_at"]))
        merged.append({"sha": c["sha"], "merged_at": c["merged_at"], "deployed": res["deployed"],
                       "deployed_by": res["by"], "deployed_by_execution_status": res["status"]})
    head_res = settle(head["sha"], parse_time(head["committed_at"]))
    mark_recovered(executions, containment)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    kept = executions[:MAX_EXECUTIONS_KEPT]
    return {
        "assessment_requirement": ar,
        "generated_at": stamp,
        "target": target,
        "target_type": TARGET_TYPE,
        "repository": repo,
        "branch": branch,
        "covers_date": day["covers_date"],
        "window": {"start": day["start"], "end": day["end"]},
        "collection": {
            "complete": not problems,
            "source": SOURCE,
            "allowed_lag_minutes": lag_minutes,
            "regions": regions,
            "executions_read": len(executions),
            "changes_checked": len(changes),
            "comparisons": getattr(containment, "calls", 0),
            "problems": sorted(set(problems)),
            "limitations": LIMITATIONS,
            "generated_at": stamp,
        },
        "head": {"sha": head["sha"], "committed_at": head["committed_at"], "deployed": head_res["deployed"],
                 "deployed_by": head_res["by"], "deployed_by_execution_status": head_res["status"]},
        "latest_execution": kept[0] if kept else None,
        "executions": kept,
        "merged_commits": merged,
    }


def normalize_execution(summary: dict) -> dict:
    sources = summary.get("sourceRevisions") or [{}]
    commit = (sources[0].get("revisionId") or "").lower()
    status = normalize_status(summary.get("status"))
    terminal = status in ("succeeded", "failed", "stopped", "superseded")
    return {
        "commit": commit if SHA_RE.match(commit) else None,
        "status": status,
        "trigger": normalize_trigger((summary.get("trigger") or {}).get("triggerType")),
        "started": utc_iso(summary["startTime"]),
        "finished": utc_iso(summary["lastUpdateTime"]) if terminal and summary.get("lastUpdateTime") else None,
        "applied": None,
        "applied_sha": None,
        "_id": summary.get("pipelineExecutionId"),
    }


def collect(aws: Aws, gh: Gh, ar: str, target: str, repo: str, branch: str, lag_minutes: int,
            day: dict, regions: list, now: datetime = None) -> dict:
    now = now or datetime.now(timezone.utc)
    window_start, window_end = parse_time(day["start"]), parse_time(day["end"])
    region = regions[0]
    summaries, problems = read_executions(aws, target, region, window_start)
    executions = [normalize_execution(s) for s in summaries if parse_time(s["startTime"]) >= window_start]
    lookups = 0
    for e in executions:
        if e["status"] in ("succeeded", "failed", "stopped") and e["_id"]:
            if lookups >= MAX_ACTION_LOOKUPS:
                problems.append("too many executions to read every applied record")
                break
            lookups += 1
            try:
                e["applied"], e["applied_sha"] = applied_record(aws, target, e["_id"], region)
            except AwsError:
                problems.append("the applied record of an execution could not be read")
    for e in executions:
        e.pop("_id", None)
    executions.sort(key=lambda e: e["started"], reverse=True)
    try:
        head = read_head(gh, repo, branch)
        changes, pr_problems = read_merged_changes(gh, repo, branch, window_start, window_end)
    except GhError as e:
        raise CollectionError(f"cannot read {repo}: {e}")
    return build_evidence(ar, target, repo, branch, lag_minutes, day, now, [region], executions,
                          head, changes, problems + pr_problems, Containment(gh, repo))


def default_branch(gh: Gh, repo: str) -> str:
    return gh.api(f"repos/{repo}", "--jq", "{b: .default_branch}")["b"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ar", required=True)
    ap.add_argument("--target", required=True, help="the deployment pipeline's name")
    ap.add_argument("--profile", required=True, help="the read-only profile of the account that owns the pipeline")
    ap.add_argument("--region", required=True)
    ap.add_argument("--repository", required=True, help="owner/name of the repository whose branch is deployed")
    ap.add_argument("--branch", default="", help="empty means the repository's default branch")
    ap.add_argument("--lag-minutes", type=int, default=120)
    ap.add_argument("--date", required=True, help="the UTC day to cover, YYYY-MM-DD (already checked by the caller)")
    args = ap.parse_args()
    interval = float(os.environ.get("RSC_PIPELINE_INTERVAL", "0.2"))
    try:
        gh = Gh()
        branch = args.branch or default_branch(gh, args.repository)
        evidence = collect(Aws(args.profile, interval=interval), gh, args.ar, args.target, args.repository,
                           branch, args.lag_minutes, day_for(args.date), [args.region])
        print(json.dumps(evidence, indent=2))
    except (CollectionError, AwsError, GhError, DayError) as e:
        sys.exit(f"ERROR: {mask(str(e))}")


if __name__ == "__main__":
    main()
