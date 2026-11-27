#!/usr/bin/env python3
"""Collect deployed-workload health evidence for one cluster.

    argocd_health.py --ar <AR id> --target <cluster> --profile <read-only profile>
                     --region us-east-1 [--lookback-minutes 30] [--freshness-seconds 300]
                     [--step-seconds 60]

Answers "after deployment, are the applications that make up the environment synchronized
and healthy, and has any of them stayed unhealthy for a sustained period?" from the
platform's own metrics: the deployment tool's application state is scraped into
Prometheus and forwarded to Thanos behind an API gateway in the regional account. The
gateway's resource policy lets principals of that account run read queries, and the
read-only role is one. Requests are SigV4-signed GETs (evidence/lib/sigv4.py): nothing is
written, and no cluster access is needed. The gateway is found by name (it contains
"rhobs"), never by a stored ID.

The metric is `argocd_app_info{cluster, name, project, sync_status, health_status}` (an
info gauge: its value is always 1, the state is in the labels).

THE RULES (exactly what the evidence says, and what the policy denies):

  A step is a timestamp of the lookback window, one every `step` seconds. At a step an
  application shows one or more states (two can overlap for a moment while a state change
  propagates through the metrics pipeline). A step is classified:
    ok           every state shown is synced and (healthy or suspended)
    bad          any state shown is out-of-sync or unknown-sync, or degraded, missing or
                 unknown health (the conservative choice when states overlap)
    progressing  no bad state and at least one progressing (still settling)
  Over the whole window, for an application observed at (nearly) every step:
    unhealthy_for_window          no step was ok and at least one was bad
    stuck_progressing_for_window  no step was ok or bad: it was progressing the whole window
  Anything that was ok at least once in the window is tolerated: a rollout that settled, or
  a blip that cleared. An application seen at fewer than OBSERVED_MIN of the steps (new,
  renamed, or the metrics have gaps) is not judged: it is recorded as partially_observed.

INCOMPLETE rather than a pass (collection.complete = false, which the policy denies as
"could not tell") whenever the metrics cannot be trusted: a query fails or returns an
error, the newest sample is older than the freshness limit, the cluster reports no
applications, or the metrics have gaps across the window. Failing to find the gateway or
to obtain credentials at all is an error and writes no evidence.

Never recorded: account IDs, the gateway's ID or URL, ARNs, or the deployment tool's
cluster URL. Application names are platform component names.
"""
import argparse
import json
import math
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

from aws_cli import Aws, AwsError, mask, utc_iso
from sigv4 import sign_get

METRIC = "argocd_app_info"
SOURCE = "deployment-metrics"
TARGET_TYPE = "deployment-cluster"
OBSERVED_MIN = 0.9  # an application must be seen at >= 90% of the steps to be judged
WINDOW_COVERAGE_MIN = 0.9  # and the metrics themselves must have samples at >= 90% of them
CLUSTER_RE = re.compile(r"[A-Za-z0-9_-]{1,63}")
LIMITATIONS = [
    "It reads the state the deployment tool reports through the platform's metrics, so it depends on that metrics pipeline and on the API gateway's resource policy; if either changes, collection becomes incomplete, never a pass.",
    "Only applications the deployment tool itself reports are examined: workloads it does not manage, and anything inside an application's pods, are not seen.",
    "An application is judged unhealthy only if it stayed so for the whole lookback window. A break that began inside the window, or a short outage that ended before the run, is not flagged.",
    "An application seen at fewer than 90% of the window's steps (new, renamed, or with metric gaps) is recorded as partially observed and is not judged.",
    "Metrics older than the freshness limit, an empty result for a cluster, or gaps across the window make the collection incomplete, never a pass.",
    "The regional metrics store only holds clusters that forward their metrics to it.",
    "The state is a point-in-time reading of the last lookback window; a daily run does not see what happened between runs.",
]

BAD_HEALTH = {"degraded", "missing", "unknown"}
BAD_SYNC = {"out-of-sync", "unknown"}


class CollectionError(RuntimeError):
    pass


class MetricsError(RuntimeError):
    """A query that did not give a usable answer; never contains a URL."""


# --- state normalization ------------------------------------------------------

def norm_sync(raw) -> str:
    return {"synced": "synced", "outofsync": "out-of-sync"}.get(str(raw or "").lower(), "unknown")


def norm_health(raw) -> str:
    value = str(raw or "").lower()
    return value if value in {"healthy", "progressing", "degraded", "missing", "suspended"} else "unknown"


def step_class(states: set) -> str:
    """Classify one step from the (sync, health) states shown at it (see the module doc)."""
    if any(sync in BAD_SYNC or health in BAD_HEALTH for sync, health in states):
        return "bad"
    if all(sync == "synced" and health in {"healthy", "suspended"} for sync, health in states):
        return "ok"
    return "progressing"


# --- metrics client -----------------------------------------------------------

class Metrics:
    """Signed read queries against the gateway's Prometheus-compatible API."""

    def __init__(self, base_url: str, credentials: dict, region: str, timeout: float = 30.0, urlopen=urllib.request.urlopen):
        self.base_url, self.credentials, self.region = base_url, credentials, region
        self.timeout, self._urlopen = timeout, urlopen

    def _get(self, path: str, params: dict) -> dict:
        url, headers = sign_get(self.base_url, path, params, self.credentials, self.region, "execute-api")
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self._urlopen(request, timeout=self.timeout) as response:
                status, body = response.status, response.read()
        except urllib.error.HTTPError as e:
            code = e.code
            e.close()
            raise MetricsError(f"the metrics API answered HTTP {code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise MetricsError(f"the metrics API could not be reached ({type(e).__name__})") from None
        if status != 200:
            raise MetricsError(f"the metrics API answered HTTP {status}")
        try:
            doc = json.loads(body)
        except ValueError:
            raise MetricsError("the metrics API answered something that is not JSON") from None
        if doc.get("status") != "success":
            raise MetricsError(f"the metrics query failed ({str(doc.get('errorType') or doc.get('status'))[:40]})")
        return doc["data"]

    def instant(self, promql: str, at: float) -> list:
        return self._get("/api/v1/query", {"query": promql, "time": f"{at:.0f}"}).get("result") or []

    def range(self, promql: str, start: float, end: float, step: int) -> list:
        return self._get("/api/v1/query_range", {"query": promql, "start": f"{start:.0f}", "end": f"{end:.0f}",
                                                 "step": str(step)}).get("result") or []


# --- discovery of the gateway and the credentials -----------------------------

def discover_base_url(aws: Aws, region: str) -> str:
    """The gateway is found by name (contains "rhobs") and its stage, never from a stored ID."""
    try:
        apis, position = [], None
        while True:
            args = ["apigateway", "get-rest-apis", "--region", region, "--limit", "100"] + (["--position", position] if position else [])
            page = aws.call(*args)
            apis += page.get("items") or []
            position = page.get("position")
            if not position:
                break
        named = [a for a in apis if "rhobs" in (a.get("name") or "").lower()]
        if len(named) != 1:
            raise CollectionError(f"expected exactly one metrics API gateway (name contains 'rhobs'), found {len(named)}")
        stages = [s["stageName"] for s in aws.call("apigateway", "get-stages", "--rest-api-id", named[0]["id"],
                                                    "--region", region).get("item") or []]
    except AwsError as e:
        raise CollectionError(f"could not find the metrics API gateway: {e}") from None
    stage = "prod" if "prod" in stages else (stages[0] if len(stages) == 1 else None)
    if stage is None:
        raise CollectionError("the metrics API gateway has no single, identifiable stage")
    return f"https://{named[0]['id']}.execute-api.{region}.amazonaws.com/{stage}"


def read_credentials(aws: Aws) -> dict:
    try:
        creds = aws.call("configure", "export-credentials", "--format", "process")
    except AwsError as e:
        raise CollectionError(f"could not obtain credentials for the read-only profile: {e}") from None
    if not creds.get("AccessKeyId") or not creds.get("SecretAccessKey"):
        raise CollectionError("the read-only profile gave no usable credentials")
    return creds


# --- reading and judging ------------------------------------------------------

def app_key(labels: dict) -> tuple:
    return (labels.get("name") or "", labels.get("project") or "")


def parse_age(result: list):
    """Seconds since the newest sample, or None when the query returned nothing."""
    if not result:
        return None
    try:
        age = float(result[0]["value"][1])
    except (KeyError, IndexError, ValueError, TypeError):
        return None
    return None if math.isnan(age) else age


def current_apps(result: list) -> dict:
    """{(name, project): [(sync, health), ...]} from an instant query."""
    apps = {}
    for series in result:
        labels = series.get("metric") or {}
        if not labels.get("name"):
            continue
        apps.setdefault(app_key(labels), []).append((norm_sync(labels.get("sync_status")), norm_health(labels.get("health_status"))))
    return apps


def timeline(result: list, start: float, step: int, steps: int) -> dict:
    """{(name, project): {step index: set of (sync, health)}} from a range query."""
    out = {}
    for series in result:
        labels = series.get("metric") or {}
        if not labels.get("name"):
            continue
        state = (norm_sync(labels.get("sync_status")), norm_health(labels.get("health_status")))
        per_app = out.setdefault(app_key(labels), {})
        for ts, _value in series.get("values") or []:
            idx = round((float(ts) - start) / step)
            if 0 <= idx < steps:
                per_app.setdefault(idx, set()).add(state)
    return out


def judge(per_step: dict, steps: int) -> dict:
    """The whole-window judgement for one application (see the module doc)."""
    observed = len(per_step) / steps if steps else 0.0
    base = {"observed_fraction": round(observed, 3), "partially_observed": observed < OBSERVED_MIN,
            "unhealthy_for_window": False, "stuck_progressing_for_window": False}
    if observed < OBSERVED_MIN:
        return base
    classes = [step_class(states) for states in per_step.values()]
    if "ok" in classes:
        return base
    if "bad" in classes:
        base["unhealthy_for_window"] = True
    else:
        base["stuck_progressing_for_window"] = True
    return base


def state_of(states: list) -> tuple:
    """The (sync, health) to show for an application: the worst of the states it currently shows."""
    for sync, health in sorted(states, key=lambda s: (step_class({s}) != "bad", step_class({s}) != "progressing")):
        return sync, health
    return "unknown", "unknown"


def build_evidence(ar: str, target: str, now: datetime, lookback_minutes: int, freshness_seconds: int, step_seconds: int,
                   age, current: dict, windowed: dict, steps: int, problems: list) -> dict:
    start_covered = {i for per_app in windowed.values() for i in per_app}
    window_coverage = len(start_covered) / steps if steps else 0.0
    if windowed and window_coverage < WINDOW_COVERAGE_MIN:
        problems.append(f"the metrics have gaps in the lookback window (samples at {window_coverage:.0%} of the steps)")
    if age is not None and age > freshness_seconds:
        problems.append(f"the newest sample is {age:.0f} seconds old, older than the {freshness_seconds} second freshness limit")
    if age is None and not problems:
        problems.append("the cluster reports no samples")
    if not current and not any("could not" in p or "answered" in p for p in problems):
        problems.append("the cluster reports no applications")

    applications = []
    for key in sorted(current):
        sync, health = state_of(current[key])
        verdict = judge(windowed.get(key, {}), steps)
        applications.append({"name": key[0], "project": key[1], "sync_state": sync, "health_state": health, **verdict})
    gone = len([k for k in windowed if k not in current])
    return {
        "assessment_requirement": ar,
        "generated_at": utc_iso(now.timestamp()),
        "target": target,
        "target_type": TARGET_TYPE,
        "collection": {
            "complete": not problems,
            "source": SOURCE,
            "window_minutes": lookback_minutes,
            "step_seconds": step_seconds,
            "steps": steps,
            "freshness_seconds": freshness_seconds,
            "newest_sample_age_seconds": None if age is None else round(age, 1),
            "window_coverage": round(window_coverage, 3),
            "applications_gone_in_window": gone,
            "problems": problems,
            "limitations": LIMITATIONS,
            "generated_at": utc_iso(now.timestamp()),
        },
        "applications": applications,
    }


def collect(metrics: Metrics, ar: str, target: str, now: datetime, lookback_minutes: int, freshness_seconds: int,
            step_seconds: int) -> dict:
    if not CLUSTER_RE.fullmatch(target):
        raise CollectionError("the cluster name is not a plain identifier")
    selector = f'{METRIC}{{cluster="{target}"}}'
    end = math.floor(now.timestamp())
    start = end - lookback_minutes * 60
    steps = (end - start) // step_seconds + 1
    problems, age, current, windowed = [], None, {}, {}
    try:
        age = parse_age(metrics.instant(f"time() - max(timestamp({selector}))", end))
        current = current_apps(metrics.instant(selector, end))
        windowed = timeline(metrics.range(selector, start, end, step_seconds), start, step_seconds, steps)
    except MetricsError as e:
        problems.append(f"could not read the metrics: {e}")
    return build_evidence(ar, target, now, lookback_minutes, freshness_seconds, step_seconds, age, current, windowed, steps, problems)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ar", required=True)
    ap.add_argument("--target", required=True, help="the cluster name (the metrics' cluster label)")
    ap.add_argument("--profile", required=True, help="the read-only profile of the account that owns the metrics API")
    ap.add_argument("--region", required=True)
    ap.add_argument("--lookback-minutes", type=int, default=30)
    ap.add_argument("--freshness-seconds", type=int, default=300)
    ap.add_argument("--step-seconds", type=int, default=60)
    args = ap.parse_args()
    if not re.fullmatch(r"rsc-[a-z0-9-]+-ro", args.profile):
        sys.exit(f"ERROR: refusing profile {args.profile!r}: only read-only profiles (rsc-<account>-ro) are allowed")
    try:
        aws = Aws(args.profile)
        metrics = Metrics(discover_base_url(aws, args.region), read_credentials(aws), args.region,
                          timeout=float(os.environ.get("RSC_METRICS_TIMEOUT", "30")))
        evidence = collect(metrics, args.ar, args.target, datetime.now(timezone.utc), args.lookback_minutes,
                           args.freshness_seconds, args.step_seconds)
    except (CollectionError, AwsError) as e:
        sys.exit(f"ERROR: {mask(str(e))}")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
