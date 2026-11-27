"""Shared fakes for the history tests: an in-memory stand-in for the `aws s3api` CLI and
builders for synthetic run records. Synthetic data only: no real names, no IDs."""
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

ENDPOINT = "http://localhost:9"  # never contacted: the runner below answers instead


class FakeS3:
    """Callable standing in for subprocess.run over `aws [--endpoint-url U] s3api <op> ...`."""

    def __init__(self, fail_all: str = None, no_conditional: bool = False):
        self.objects, self.calls = {}, []
        self.fail_all, self.no_conditional = fail_all, no_conditional

    @staticmethod
    def _done(rc=0, out="", err=""):
        return subprocess.CompletedProcess([], rc, out, err)

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        if self.fail_all:
            return self._done(254, err=self.fail_all)
        i = cmd.index("s3api")
        op, rest = cmd[i + 1], cmd[i + 2:]
        opt = lambda name: rest[rest.index(name) + 1] if name in rest else None
        key = opt("--key")
        if op == "head-object":
            return self._done() if key in self.objects else self._done(254, err="An error occurred (404) when calling the HeadObject operation: Not Found")
        if op == "get-object":
            if key not in self.objects:
                return self._done(254, err="An error occurred (NoSuchKey) when calling the GetObject operation")
            Path(rest[-1]).write_bytes(self.objects[key])
            return self._done()
        if op == "put-object":
            if "--if-none-match" in rest:
                if self.no_conditional:
                    return self._done(252, err="Unknown options: --if-none-match, *")
                if key in self.objects:
                    return self._done(254, err="An error occurred (PreconditionFailed) (412)")
            self.objects[key] = Path(opt("--body")).read_bytes()
            return self._done()
        if op == "list-objects-v2":
            prefix = opt("--prefix")
            keys = sorted(k for k in self.objects if k.startswith(prefix))
            return self._done(out=json.dumps({"Contents": [{"Key": k} for k in keys]}) if keys else "")
        return self._done(255, err=f"unexpected operation {op}")


def ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_record(day: datetime, methods: dict, suffix: str = "a1b2c3", kind: str = "intent", covers: str = None,
                backfill: bool = False, basis: dict = None) -> dict:
    """A schema-valid record made at `day` (a datetime) about the UTC day `covers` (default: the
    day it was made). methods: {(ksi, ar): result}; basis: {ar: "event"|"state"} (default event).
    A state method that passed or failed carries collected_at; a not_collected one carries nothing."""
    rid = f"{day.strftime('%Y%m%dT%H%M%SZ')}-{suffix}"
    entries = []
    for (ksi, ar), res in sorted(methods.items()):
        b = (basis or {}).get(ar, "event")
        nc = res == "not_collected"
        entries.append({"ksi": ksi, "ar": ar, "method_kind": kind, "basis": b, "result": res,
                        "violations": 1 if res == "fail" else 0, "incomplete": 1 if res == "error" else 0,
                        "targets_expected": 0 if nc else 2, "targets_reached": 0 if nc else (1 if res == "error" else 2),
                        "window": {"start": ts(day - timedelta(days=1)), "end": ts(day)} if b == "event" and not nc else None,
                        "collected_at": ts(day - timedelta(minutes=2)) if b == "state" and res in ("pass", "fail") else None,
                        "evidence_sha256": None if nc else "a" * 64,
                        "rules_failed": [{"rule": "x.y", "count": 1}] if res == "fail" else []})
    return {"schema_version": 1, "run_id": rid, "covers_date": covers or day.astimezone(timezone.utc).date().isoformat(),
            "backfill": backfill, "recorded_at": ts(day), "started_at": ts(day - timedelta(minutes=5)),
            "finished_at": ts(day - timedelta(minutes=1)), "environment": "integration",
            "pipeline": {"commit": "0" * 40, "dirty": False}, "policy_sha256": "b" * 64,
            "tools": {"prowler": "5.52.0"}, "methods": entries}


def utc(y, m, d, h=9, mi=0) -> datetime:
    return datetime(y, m, d, h, mi, tzinfo=timezone.utc)
