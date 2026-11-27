"""A thin, paced and retrying wrapper over the aws CLI, shared by the AWS collectors.

JSON in, JSON out, through one profile (always a read-only one: collectors never take
an admin profile). Throttling is retried with backoff; any other failure raises
AwsError with a message that never contains an account ID.
"""
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone

ID_RE = re.compile(r"[0-9]{12}")
THROTTLE_RE = re.compile(r"Throttling|Rate exceeded|TooManyRequests", re.I)


class AwsError(RuntimeError):
    pass


def mask(text: str) -> str:
    return ID_RE.sub("<ID>", text)


def utc_iso(value) -> str:
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, timezone.utc)
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Aws:
    """Thin wrapper over the aws CLI: JSON in, JSON out, paced and retried lookups."""

    def __init__(self, profile, interval=None, retries=None, backoff=None, run=subprocess.run, sleep=time.sleep):
        self.profile = profile
        self.interval = float(os.environ.get("RSC_LOOKUP_INTERVAL", "0.55")) if interval is None else interval
        self.retries = int(os.environ.get("RSC_LOOKUP_RETRIES", "6")) if retries is None else retries
        self.backoff = float(os.environ.get("RSC_LOOKUP_BACKOFF", "1.0")) if backoff is None else backoff
        self._run, self._sleep, self._last = run, sleep, {}

    def call(self, *args: str, region: str = None) -> dict:
        """Run one aws call; throttling is retried with backoff, anything else raises."""
        cmd = ["aws", "--profile", self.profile, "--output", "json", *args]
        for attempt in range(self.retries + 1):
            if region is not None:
                # At most 2 lookups per second per account and region.
                wait = self.interval - (time.monotonic() - self._last.get(region, -1e9))
                if wait > 0:
                    self._sleep(wait)
                self._last[region] = time.monotonic()
            res = self._run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                return json.loads(res.stdout) if res.stdout.strip() else {}
            err = (res.stderr or res.stdout or "").strip()
            if THROTTLE_RE.search(err) and attempt < self.retries:
                self._sleep(min(self.backoff * (2 ** attempt), 30))
                continue
            raise AwsError(mask(err.splitlines()[-1] if err else "aws call failed")[:200])
        raise AwsError("throttled")  # pragma: no cover (loop always returns or raises)
