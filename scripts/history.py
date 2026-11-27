#!/usr/bin/env python3
"""Append-only history of run records, in the evidence locker (S3) or a local folder.

Each `make record` appends one RUN RECORD (see scripts/build_record.py) here. The
series is what the FedRAMP Security Decision Record has to carry for Class C
(rule SDR-CSX-KMT: a 30-day summary, a past-year summary and ALL daily metric data,
including the status of persistent validation, up to the past year where available).

The series is DAY-PARTITIONED: every record is about one UTC day (`covers_date`, the
half-open interval [D 00:00:00Z, D+1 00:00:00Z)), which is not the time the run happened.
A missed day is recovered by running for that date, and records are filed under the day
they cover.

The history holds real findings, so it NEVER lives in this repository. Selection:

    RSC_S3_BUCKET set      -> S3 (via the `aws` CLI), same variables as push-evidence.sh:
                              RSC_S3_BUCKET, RSC_S3_PREFIX (default rosa-seaplane-compliance),
                              RSC_S3_ENDPOINT_URL (a local mock such as adobe/s3mock)
    otherwise              -> a local folder: RSC_HISTORY_DIR or .history/ (gitignored)

Layout, under `<prefix>/history/` in S3 or the local folder:

    v1/INIT                          version marker, written once
    v1/runs/YYYY/MM/DD/<run_id>.json one record per run, filed under the day it COVERS;
                                     never overwritten

Rules the store enforces:
  * Append-only: an existing object is never replaced. A rerun of a day appends a new
    record with a new run id; the day's status comes from the latest, all are kept.
  * Fail closed: a store that cannot be read, or whose INIT marker is missing or from
    an incompatible layout, is an ERROR, never "empty history". 'Not initialised yet' and
    'unreadable' are different errors.
  * Writes are atomic from a reader's point of view (a single S3 put; a temp file
    linked into place locally).

    history.py init      create the version marker (idempotent)
    history.py status    say which store is selected and whether it is initialised
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAYOUT = "rsc-history"
LAYOUT_VERSION = 1
INIT_KEY = "v1/INIT"
RUNS_PREFIX = "v1/runs/"
RUN_ID_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T\d{6}Z-[0-9a-f]{6}$")
DEFAULT_LOCAL_DIR = ROOT / ".history"
DEFAULT_S3_PREFIX = "rosa-seaplane-compliance"


class StoreError(RuntimeError):
    """Anything wrong with the history store. Always an error, never 'no history'."""


class NotInitialised(StoreError):
    """The store is reachable but has no INIT marker: run `make history-init`."""


class Unreadable(StoreError):
    """The store (or something in it) could not be read, or is not what it claims to be."""


class Incompatible(StoreError):
    """The INIT marker is from a layout or version this code does not understand."""


class AlreadyExists(StoreError):
    """An object already exists: history is append-only."""


def new_run_id(now: datetime = None) -> str:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"


def check_run_id(run_id: str) -> str:
    if not RUN_ID_RE.match(run_id or ""):
        raise Unreadable(f"not a run id: {run_id!r}")
    return run_id


def parse_day(text) -> date:
    try:
        return date.fromisoformat(text)
    except (TypeError, ValueError):
        raise Unreadable(f"not a date (YYYY-MM-DD): {text!r}") from None


def runs_key(covers_date: str, run_id: str) -> str:
    """Where a record lives: under the UTC day it COVERS, not the day it was made."""
    d = parse_day(covers_date)
    return f"{RUNS_PREFIX}{d:%Y/%m/%d}/{check_run_id(run_id)}.json"


def _safe_key(key: str) -> str:
    if not key or key.startswith("/") or ".." in key.split("/") or "\\" in key:
        raise StoreError(f"unsafe key: {key!r}")
    return key


# --- backends -----------------------------------------------------------------

class LocalBackend:
    """A folder. Writes go to a temp file that is hard-linked into place, so a reader never
    sees a partial object and an existing object is never replaced."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.where = f"local folder {self.root}"

    def get(self, key: str):
        path = self.root / _safe_key(key)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as e:
            raise Unreadable(f"cannot read {key} in {self.where}: {e}") from None

    def put_new(self, key: str, data: bytes) -> None:
        final = self.root / _safe_key(key)
        try:
            final.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=final.parent)
        except OSError as e:
            raise Unreadable(f"cannot write in {self.where}: {e}") from None
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(tmp, final)
            except FileExistsError:
                raise AlreadyExists(f"{key} already exists in {self.where}") from None
            except OSError as e:
                raise Unreadable(f"cannot write {key} in {self.where}: {e}") from None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def list(self, prefix: str) -> list:
        base = self.root / _safe_key(prefix.rstrip("/"))
        if not base.is_dir():
            return []
        out = []
        for p in base.rglob("*"):
            if p.is_file() and not p.name.startswith(".tmp-"):
                out.append(p.relative_to(self.root).as_posix())
        return sorted(out)


class S3Backend:
    """An S3 bucket (or an S3-compatible mock) through the `aws` CLI.

    `runner` is injectable so tests can stand in for the CLI. Appends use a conditional
    put (If-None-Match: *) where the endpoint supports it, after a head-object check, so
    an object is never replaced. Real immutability (Object Lock) is a bucket setting this
    repository does not configure.
    """

    def __init__(self, bucket: str, prefix: str, endpoint: str = None, runner=None, aws: str = "aws"):
        self.bucket, self.prefix, self.endpoint, self.aws = bucket, prefix.strip("/"), endpoint, aws
        self.runner = runner or self._run
        self.where = f"s3://{bucket}/{self.prefix}/"

    @staticmethod
    def _run(cmd):
        return subprocess.run(cmd, capture_output=True, text=True)

    def _cmd(self, *args):
        base = [self.aws]
        if self.endpoint:
            base += ["--endpoint-url", self.endpoint]
        return [*base, "s3api", *args, "--bucket", self.bucket]

    def _full(self, key: str) -> str:
        return f"{self.prefix}/{_safe_key(key)}"

    @staticmethod
    def _missing(err: str) -> bool:
        return any(s in err for s in ("NoSuchKey", "Not Found", "(404)"))

    def _exists(self, key: str) -> bool:
        res = self.runner(self._cmd("head-object", "--key", self._full(key)))
        if res.returncode == 0:
            return True
        if self._missing(res.stderr):
            return False
        raise Unreadable(f"cannot check {key} in {self.where}: {res.stderr.strip()[:200]}")

    def get(self, key: str):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "object"
            res = self.runner(self._cmd("get-object", "--key", self._full(key)) + [str(out)])
            if res.returncode != 0:
                if self._missing(res.stderr):
                    return None
                raise Unreadable(f"cannot read {key} in {self.where}: {res.stderr.strip()[:200]}")
            try:
                return out.read_bytes()
            except OSError as e:
                raise Unreadable(f"cannot read {key} in {self.where}: {e}") from None

    def put_new(self, key: str, data: bytes) -> None:
        if self._exists(key):
            raise AlreadyExists(f"{key} already exists in {self.where}")
        with tempfile.TemporaryDirectory() as t:
            body = Path(t) / "object"
            body.write_bytes(data)
            base = self._cmd("put-object", "--key", self._full(key), "--body", str(body))
            res = self.runner(base + ["--if-none-match", "*"])
            if res.returncode != 0 and any(s in res.stderr for s in ("Unknown options", "NotImplemented", "not implemented", "if-none-match")):
                res = self.runner(base)  # this endpoint has no conditional writes: the head check above stands
            if res.returncode != 0:
                if "PreconditionFailed" in res.stderr or "(412)" in res.stderr:
                    raise AlreadyExists(f"{key} already exists in {self.where}")
                raise Unreadable(f"cannot write {key} in {self.where}: {res.stderr.strip()[:200]}")

    def list(self, prefix: str) -> list:
        full = self._full(prefix.rstrip("/")) + "/"
        res = self.runner(self._cmd("list-objects-v2", "--prefix", full, "--output", "json"))
        if res.returncode != 0:
            raise Unreadable(f"cannot list {prefix} in {self.where}: {res.stderr.strip()[:200]}")
        if not res.stdout.strip():
            return []
        try:
            doc = json.loads(res.stdout)
        except ValueError:
            raise Unreadable(f"unreadable listing of {prefix} in {self.where}") from None
        strip = self.prefix + "/"
        return sorted(o["Key"][len(strip):] for o in ((doc or {}).get("Contents") or []) if o["Key"].startswith(strip))


def open_backend(environ: dict = None):
    environ = os.environ if environ is None else environ
    bucket = environ.get("RSC_S3_BUCKET")
    if bucket:
        prefix = environ.get("RSC_S3_PREFIX") or DEFAULT_S3_PREFIX
        return S3Backend(bucket, f"{prefix}/history", environ.get("RSC_S3_ENDPOINT_URL") or None)
    return LocalBackend(Path(environ.get("RSC_HISTORY_DIR") or DEFAULT_LOCAL_DIR))


# --- the store ----------------------------------------------------------------

class Store:
    def __init__(self, backend):
        self.backend = backend

    def _marker(self):
        raw = self.backend.get(INIT_KEY)
        if raw is None:
            return None
        try:
            doc = json.loads(raw)
        except ValueError:
            raise Unreadable(f"the INIT marker in {self.backend.where} is not valid JSON") from None
        if not isinstance(doc, dict) or doc.get("layout") != LAYOUT or doc.get("version") != LAYOUT_VERSION:
            raise Incompatible(f"the INIT marker in {self.backend.where} is from a layout this code does not understand: {doc!r}")
        return doc

    def init(self) -> bool:
        """Create the version marker. True if created now, False if it already existed."""
        if self._marker() is not None:
            return False
        marker = {"layout": LAYOUT, "version": LAYOUT_VERSION,
                  "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        try:
            self.backend.put_new(INIT_KEY, (json.dumps(marker, indent=2) + "\n").encode())
        except AlreadyExists:
            self._marker()  # lost a race: make sure what is there is compatible
            return False
        return True

    def require_init(self) -> dict:
        marker = self._marker()
        if marker is None:
            raise NotInitialised(f"{self.backend.where} is not initialised: run `make history-init`")
        return marker

    def put_record(self, record: dict) -> str:
        self.require_init()
        key = runs_key(record.get("covers_date"), record.get("run_id"))
        self.backend.put_new(key, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
        return key

    def records(self, since: date = None, until: date = None, validator=None) -> list:
        """All records COVERING the days between two dates (inclusive), oldest day first. Any
        unreadable, malformed or inconsistent record is an error: skipping it would hide
        history. `validator(record)` may raise to reject a record that is not well formed."""
        self.require_init()
        out = []
        for key in self.backend.list(RUNS_PREFIX):
            m = re.match(r"^v1/runs/(\d{4})/(\d{2})/(\d{2})/([^/]+)\.json$", key)
            if not m:
                raise Unreadable(f"unexpected object in the history: {key}")
            day = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if (since and day < since) or (until and day > until):
                continue
            raw = self.backend.get(key)
            if raw is None:
                raise Unreadable(f"{key} was listed but cannot be read")
            try:
                rec = json.loads(raw)
            except ValueError:
                raise Unreadable(f"{key} is not valid JSON") from None
            if not isinstance(rec, dict) or rec.get("schema_version") != 1:
                raise Unreadable(f"{key} is not a version 1 run record")
            if rec.get("run_id") != m.group(4) or rec.get("covers_date") != day.isoformat():
                raise Unreadable(f"{key} does not match the run id and covered day inside it")
            if validator is not None:
                try:
                    validator(rec)
                except Exception as e:  # noqa: BLE001 - any rejection means the history is not trustworthy
                    raise Unreadable(f"{key} is not a valid run record: {str(e).splitlines()[0][:160]}") from None
            out.append(rec)
        return sorted(out, key=lambda r: (r["covers_date"], r.get("finished_at", ""), r["run_id"]))


def open_store(environ: dict = None) -> Store:
    return Store(open_backend(environ))


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    try:
        store = open_store()
        where = store.backend.where
        if cmd == "init":
            created = store.init()
            print(f"{'Initialised' if created else 'Already initialised'}: {where}")
        elif cmd == "status":
            try:
                store.require_init()
                state = "initialised"
            except NotInitialised:
                state = "NOT initialised (run `make history-init`)"
            print(f"History store: {where}: {state}")
        else:
            sys.exit(f"usage: {sys.argv[0]} init|status")
    except StoreError as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
