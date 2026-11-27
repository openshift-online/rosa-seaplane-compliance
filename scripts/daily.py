#!/usr/bin/env python3
"""`make daily`: the normal run for yesterday, after filling in any days that were missed.

    daily.py [--date YYYY-MM-DD]

A UTC day is the half-open interval [D 00:00:00Z, D+1 00:00:00Z). Without --date:

  1. BACKFILL: every day from RSC_BACKFILL_DAYS ago (default 5, at least 3, at most 89) up to
     the day BEFORE yesterday that has no record in the history is collected, oldest first.
     A backfill runs only the EVENT collectors (config/history/ar-basis.yaml) for that date,
     into its own working folder (output/backfill/<date>/), never into evidence/output or the
     latest outputs, evaluates the policies over that folder, and appends a record with
     backfill=true: the event methods carry real results and every STATE method is
     `not_collected`, because the past state of a system cannot be reconstructed and today's
     is never passed off as that day's. No scan, SDR or viewer is made for a backfill.
  2. NORMAL RUN for yesterday: every collector, the scan, findings, trace, the record
     (backfill=false), the history summary and the viewer.

A failing backfill (its collectors fail, or its policies cannot be evaluated) writes no record, so
the next `make daily` tries that day again; it does not stop the normal run, and it is reported at
the end together with a non-zero exit. A rerun the same day never backfills a day that already has
a record, and appends one more record for yesterday.

With --date, only that day is run: the normal run if it is yesterday, a backfill if it is earlier
(a record already there does not matter: this appends another). Today, the future, a malformed
date and a day older than 90 days are refused; so is a run before the day has settled
(RSC_SETTLE_MINUTES, default 120, RSC_ALLOW_EARLY=1 to override), so schedule it at or after 02:00 UTC.
All checks happen before any long run starts.
"""
import argparse
import os
import shutil
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "evidence/lib"))

import build_record  # noqa: E402
import day_window  # noqa: E402
import history  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BACKFILL_DAYS = 5
MIN_BACKFILL_DAYS = 3
MAX_BACKFILL_DAYS = 89   # CloudTrail keeps 90 days and a day is read from its start


class DailyError(RuntimeError):
    pass


def backfill_days(environ: dict) -> int:
    raw = environ.get("RSC_BACKFILL_DAYS") or str(DEFAULT_BACKFILL_DAYS)
    try:
        n = int(raw)
    except ValueError:
        raise DailyError(f"RSC_BACKFILL_DAYS must be a whole number, not {raw!r}") from None
    if not MIN_BACKFILL_DAYS <= n <= MAX_BACKFILL_DAYS:
        raise DailyError(f"RSC_BACKFILL_DAYS must be between {MIN_BACKFILL_DAYS} and {MAX_BACKFILL_DAYS} "
                         f"(a verification is due at least every 3 days; CloudTrail keeps 90), not {n}")
    return n


def missing_days(recorded: set, today: date, n: int) -> list:
    """The days to backfill, oldest first: from `n` days ago up to the day BEFORE yesterday
    (never yesterday, which is the normal run, and never today) that have no record."""
    return [d for d in (today - timedelta(days=i) for i in range(n, 1, -1)) if d not in recorded]


def event_collectors(basis: dict, root: Path) -> list:
    """The collector of every EVENT method, by its declared basis. A state collector is never in it."""
    out = []
    for ar in sorted(basis):
        if basis[ar]["basis"] != "event":
            continue
        path = root / "evidence" / f"{ar}.sh"
        if not (path.is_file() and os.access(path, os.X_OK)):
            raise DailyError(f"{ar} is declared an event method but evidence/{ar}.sh is missing or not executable")
        out.append(path)
    return out


class Runner:
    """Runs one command, streaming its output; `log` captures a quiet helper's output and shows it only on failure."""

    def __call__(self, cmd: list, env: dict, log: Path = None) -> int:
        print(f"==> {' '.join(str(c) for c in cmd)}", flush=True)
        if log is None:
            return subprocess.run([str(c) for c in cmd], env=env, cwd=ROOT).returncode
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "w") as f:
            rc = subprocess.run([str(c) for c in cmd], env=env, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT).returncode
        if rc != 0:
            print(log.read_text(), file=sys.stderr)
        return rc


def backfill_day(day: str, runner, root: Path, environ: dict, basis: dict, python: str = None, out=print) -> Path:
    """Collect and record ONE past day, from its event collectors only. Returns the working folder.
    Raises DailyError (and writes no record) if anything fails."""
    python = python or sys.executable
    work = root / "output" / "backfill" / day
    shutil.rmtree(work, ignore_errors=True)
    evidence = work / "evidence"
    evidence.mkdir(parents=True)
    env = {**environ, "RSC_DATE": day, "RSC_EVIDENCE_DIR": str(evidence)}

    failed = []
    for collector in event_collectors(basis, root):
        out(f"==> Backfilling {day}: {collector.stem}")
        if runner([collector], env) != 0:
            failed.append(collector.stem)
    if failed:
        raise DailyError(f"{day}: the event collector(s) {', '.join(failed)} failed, so no record was written "
                         "(the next `make daily` tries this day again)")

    coverage, trace = work / "coverage.json", work / "trace.json"
    out = work / "out"
    steps = [
        ("coverage", [python, root / "scripts/coverage.py", "--out", coverage]),
        ("findings", [python, root / "scripts/build_findings.py", "--evidence-dir", evidence, "--coverage", coverage,
                      "--out-dir", out]),
        ("trace", [python, root / "scripts/build_trace.py", "--coverage", coverage, "--out", trace,
                   "--scan-dir", work / "scan"]),
        ("record", [python, root / "scripts/build_record.py", "--date", day, "--coverage", coverage, "--trace", trace,
                    "--findings", out / "findings.json", "--evidence-dir", evidence]),
    ]
    for label, cmd in steps:
        if runner(cmd, env, work / f"{label}.log") != 0:
            raise DailyError(f"{day}: the {label} step failed, so no record was written")
    return work


def normal_day(day: str, runner, environ: dict, make: str = None) -> None:
    """The full run for yesterday: every collector and the scan, then findings, trace, the record, the
    history summary and the viewer. Stops at the first failing step."""
    make = make or os.environ.get("MAKE", "make")
    env = {**environ, "RSC_DATE": day}
    for target in (["run-local"], ["coverage"], ["findings"], ["trace"], ["record", f"DATE={day}"],
                   ["history-summary"], ["sdr-view"]):
        if runner([make, *target], env) != 0:
            raise DailyError(f"{day}: `make {' '.join(target)}` failed")


def settled_day(requested, now: datetime, environ: dict) -> dict:
    """Validate the day to run before anything long starts: complete, within 90 days, settled."""
    try:
        return day_window.resolve(requested, now,
                                  int(environ.get("RSC_SETTLE_MINUTES") or day_window.DEFAULT_SETTLE_MINUTES),
                                  allow_early=environ.get("RSC_ALLOW_EARLY") == "1")
    except (day_window.DayError, ValueError) as e:
        raise DailyError(str(e)) from None


def daily(requested, environ: dict, runner, store, now: datetime, basis: dict, root: Path = ROOT, out=print) -> int:
    """Run everything; return the exit code (non-zero if any step failed)."""
    today = now.astimezone(timezone.utc).date()
    target = settled_day(requested, now, environ)
    n = backfill_days(environ) if not requested else None
    store.require_init()
    plan = []
    if requested:
        plan = [(target["covers_date"], target["backfill"])]
    else:
        recorded = {date.fromisoformat(r["covers_date"])
                    for r in store.records(since=today - timedelta(days=n + 1), validator=build_record.check_record)}
        plan = [(d.isoformat(), True) for d in missing_days(recorded, today, n)] + [(target["covers_date"], False)]
    out("Plan: " + ", ".join(f"{d} ({'backfill' if bf else 'normal run'})" for d, bf in plan))

    backfilled, failures, normal = [], [], None
    for day, is_backfill in plan:
        try:
            if is_backfill:
                backfill_day(day, runner, root, environ, basis, out=out)
                backfilled.append(day)
            else:
                normal_day(day, runner, environ)
                normal = day
        except DailyError as e:
            failures.append(str(e))
            out(f"FAILED: {e}")

    out("")
    out("== daily summary ==")
    out(f"Backfilled: {', '.join(backfilled) if backfilled else 'nothing'}")
    if normal:
        out(f"Normal run: {normal} done")
    for f in failures:
        out(f"FAILED: {f}")
    return 1 if failures else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--date", default=None, help="run only this UTC day (default: fill missing days, then yesterday)")
    args = ap.parse_args()
    now = datetime.now(timezone.utc)
    try:
        basis = build_record.load_basis()
        code = daily(args.date or None, dict(os.environ), Runner(), history.open_store(), now, basis)
    except (DailyError, build_record.RecordError, history.StoreError) as e:
        sys.exit(f"ERROR: {e}")
    sys.exit(code)


if __name__ == "__main__":
    main()
