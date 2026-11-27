#!/usr/bin/env python3
"""The one UTC day an EVENT collector covers.

    day_window.py [--date YYYY-MM-DD] [--settle-minutes 120] [--allow-early] [--now ISO]

Prints {"covers_date", "start", "end", "backfill"} as JSON, or exits 2 with the reason.
The day is the half-open interval [D 00:00:00Z, D+1 00:00:00Z): an event at exactly
D 00:00:00Z belongs to D, one at exactly D+1 00:00:00Z belongs to D+1, one at
D 23:59:59.999Z belongs to D. Taking the end as exclusive means nothing falls between two
days or into both.

Defaults come from the environment, so `make daily` fixes one day for every collector:
RSC_DATE (default: yesterday, UTC), RSC_SETTLE_MINUTES (default 120), RSC_ALLOW_EARLY=1.

Refused: a malformed date; today or a later day (the day is not complete); a day whose
start is more than 90 days ago (CloudTrail event history keeps 90 days, so the day could
not be fully read); a run before the day has had SETTLE minutes after its end to receive
its late events (CloudTrail lags by minutes, GitHub by seconds) unless explicitly allowed.
Yesterday is a normal run; any earlier day is a backfill.
"""
import argparse
import json
import os
import sys
from datetime import date, datetime, timedelta, timezone

MAX_AGE_DAYS = 90
DEFAULT_SETTLE_MINUTES = 120
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


class DayError(ValueError):
    pass


def fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TS_FMT)


def day_for(text: str) -> dict:
    """The half-open window of a date, without any of resolve()'s policy (a collector that
    was handed a date already checked by the caller uses this)."""
    if not isinstance(text, str) or len(text) != 10:
        raise DayError(f"the date must be YYYY-MM-DD, not {text!r}")
    try:
        day = date.fromisoformat(text)
    except ValueError:
        raise DayError(f"the date must be YYYY-MM-DD, not {text!r}") from None
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return {"covers_date": day.isoformat(), "start": fmt(start), "end": fmt(start + timedelta(days=1))}


def resolve(requested=None, now: datetime = None, settle_minutes: int = DEFAULT_SETTLE_MINUTES,
            allow_early: bool = False) -> dict:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    today = now.date()
    window = day_for((today - timedelta(days=1)).isoformat() if requested in (None, "") else requested)
    day = date.fromisoformat(window["covers_date"])
    start = datetime.fromisoformat(window["start"].replace("Z", "+00:00"))
    end = start + timedelta(days=1)
    if day >= today:
        raise DayError(f"{day.isoformat()} is not a complete day yet (today is {today.isoformat()} UTC): "
                       "the newest day that can be collected is yesterday")
    if now - start > timedelta(days=MAX_AGE_DAYS):
        raise DayError(f"{day.isoformat()} is more than {MAX_AGE_DAYS} days ago: CloudTrail event history only keeps "
                       f"{MAX_AGE_DAYS} days, so the day could not be fully read")
    ready = end + timedelta(minutes=settle_minutes)
    if now < ready and not allow_early:
        raise DayError(f"{day.isoformat()} ended less than {settle_minutes} minutes ago: its late events may not have "
                       f"arrived. Run at or after {fmt(ready)}, or set RSC_ALLOW_EARLY=1 to collect anyway")
    return {**window, "backfill": day < today - timedelta(days=1)}


def in_day(timestamp: str, start: str, end: str) -> bool:
    """True when an ISO timestamp falls in [start, end). Fractions of a second are honoured."""
    def parse(text):
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    return parse(start) <= parse(timestamp) < parse(end)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--date", default=os.environ.get("RSC_DATE"))
    ap.add_argument("--settle-minutes", type=int,
                    default=int(os.environ.get("RSC_SETTLE_MINUTES") or DEFAULT_SETTLE_MINUTES))
    ap.add_argument("--allow-early", action="store_true", default=os.environ.get("RSC_ALLOW_EARLY") == "1")
    ap.add_argument("--now", help="testing only: pretend it is this ISO time")
    args = ap.parse_args()
    now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else None
    try:
        print(json.dumps(resolve(args.date, now, args.settle_minutes, args.allow_early)))
    except DayError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
