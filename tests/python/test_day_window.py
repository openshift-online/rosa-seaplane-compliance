import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import day_window as dw  # noqa: E402

NOW = datetime(2026, 11, 27, 9, 30, tzinfo=timezone.utc)


def at(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


class Resolve(unittest.TestCase):
    def test_default_is_yesterday_a_normal_run(self):
        day = dw.resolve(None, NOW)
        self.assertEqual(day, {"covers_date": "2026-11-26", "start": "2026-11-26T00:00:00Z",
                               "end": "2026-11-27T00:00:00Z", "backfill": False})

    def test_an_empty_string_is_the_default_too(self):
        self.assertEqual(dw.resolve("", NOW)["covers_date"], "2026-11-26")

    def test_yesterday_named_explicitly_is_still_a_normal_run(self):
        self.assertFalse(dw.resolve("2026-11-26", NOW)["backfill"])

    def test_any_earlier_day_is_a_backfill(self):
        for d in ("2026-11-25", "2026-11-01", "2026-08-30"):
            self.assertTrue(dw.resolve(d, NOW)["backfill"], d)

    def test_today_and_the_future_are_refused_as_not_complete(self):
        for d in ("2026-11-27", "2026-11-28", "2027-01-01"):
            with self.assertRaisesRegex(dw.DayError, "not a complete day"):
                dw.resolve(d, NOW)

    def test_malformed_dates_are_refused(self):
        for d in ("yesterday", "2026-13-01", "2026-02-30", "20261126", "2026-1-5", "26-11-26", " 2026-11-26"):
            with self.assertRaisesRegex(dw.DayError, "YYYY-MM-DD"):
                dw.resolve(d, NOW)

    def test_the_90_day_limit_is_cloudtrails_and_the_message_says_so(self):
        oldest_ok = (NOW - timedelta(days=90)).date() + timedelta(days=1)   # start is 89 days and 9.5 hours ago
        self.assertEqual(dw.resolve(oldest_ok.isoformat(), NOW)["covers_date"], oldest_ok.isoformat())
        too_old = oldest_ok - timedelta(days=1)                              # start is over 90 days ago
        with self.assertRaisesRegex(dw.DayError, "90 days.*CloudTrail"):
            dw.resolve(too_old.isoformat(), NOW)

    def test_settle_delay_a_day_that_ended_minutes_ago_is_refused_and_says_when_to_run(self):
        early = datetime(2026, 11, 27, 1, 59, tzinfo=timezone.utc)
        with self.assertRaisesRegex(dw.DayError, "2026-11-27T02:00:00Z"):
            dw.resolve(None, early)
        self.assertEqual(dw.resolve(None, datetime(2026, 11, 27, 2, 0, tzinfo=timezone.utc))["covers_date"], "2026-11-26")

    def test_the_settle_delay_is_configurable_and_can_be_overridden(self):
        early = datetime(2026, 11, 27, 0, 30, tzinfo=timezone.utc)
        with self.assertRaises(dw.DayError):
            dw.resolve(None, early)
        self.assertEqual(dw.resolve(None, early, settle_minutes=30)["covers_date"], "2026-11-26")
        self.assertEqual(dw.resolve(None, early, allow_early=True)["covers_date"], "2026-11-26")

    def test_the_settle_delay_does_not_apply_to_older_days(self):
        self.assertEqual(dw.resolve("2026-11-25", datetime(2026, 11, 27, 0, 1, tzinfo=timezone.utc))["covers_date"], "2026-11-25")

    def test_a_time_zone_is_not_confused_with_the_utc_day(self):
        late_in_new_york = datetime(2026, 11, 26, 20, 0, tzinfo=timezone(timedelta(hours=-5)))   # 2026-11-27 01:00 UTC
        with self.assertRaises(dw.DayError):
            dw.resolve(None, late_in_new_york)                                                    # settle not elapsed
        self.assertEqual(dw.resolve(None, late_in_new_york, allow_early=True)["covers_date"], "2026-11-26")


class Boundaries(unittest.TestCase):
    """Half-open [D 00:00:00Z, D+1 00:00:00Z): nothing falls between two days or into both."""

    def test_the_first_instant_of_the_day_is_in_it(self):
        self.assertTrue(dw.in_day("2026-11-26T00:00:00Z", "2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z"))

    def test_the_last_millisecond_of_the_day_is_in_it(self):
        self.assertTrue(dw.in_day("2026-11-26T23:59:59.999Z", "2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z"))

    def test_the_first_instant_of_the_next_day_is_not_in_it(self):
        self.assertFalse(dw.in_day("2026-11-27T00:00:00Z", "2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z"))

    def test_the_last_instant_before_the_day_is_not_in_it(self):
        self.assertFalse(dw.in_day("2026-11-25T23:59:59.999Z", "2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z"))

    def test_offsets_are_converted(self):
        day = ("2026-11-26T00:00:00Z", "2026-11-27T00:00:00Z")
        self.assertTrue(dw.in_day("2026-11-26T01:00:00+01:00", *day))         # exactly 00:00Z
        self.assertFalse(dw.in_day("2026-11-26T00:59:59+01:00", *day))        # 23:59:59Z the day before
        self.assertFalse(dw.in_day("2026-11-26T23:30:00-01:00", *day))        # 00:30Z the day after

    def test_consecutive_days_partition_time(self):
        a, b = dw.day_for("2026-11-26"), dw.day_for("2026-11-27")
        self.assertEqual(a["end"], b["start"])
        for t in ("2026-11-26T23:59:59.999999Z", "2026-11-27T00:00:00Z"):
            self.assertEqual([dw.in_day(t, d["start"], d["end"]) for d in (a, b)].count(True), 1)


class Cli(unittest.TestCase):
    def run_cli(self, *args, **env):
        import os
        e = {k: v for k, v in os.environ.items() if not k.startswith("RSC_")}
        e.update(env)
        return subprocess.run([sys.executable, str(ROOT / "evidence/lib/day_window.py"), *args], capture_output=True, text=True, env=e)

    def test_prints_json_for_a_valid_day(self):
        res = self.run_cli("--date", "2026-11-25", "--now", "2026-11-27T09:00:00Z")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(res.stdout)["backfill"], True)

    def test_exits_2_with_the_reason_for_a_refused_day(self):
        res = self.run_cli("--date", "2026-11-27", "--now", "2026-11-27T09:00:00Z")
        self.assertEqual(res.returncode, 2)
        self.assertIn("not a complete day", res.stderr)
        self.assertEqual(res.stdout, "")

    def test_the_environment_supplies_the_defaults(self):
        res = self.run_cli("--now", "2026-11-27T09:00:00Z", RSC_DATE="2026-11-20")
        self.assertEqual(json.loads(res.stdout)["covers_date"], "2026-11-20")
        res = self.run_cli("--now", "2026-11-27T00:10:00Z", RSC_ALLOW_EARLY="1")
        self.assertEqual(res.returncode, 0, res.stderr)
        res = self.run_cli("--now", "2026-11-27T00:10:00Z", RSC_SETTLE_MINUTES="5")
        self.assertEqual(res.returncode, 0, res.stderr)
        res = self.run_cli("--now", "2026-11-27T00:10:00Z")
        self.assertEqual(res.returncode, 2)


if __name__ == "__main__":
    unittest.main()
