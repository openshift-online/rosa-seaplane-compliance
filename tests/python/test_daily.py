import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "evidence/lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_record  # noqa: E402
import daily  # noqa: E402
import history  # noqa: E402
from history_fakes import make_record, utc  # noqa: E402

NOW = utc(2026, 11, 27, 9, 0)        # today 2026-11-27, so yesterday is 2026-11-26
K = "KSI-AAA-BBB"
EVENT1, EVENT2, STATE1 = "RSC.T.CTRL01.AR02", "RSC.T.CTRL03.AR01", "RSC.T.CTRL01.AR01"
BASIS = {EVENT1: {"basis": "event", "state_rules": set()}, EVENT2: {"basis": "event", "state_rules": set()},
         STATE1: {"basis": "state", "state_rules": set()}}


class Missing(unittest.TestCase):
    TODAY = NOW.date()

    def days(self, recorded=(), n=5):
        return [d.isoformat() for d in daily.missing_days({NOW.date().replace(day=int(r)) for r in recorded}, self.TODAY, n)]

    def test_the_days_before_yesterday_without_a_record_oldest_first(self):
        self.assertEqual(self.days(), ["2026-11-22", "2026-11-23", "2026-11-24", "2026-11-25"])

    def test_a_day_with_a_record_is_not_missing(self):
        self.assertEqual(self.days(recorded=(22, 24)), ["2026-11-23", "2026-11-25"])

    def test_yesterday_and_today_are_never_a_backfill(self):
        for n in (3, 5, 30):
            self.assertNotIn("2026-11-26", self.days(n=n))
            self.assertNotIn("2026-11-27", self.days(n=n))
        self.assertEqual(self.days(n=3), ["2026-11-24", "2026-11-25"])

    def test_a_record_for_yesterday_alone_still_leaves_the_older_days_missing(self):
        self.assertEqual(self.days(recorded=(26,)), ["2026-11-22", "2026-11-23", "2026-11-24", "2026-11-25"])

    def test_everything_recorded_means_nothing_to_do(self):
        self.assertEqual(self.days(recorded=(22, 23, 24, 25, 26)), [])

    def test_the_window_is_counted_back_from_today(self):
        self.assertEqual(self.days(n=10)[0], "2026-11-17")


class Settings(unittest.TestCase):
    def test_default_is_five(self):
        self.assertEqual(daily.backfill_days({}), 5)
        self.assertEqual(daily.backfill_days({"RSC_BACKFILL_DAYS": ""}), 5)

    def test_it_must_be_at_least_three_and_below_what_cloudtrail_keeps(self):
        self.assertEqual(daily.backfill_days({"RSC_BACKFILL_DAYS": "3"}), 3)
        self.assertEqual(daily.backfill_days({"RSC_BACKFILL_DAYS": "89"}), 89)
        for bad in ("2", "0", "-1", "90", "five", "3.5"):
            with self.assertRaises(daily.DailyError, msg=bad):
                daily.backfill_days({"RSC_BACKFILL_DAYS": bad})


class FakeRunner:
    """Records every command. `fail(cmd, env)` says which should fail; `on_record` runs when a step 'succeeds'."""

    def __init__(self, fail=None, on_record=None):
        self.calls, self.fail, self.on_record = [], fail or (lambda cmd, env: False), on_record

    def __call__(self, cmd, env, log=None):
        cmd = [str(c) for c in cmd]
        self.calls.append({"cmd": cmd, "env": dict(env), "log": log})
        if self.fail(cmd, env):
            return 1
        if self.on_record:
            self.on_record(cmd, env)
        return 0


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        for ar in BASIS:
            f = self.root / "evidence" / f"{ar}.sh"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("#!/bin/sh\n")
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        (self.root / "evidence/output").mkdir()
        (self.root / "output").mkdir()
        (self.root / "evidence/output/keep.json").write_text("latest evidence")
        (self.root / "output/findings.json").write_text("latest findings")
        self.store = history.Store(history.LocalBackend(Path(self.tmp.name) / "h"))
        self.store.init()
        self.out = []

    def add_record(self, covers, backfill=True, suffix="a1b2c3"):
        self.store.put_record(make_record(NOW - timedelta(hours=1), {(K, EVENT1): "pass"}, suffix, covers=covers, backfill=backfill))

    def run_daily(self, requested=None, runner=None, now=NOW, environ=None):
        self.runner = runner or FakeRunner()
        code = daily.daily(requested, environ or {}, self.runner, self.store, now, BASIS, self.root, out=self.out.append)
        return code

    def text(self):
        return "\n".join(self.out)


class Orchestration(Fixture):
    def test_backfills_oldest_first_then_the_normal_run(self):
        self.assertEqual(self.run_daily(), 0)
        plan = self.out[0]
        self.assertEqual(plan, "Plan: 2026-11-22 (backfill), 2026-11-23 (backfill), 2026-11-24 (backfill), "
                               "2026-11-25 (backfill), 2026-11-26 (normal run)")
        record_days = [c["cmd"][c["cmd"].index("--date") + 1] for c in self.runner.calls if "--date" in c["cmd"]]
        self.assertEqual(record_days, ["2026-11-22", "2026-11-23", "2026-11-24", "2026-11-25"])
        # the normal run comes last and covers yesterday, told to every make step through RSC_DATE
        normal = [c for c in self.runner.calls if c["cmd"][0] == "make"]
        self.assertEqual([c["cmd"][1] for c in normal],
                         ["run-local", "coverage", "findings", "trace", "record", "history-summary", "sdr-view"])
        self.assertEqual({c["env"]["RSC_DATE"] for c in normal}, {"2026-11-26"})
        self.assertEqual(next(c["cmd"] for c in normal if c["cmd"][1] == "record"), ["make", "record", "DATE=2026-11-26"])
        self.assertEqual(self.runner.calls[-7]["cmd"][0], "make")                       # nothing of a backfill after it
        self.assertIn("Backfilled: 2026-11-22, 2026-11-23, 2026-11-24, 2026-11-25", self.text())
        self.assertIn("Normal run: 2026-11-26 done", self.text())

    def test_only_the_missing_days_are_backfilled(self):
        self.add_record("2026-11-23")
        self.add_record("2026-11-25")
        self.run_daily()
        self.assertEqual(self.out[0], "Plan: 2026-11-22 (backfill), 2026-11-24 (backfill), 2026-11-26 (normal run)")

    def test_nothing_missing_is_just_the_normal_run_and_says_so(self):
        for d in ("2026-11-22", "2026-11-23", "2026-11-24", "2026-11-25"):
            self.add_record(d)
        self.assertEqual(self.run_daily(), 0)
        self.assertEqual(self.out[0], "Plan: 2026-11-26 (normal run)")
        self.assertIn("Backfilled: nothing", self.text())

    def test_the_backfill_window_follows_the_setting(self):
        self.run_daily(environ={"RSC_BACKFILL_DAYS": "3"})
        self.assertEqual(self.out[0], "Plan: 2026-11-24 (backfill), 2026-11-25 (backfill), 2026-11-26 (normal run)")

    def test_a_second_run_never_backfills_again_and_appends_a_rerun_for_yesterday(self):
        def append(cmd, env):
            if any(x.endswith("build_record.py") for x in cmd):
                day = cmd[cmd.index("--date") + 1]
                self.store.put_record(make_record(NOW, {(K, EVENT1): "pass"}, os.urandom(3).hex(), covers=day, backfill=True))
            if cmd[:2] == ["make", "record"]:
                self.store.put_record(make_record(NOW, {(K, EVENT1): "pass"}, os.urandom(3).hex(), covers=cmd[2][5:], backfill=False))

        self.run_daily(runner=FakeRunner(on_record=append))
        self.assertEqual(len(self.store.records()), 5)
        self.out.clear()
        self.run_daily(runner=FakeRunner(on_record=append))
        self.assertEqual(self.out[0], "Plan: 2026-11-26 (normal run)")
        self.assertEqual(len([r for r in self.store.records() if r["covers_date"] == "2026-11-26"]), 2)
        self.assertEqual(len(self.store.records()), 6)

    def test_a_record_that_is_not_well_formed_stops_the_run_before_anything_is_collected(self):
        self.add_record("2026-11-23")
        p = self.store.backend.root / next(k for k in self.store.backend.list(history.RUNS_PREFIX))
        doc = json.loads(p.read_text())
        doc["environment"] = 42
        p.write_text(json.dumps(doc))
        with self.assertRaises(history.StoreError):
            self.run_daily()
        self.assertEqual(self.runner.calls, [])

    def test_the_history_must_be_initialised_before_anything_runs(self):
        self.store = history.Store(history.LocalBackend(Path(self.tmp.name) / "empty"))
        with self.assertRaises(history.StoreError):
            self.run_daily()
        self.assertEqual(self.runner.calls, [])


class BackfillIsolation(Fixture):
    def test_only_event_collectors_run_and_never_a_state_collector(self):
        self.run_daily()
        collectors = [Path(c["cmd"][0]).name for c in self.runner.calls if c["cmd"][0].endswith(".sh")]
        self.assertEqual(sorted(set(collectors)), sorted([f"{EVENT1}.sh", f"{EVENT2}.sh"]))
        self.assertEqual(len(collectors), 2 * 4)                  # both event collectors, for each of the four days
        self.assertNotIn(f"{STATE1}.sh", collectors)

    def test_each_collector_is_given_its_day_and_a_folder_of_its_own(self):
        self.run_daily()
        for c in self.runner.calls:
            if not c["cmd"][0].endswith(".sh"):
                continue
            day = c["env"]["RSC_DATE"]
            self.assertEqual(c["env"]["RSC_EVIDENCE_DIR"], str(self.root / "output/backfill" / day / "evidence"))

    def test_the_latest_evidence_and_outputs_are_never_touched_or_named(self):
        self.run_daily()
        self.assertEqual((self.root / "evidence/output/keep.json").read_text(), "latest evidence")
        self.assertEqual((self.root / "output/findings.json").read_text(), "latest findings")
        latest_evidence, latest_out = str(self.root / "evidence/output"), str(self.root / "output")
        for c in self.runner.calls:
            if c["cmd"][0] == "make":
                continue                                               # the normal run uses the normal places
            for arg in c["cmd"][1:] + list(c["env"].values()):
                self.assertNotIn(latest_evidence, arg)
                if latest_out in arg:
                    self.assertIn(str(self.root / "output/backfill"), arg)   # only inside the backfill's own folder

    def test_no_scan_and_no_sdr_or_viewer_for_a_backfill(self):
        self.run_daily()
        steps = []
        for c in self.runner.calls:
            if c["env"].get("RSC_DATE") != "2026-11-26":
                steps.append(" ".join(c["cmd"]))
        text = "\n".join(steps)
        for forbidden in ("complyctl", "run-local", "sdr", "history-summary", "entrypoint"):
            self.assertNotIn(forbidden, text)

    def test_the_record_step_is_given_the_backfills_own_files_and_the_date(self):
        self.run_daily()
        rec = next(c["cmd"] for c in self.runner.calls if any(x.endswith("build_record.py") for x in c["cmd"]))
        day = rec[rec.index("--date") + 1]
        work = self.root / "output/backfill" / day
        for flag, path in (("--coverage", work / "coverage.json"), ("--trace", work / "trace.json"),
                           ("--findings", work / "out/findings.json"), ("--evidence-dir", work / "evidence")):
            self.assertEqual(rec[rec.index(flag) + 1], str(path))

    def test_the_policies_are_evaluated_over_the_backfills_folder(self):
        self.run_daily()
        f = next(c["cmd"] for c in self.runner.calls if any(x.endswith("build_findings.py") for x in c["cmd"]))
        day = f[f.index("--coverage") + 1].split("/")[-2]
        self.assertEqual(f[f.index("--evidence-dir") + 1], str(self.root / "output/backfill" / day / "evidence"))

    def test_a_rerun_of_a_backfill_starts_from_a_clean_folder(self):
        work = self.root / "output/backfill/2026-11-22"
        (work / "evidence").mkdir(parents=True)
        (work / "evidence/stale.json").write_text("from the last attempt")
        self.run_daily()
        self.assertFalse((work / "evidence/stale.json").exists())


def is_step(cmd, script):
    return any(x.endswith(script) for x in cmd)


class Failures(Fixture):
    def recorded_days(self):
        return [c["cmd"][c["cmd"].index("--date") + 1] for c in self.runner.calls if "--date" in c["cmd"]]

    def failing_collector_on(self, day):
        return FakeRunner(fail=lambda cmd, env: cmd[0].endswith(f"{EVENT1}.sh") and env.get("RSC_DATE") == day)

    def test_a_failing_collector_writes_no_record_for_that_day_and_the_rest_goes_on(self):
        code = self.run_daily(runner=self.failing_collector_on("2026-11-23"))
        self.assertEqual(code, 1)
        text = self.text()
        self.assertIn("FAILED: 2026-11-23: the event collector(s) RSC.T.CTRL01.AR02 failed, so no record was written", text)
        self.assertEqual(self.recorded_days(), ["2026-11-22", "2026-11-24", "2026-11-25"])   # no record step for the failed day
        self.assertIn("Backfilled: 2026-11-22, 2026-11-24, 2026-11-25", text)
        self.assertIn("Normal run: 2026-11-26 done", text)                                  # the normal run was not stopped

    def test_a_failing_policy_evaluation_writes_no_record_and_does_not_stop_the_normal_run(self):
        seen = {"n": 0}

        def fail(cmd, env):
            if is_step(cmd, "build_findings.py"):
                seen["n"] += 1
                return seen["n"] == 2                                                        # the second day's findings
            return False
        code = self.run_daily(runner=FakeRunner(fail=fail))
        self.assertEqual(code, 1)
        self.assertIn("FAILED: 2026-11-23: the findings step failed, so no record was written", self.text())
        self.assertIn("Normal run: 2026-11-26 done", self.text())
        self.assertNotIn("2026-11-23", self.recorded_days())

    def test_the_failed_day_is_tried_again_by_the_next_run(self):
        self.run_daily(runner=self.failing_collector_on("2026-11-23"))
        for d in ("2026-11-22", "2026-11-24", "2026-11-25"):
            self.add_record(d)                                                              # what the successful days left
        self.out.clear()
        self.run_daily()
        self.assertEqual(self.out[0], "Plan: 2026-11-23 (backfill), 2026-11-26 (normal run)")

    def test_a_failing_normal_run_stops_at_the_failing_step_and_is_reported(self):
        code = self.run_daily(runner=FakeRunner(fail=lambda cmd, env: cmd[:2] == ["make", "trace"]))
        self.assertEqual(code, 1)
        steps = [c["cmd"][1] for c in self.runner.calls if c["cmd"][0] == "make"]
        self.assertEqual(steps, ["run-local", "coverage", "findings", "trace"])
        self.assertIn("FAILED: 2026-11-26: `make trace` failed", self.text())
        self.assertIn("Backfilled: 2026-11-22", self.text())                                 # the backfills still count

    def test_every_failure_is_listed_at_the_end_and_the_exit_code_is_not_zero(self):
        code = self.run_daily(runner=FakeRunner(fail=lambda cmd, env: cmd[0].endswith(f"{EVENT2}.sh") or cmd[:2] == ["make", "sdr-view"]))
        self.assertEqual(code, 1)
        summary = self.text().split("== daily summary ==")[1]
        self.assertEqual(summary.count("FAILED:"), 5)                                        # four backfills and the normal run
        self.assertIn("Backfilled: nothing", summary)

    def test_the_exit_code_is_zero_only_when_everything_worked(self):
        self.assertEqual(self.run_daily(), 0)


class ExplicitDate(Fixture):
    def test_yesterday_is_the_normal_run_only(self):
        self.assertEqual(self.run_daily("2026-11-26"), 0)
        self.assertEqual(self.out[0], "Plan: 2026-11-26 (normal run)")
        self.assertTrue(all(c["cmd"][0] == "make" for c in self.runner.calls))

    def test_an_earlier_day_is_a_backfill_only_even_when_it_has_a_record(self):
        self.add_record("2026-11-24")
        self.assertEqual(self.run_daily("2026-11-24"), 0)
        self.assertEqual(self.out[0], "Plan: 2026-11-24 (backfill)")
        self.assertFalse(any(c["cmd"][0] == "make" for c in self.runner.calls))
        self.assertEqual({c["env"]["RSC_DATE"] for c in self.runner.calls}, {"2026-11-24"})

    def test_a_day_that_cannot_be_collected_is_refused_before_anything_runs(self):
        for bad in ("2026-11-27", "2026-11-28", "yesterday", "2026-02-30", "2026-08-01"):
            with self.assertRaises(daily.DailyError, msg=bad):
                self.run_daily(bad)
            self.assertEqual(self.runner.calls, [], bad)

    def test_the_settle_delay_refuses_an_early_run_before_anything_starts(self):
        early = utc(2026, 11, 27, 0, 45)
        with self.assertRaises(daily.DailyError) as cm:
            self.run_daily(now=early)
        self.assertIn("02:00:00Z", str(cm.exception))
        self.assertEqual(self.runner.calls, [])
        with self.assertRaises(daily.DailyError):
            self.run_daily("2026-11-26", now=early)
        self.assertEqual(self.run_daily(now=early, environ={"RSC_ALLOW_EARLY": "1"}), 0)
        self.assertEqual(self.run_daily("2026-11-26", now=early, environ={"RSC_SETTLE_MINUTES": "30"}), 0)

    def test_the_settle_delay_does_not_hold_back_an_older_day(self):
        self.assertEqual(self.run_daily("2026-11-24", now=utc(2026, 11, 27, 0, 5)), 0)

    def test_a_bad_setting_is_refused_before_anything_runs(self):
        with self.assertRaises(daily.DailyError):
            self.run_daily(environ={"RSC_BACKFILL_DAYS": "1"})
        self.assertEqual(self.runner.calls, [])
        with self.assertRaises(daily.DailyError):
            self.run_daily(environ={"RSC_SETTLE_MINUTES": "soon"})


class EventCollectors(unittest.TestCase):
    def test_the_event_methods_of_the_shipped_declaration_have_collectors_and_the_state_ones_are_left_out(self):
        basis = build_record.load_basis()
        found = {p.stem for p in daily.event_collectors(basis, ROOT)}
        self.assertEqual(found, {ar for ar, spec in basis.items() if spec["basis"] == "event"})
        self.assertTrue(found and found.isdisjoint({ar for ar, spec in basis.items() if spec["basis"] == "state"}))

    def test_an_event_method_without_a_collector_is_an_error(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "evidence").mkdir()
            with self.assertRaises(daily.DailyError):
                daily.event_collectors({"RSC.X.AR1": {"basis": "event", "state_rules": set()}}, Path(t))


if __name__ == "__main__":
    unittest.main()
