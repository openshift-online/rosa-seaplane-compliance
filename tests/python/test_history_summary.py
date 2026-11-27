import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import history_summary as hs  # noqa: E402
from history_fakes import make_record, utc  # noqa: E402

K = "KSI-AAA-BBB"
A1, A2 = "AR.1", "AR.2"
NOW = utc(2026, 11, 27, 12, 0)  # today = 2026-11-27


def dayrec(days_back, results, suffix="a1b2c3", hour=9):
    d = (NOW - timedelta(days=days_back)).replace(hour=hour)
    return make_record(d, {(K, ar): r for ar, r in (results if isinstance(results, dict) else {A1: results}).items()}, suffix)


class DayResults(unittest.TestCase):
    def test_the_latest_record_of_a_day_wins_for_the_days_status(self):
        recs = [dayrec(1, "fail", "aaaaaa", 8), dayrec(1, "pass", "bbbbbb", 16)]
        s = hs.summarize(recs + [dayrec(0, "pass")], NOW)
        self.assertEqual(s["ksis"][K]["summary30"]["pass_days"], 2)
        self.assertEqual(s["ksis"][K]["summary30"]["fail_days"], 0)

    def test_both_records_of_a_rerun_day_are_preserved_in_the_series(self):
        recs = [dayrec(1, "fail", "aaaaaa", 8), dayrec(1, "pass", "bbbbbb", 16), dayrec(0, "pass")]
        day = next(d for d in hs.summarize(recs, NOW)["ksis"][K]["daily"] if d["date"] == "2026-11-26")
        self.assertEqual([r["methods"][A1] for r in day["runs"]], ["fail", "pass"])
        self.assertEqual(day["result"], "pass")
        self.assertEqual(len(day["runs"]), 2)

    def test_a_ksi_day_is_the_worst_of_its_methods(self):
        s = hs.summarize([dayrec(0, {A1: "pass", A2: "error"})], NOW)
        self.assertEqual(s["ksis"][K]["daily"][0]["result"], "error")
        s = hs.summarize([dayrec(0, {A1: "error", A2: "fail"})], NOW)
        self.assertEqual(s["ksis"][K]["daily"][0]["result"], "fail")
        s = hs.summarize([dayrec(0, {A1: "pass", A2: "pass"})], NOW)
        self.assertEqual(s["ksis"][K]["daily"][0]["result"], "pass")

    def test_the_methods_keep_their_own_series(self):
        s = hs.summarize([dayrec(0, {A1: "pass", A2: "fail"})], NOW)
        by = {m["ar"]: m for m in s["ksis"][K]["methods"]}
        self.assertEqual((by[A1]["summary30"]["pass_days"], by[A2]["summary30"]["fail_days"]), (1, 1))

    def test_a_methods_latest_record_wins_only_among_records_that_contain_it(self):
        recs = [dayrec(0, {A1: "pass", A2: "fail"}, "aaaaaa", 8), dayrec(0, {A1: "pass"}, "bbbbbb", 16)]
        d = hs.summarize(recs, NOW)["ksis"][K]["daily"][0]
        self.assertEqual(d["methods"], {A1: "pass", A2: "fail"})


class Windows(unittest.TestCase):
    def test_30_days_counts_every_day_including_before_the_history_started(self):
        recs = [dayrec(i, "pass") for i in range(0, 14)]
        s = hs.summarize(recs, NOW)["ksis"][K]["summary30"]
        self.assertEqual((s["days"], s["recorded_days"], s["pass_days"], s["days_without_record"]), (30, 14, 14, 16))

    def test_counts_by_result(self):
        recs = [dayrec(0, "pass"), dayrec(1, "fail"), dayrec(2, "error"), dayrec(3, "pass")]
        s = hs.summarize(recs, NOW)["ksis"][K]["summary30"]
        self.assertEqual((s["pass_days"], s["fail_days"], s["error_days"], s["recorded_days"]), (2, 1, 1, 4))

    def test_the_year_is_the_history_that_is_available(self):
        recs = [dayrec(i, "pass") for i in range(0, 10)]
        s = hs.summarize(recs, NOW)
        y = s["ksis"][K]["summaryYear"]
        self.assertEqual((y["days"], y["recorded_days"], y["days_without_record"], y["requirement_days"]), (10, 10, 0, 365))
        self.assertEqual(s["history"]["available_days"], 10)
        self.assertEqual(s["history"]["statement"], "History available: 10 days; the requirement is up to 365.")

    def test_the_year_is_capped_at_365_days(self):
        recs = [dayrec(400, "pass"), dayrec(200, "pass"), dayrec(0, "pass")]
        s = hs.summarize([r for r in recs], NOW)
        y = s["ksis"][K]["summaryYear"]
        self.assertEqual(y["days"], 365)
        self.assertEqual(y["recorded_days"], 2)  # the 400-day-old record is outside the year
        self.assertEqual(s["history"]["available_days"], 365)

    def test_missing_days_and_the_longest_gap_inside_the_available_range(self):
        recs = [dayrec(9, "pass"), dayrec(8, "pass"), dayrec(4, "pass"), dayrec(0, "pass")]
        y = hs.summarize(recs, NOW)["ksis"][K]["summaryYear"]
        self.assertEqual(y["days"], 10)
        self.assertEqual(y["missing_days"], ["2026-11-20", "2026-11-21", "2026-11-22", "2026-11-24", "2026-11-25", "2026-11-26"])
        self.assertEqual(y["longest_gap_days"], 3)

    def test_today_is_not_a_gap_until_it_has_a_record(self):
        recs = [dayrec(3, "pass"), dayrec(2, "pass"), dayrec(1, "pass")]  # nothing yet today
        s = hs.summarize(recs, NOW)
        self.assertEqual(s["meta"]["last_counted_day"], "2026-11-26")
        self.assertEqual(s["ksis"][K]["summaryYear"]["days_without_record"], 0)
        self.assertEqual(s["ksis"][K]["summaryYear"]["longest_gap_days"], 0)

    def test_strip_has_30_cells_oldest_first(self):
        s = hs.summarize([dayrec(0, "fail"), dayrec(2, "pass")], NOW)["ksis"][K]["strip"]
        self.assertEqual(len(s), 30)
        self.assertEqual((s[-1]["date"], s[-1]["result"]), ("2026-11-27", "fail"))
        self.assertEqual((s[-2]["result"], s[-3]["result"]), ("no-record", "pass"))

    def test_the_method_sparse_in_history_starts_at_its_own_first_day(self):
        recs = [dayrec(5, {A1: "pass"}), dayrec(0, {A1: "pass", A2: "pass"})]
        by = {m["ar"]: m for m in hs.summarize(recs, NOW)["ksis"][K]["methods"]}
        self.assertEqual(by[A2]["summaryYear"]["days"], 1)
        self.assertEqual(by[A1]["summaryYear"]["days"], 6)


class Alarms(unittest.TestCase):
    def test_no_records_is_an_alarm(self):
        s = hs.summarize([], NOW)
        self.assertEqual([(a["level"], a["code"]) for a in s["alarms"]], [("ALERT", "no-history")])
        self.assertEqual(s["history"]["statement"], "History available: 0 days; the requirement is up to 365.")
        self.assertEqual(s["ksis"], {})

    def test_a_fresh_series_has_no_alarm(self):
        recs = [dayrec(i, "pass") for i in range(0, 5)]
        self.assertEqual(hs.summarize(recs, NOW)["alarms"], [])

    def alarms(self, days_back):
        return [(a["level"], a["code"]) for a in hs.summarize([dayrec(days_back, "pass")], NOW)["alarms"]]

    def test_levels_by_how_far_the_newest_covered_day_is_behind(self):
        self.assertEqual(self.alarms(0), [])                      # (a record covering today, from before days were partitioned)
        self.assertEqual(self.alarms(1), [])                      # yesterday: a normal run
        self.assertEqual(self.alarms(2), [])                      # one day behind yesterday: not yet
        self.assertEqual(self.alarms(3), [("WARN", "stale")])     # more than 1 day behind yesterday
        self.assertEqual(self.alarms(4), [("ALERT", "stale")])    # more than 3 days old
        self.assertEqual(self.alarms(30), [("ALERT", "stale")])

    def test_the_warn_message_says_a_daily_run_was_missed_and_how_it_is_filled(self):
        a = hs.summarize([dayrec(3, "pass")], NOW)["alarms"][0]
        self.assertIn("2026-11-24", a["message"])
        self.assertIn("make daily", a["message"])

    def test_every_alarm_has_a_level(self):
        for recs in ([], [dayrec(3, "pass")], [dayrec(20, "pass"), dayrec(10, "pass")]):
            for a in hs.summarize(recs, NOW)["alarms"]:
                self.assertIn(a["level"], ("WARN", "ALERT"))

    def test_staleness_follows_the_covered_day_not_when_the_run_happened(self):
        # made just now, but about a day 10 days ago: the series is still stale
        old = make_record(NOW, {(K, A1): "pass"}, covers="2026-11-17", backfill=True)
        self.assertEqual([a["code"] for a in hs.summarize([old], NOW)["alarms"]], ["stale"])

    def test_gap_when_two_records_are_more_than_3_days_apart(self):
        recs = [dayrec(10, "pass"), dayrec(5, "pass"), dayrec(1, "pass")]
        a = hs.summarize(recs, NOW)["alarms"]
        self.assertEqual([x["code"] for x in a], ["gap"])
        self.assertIn("5 days", a[0]["message"])

    def test_three_days_apart_is_within_the_minimum_cadence(self):
        recs = [dayrec(7, "pass"), dayrec(4, "pass"), dayrec(1, "pass")]
        self.assertEqual(hs.summarize(recs, NOW)["alarms"], [])

    def test_both_alarms_can_fire(self):
        recs = [dayrec(20, "pass"), dayrec(10, "pass")]
        self.assertEqual(sorted(a["code"] for a in hs.summarize(recs, NOW)["alarms"]), ["gap", "stale"])

    def test_a_gap_is_an_alert_even_when_the_series_is_current(self):
        recs = [dayrec(10, "pass"), dayrec(5, "pass"), dayrec(1, "pass")]
        self.assertEqual([(a["level"], a["code"]) for a in hs.summarize(recs, NOW)["alarms"]], [("ALERT", "gap")])

    def test_exactly_three_days_between_covered_days_is_not_a_gap(self):
        recs = [dayrec(7, "pass"), dayrec(4, "pass"), dayrec(1, "pass")]
        self.assertEqual(hs.summarize(recs, NOW)["alarms"], [])

    def test_alerts_come_before_warnings(self):
        al = hs.summarize([dayrec(10, "pass"), dayrec(3, "pass")], NOW)["alarms"]
        self.assertEqual([(a["level"], a["code"]) for a in al], [("ALERT", "gap"), ("WARN", "stale")])


def ncrec(days_back, suffix="c0c0c0", basis=None):
    d = NOW - timedelta(days=days_back)
    return make_record(NOW, {(K, A1): "not_collected"}, suffix, covers=d.date().isoformat(), backfill=True,
                       basis={A1: "state"})


class NotCollected(unittest.TestCase):
    def test_counted_apart_and_never_a_pass(self):
        s = hs.summarize([dayrec(0, "pass"), ncrec(1)], NOW)["ksis"][K]["summary30"]
        self.assertEqual((s["pass_days"], s["not_collected_days"], s["fail_days"]), (1, 1, 0))

    def test_never_replaces_a_real_result_for_the_same_day(self):
        real = dayrec(1, "fail", "aaaaaa", 8)
        later = make_record(NOW, {(K, A1): "not_collected"}, "dddddd", covers="2026-11-26", backfill=True, basis={A1: "state"})
        for recs in ([real, later], [later, real]):
            s = hs.summarize(recs + [dayrec(0, "pass")], NOW)["ksis"][K]["summary30"]
            self.assertEqual((s["fail_days"], s["not_collected_days"]), (1, 0))

    def test_ksi_day_is_worst_of_methods_and_not_collected_beats_pass(self):
        r = make_record(NOW, {(K, A1): "pass", (K, A2): "not_collected"}, covers="2026-11-26", backfill=True,
                        basis={A2: "state"})
        s = hs.summarize([r, dayrec(0, "pass")], NOW)["ksis"][K]["summary30"]
        self.assertEqual((s["pass_days"], s["not_collected_days"]), (1, 1))

    def test_a_not_collected_day_counts_in_the_longest_gap_but_not_as_missing(self):
        recs = [dayrec(0, "pass"), ncrec(1, "a00001"), ncrec(2, "a00002"), dayrec(3, "pass")]
        y = hs.summarize(recs, NOW)["ksis"][K]["summaryYear"]
        self.assertEqual((y["longest_gap_days"], y["days_without_record"]), (2, 0))

    def test_the_sentence_mentions_them(self):
        e = hs.summarize([dayrec(0, "pass"), ncrec(1)], NOW)["ksis"][K]
        self.assertIn("1 not collected", hs.history_sentence(e))

    def test_a_backfilled_record_is_filed_by_the_day_it_covers(self):
        r = make_record(NOW, {(K, A1): "pass"}, covers="2026-11-20", backfill=True)
        d = hs.summarize([r, dayrec(0, "pass")], NOW)["ksis"][K]["daily"]
        self.assertEqual(next(x for x in d if x["date"] == "2026-11-20")["result"], "pass")

    def test_reruns_are_ordered_by_finished_at(self):
        a = dayrec(1, "pass", "aaaaaa", 8)
        b = dayrec(1, "fail", "bbbbbb", 16)
        day = next(x for x in hs.summarize([b, a, dayrec(0, "pass")], NOW)["ksis"][K]["daily"] if x["date"] == "2026-11-26")
        self.assertEqual((day["result"], [r["methods"][A1] for r in day["runs"]]), ("fail", ["pass", "fail"]))


class Outputs(unittest.TestCase):
    def setUp(self):
        self.recs = [dayrec(i, "pass" if i % 2 else "fail") for i in range(0, 6)]

    def test_summaries_are_deterministic(self):
        a = json.dumps(hs.summarize(self.recs, NOW), sort_keys=True)
        b = json.dumps(hs.summarize(list(reversed(self.recs)), NOW), sort_keys=True)
        self.assertEqual(a, b)

    def test_sentence(self):
        recs = [dayrec(i, "pass") for i in range(2, 12)] + [dayrec(0, "fail"), dayrec(1, "error")]
        e = hs.summarize(recs, NOW)["ksis"][K]
        self.assertEqual(hs.history_sentence(e),
                         "30-day history: 10 of 12 recorded days passed, 1 failed, 1 could not be judged, 18 days without a record.")

    def test_sentence_example_from_the_directive(self):
        recs = [dayrec(i, "pass") for i in range(2, 14)] + [dayrec(0, "fail"), dayrec(1, "fail")]
        self.assertEqual(hs.history_sentence(hs.summarize(recs, NOW)["ksis"][K]),
                         "30-day history: 12 of 14 recorded days passed, 2 failed, 16 days without a record.")

    def test_no_sentence_without_history(self):
        self.assertEqual(hs.history_sentence(None), "")
        self.assertEqual(hs.history_sentence(hs.summarize([], NOW)["ksis"].get(K)), "")

    def test_outputs_are_written_and_carry_the_daily_data_in_full(self):
        s = hs.summarize(self.recs, NOW)
        with tempfile.TemporaryDirectory() as t:
            hs.write_outputs(s, Path(t) / "h", Path(t) / "sdr/ksi-metrics.json")
            self.assertTrue((Path(t) / "h/summary.json").is_file())
            md = (Path(t) / "h/summary.md").read_text()
            m = json.loads((Path(t) / "sdr/ksi-metrics.json").read_text())
        self.assertIn("History available: 6 days; the requirement is up to 365.", md)
        self.assertEqual(len(m["ksis"][K]["daily"]), 6)  # the daily data is not replaced by the summary
        self.assertIn("no field for historical metrics", m["meta"]["note"])
        self.assertEqual(m["meta"]["structure"], "rsc-ksi-metrics/1")

    def test_markdown_states_the_alarm(self):
        md = hs.render_markdown(hs.summarize([dayrec(9, "pass")], NOW))
        self.assertIn("**ALERT** **STALE**", md)
        self.assertIn("**WARN** **STALE**", hs.render_markdown(hs.summarize([dayrec(3, "pass")], NOW)))

    def test_no_ids_or_emails_in_the_outputs(self):
        text = json.dumps(hs.summarize(self.recs, NOW)) + hs.render_markdown(hs.summarize(self.recs, NOW))
        for needle in ("arn:aws", "@", "/Users"):
            self.assertNotIn(needle, text)


if __name__ == "__main__":
    unittest.main()
