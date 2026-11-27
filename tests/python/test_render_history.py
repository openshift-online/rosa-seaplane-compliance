import json
import re
import sys
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_sdr  # noqa: E402
import history_summary as hs  # noqa: E402
import render_sdr_html  # noqa: E402
import test_generate_sdr as tg  # noqa: E402
import test_render_sdr_html as base  # noqa: E402
from history_fakes import make_record, utc  # noqa: E402

XSS = "<script>alert(1)</script>"
NOW = utc(2026, 11, 27, 12, 0)
K = "KSI-CMT-VTD"


def recs(results_by_days_back):
    return [make_record(NOW - timedelta(days=d), {(K, tg.tc.AR1): r}) for d, r in results_by_days_back.items()]


def summary(results=None):
    return hs.summarize(recs(results or {0: "fail", 1: "pass", 2: "error", 4: "pass"}), NOW)


class Page(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdr, cls.cov = base.build()
        cls.summary = summary()
        cls.page = render_sdr_html.render(cls.sdr, cls.cov, None, None, cls.summary)
        cls.html = render_sdr_html.render_history_page(cls.summary)

    def test_tab_exists_only_with_history(self):
        self.assertIn('data-tab="page-history"', self.page)
        self.assertIn('id="page-history"', self.page)
        plain = render_sdr_html.render(self.sdr, self.cov)
        self.assertNotIn("page-history", plain)

    def test_the_available_history_is_stated(self):
        self.assertIn("History available: 5 days; the requirement is up to 365.", self.html)

    def test_day_strip_has_30_cells_each_with_a_glyph_and_a_title(self):
        cells = re.findall(r'<span class="dc dc-([a-z-]+)" title="([^"]+)">(.)</span>', self.html)
        per_row = 30
        self.assertEqual(len(cells) % per_row, 0)
        for cls, title, glyph in cells:
            self.assertIn(glyph, "✓✗!·")  # never colour alone
            self.assertRegex(title, r"^\d{4}-\d{2}-\d{2}: ")
        kinds = {c[0] for c in cells}
        self.assertEqual(kinds, {"pass", "fail", "error", "no-record"})

    def test_glyphs_match_results(self):
        for cls, glyph in (("pass", "✓"), ("fail", "✗"), ("error", "!"), ("no-record", "·")):
            self.assertIn(f'dc-{cls}" title=', self.html)
            self.assertRegex(self.html, rf'dc-{cls}" title="[^"]+">{glyph}<')

    def test_alarm_banner(self):
        stale = render_sdr_html.render_history_page(hs.summarize([make_record(NOW - timedelta(days=9), {(K, tg.tc.AR1): "pass"})], NOW))
        self.assertIn('role="alert"', stale)
        self.assertIn("ALERT stale", stale)
        warn = render_sdr_html.render_history_page(hs.summarize([make_record(NOW - timedelta(days=3), {(K, tg.tc.AR1): "pass"})], NOW))
        self.assertIn("WARN stale", warn)
        self.assertIn("alarm-warn", warn)
        self.assertNotIn('role="alert"', warn)
        self.assertNotIn('role="alert"', self.html)
        self.assertIn("No alarms", self.html)

    def test_the_summary_numbers_are_shown(self):
        self.assertIn("2 / 1 / 1 / 0 / 26", self.html)  # pass / fail / error / not collected / none
        self.assertIn("longest", self.html.lower() + "longest")  # the column exists

    def test_nothing_recorded_says_how_to_start(self):
        html = render_sdr_html.render_history_page(hs.summarize([], NOW))
        self.assertIn("ALERT no-history", html)
        self.assertIn("make history-init", html)

    def test_hostile_text_is_escaped(self):
        s = json.loads(json.dumps(self.summary))
        ent = s["ksis"][K]
        s["ksis"][XSS] = ent
        ent["methods"][0]["ar"] = XSS
        s["alarms"] = [{"code": XSS, "message": XSS}]
        s["history"]["statement"] = XSS
        html = render_sdr_html.render_history_page(s)
        self.assertNotIn(XSS, html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_page_stays_offline_with_one_inline_script(self):
        self.assertEqual(len(re.findall(r"<script\b", self.page)), 1)
        self.assertIsNone(re.search(r"""(src|href|action)\s*=\s*["']?\s*(https?:)?//""", self.page))
        for bad in ("<link", "<img", "@import", "url(", "<iframe", "fetch(", "XMLHttpRequest"):
            self.assertNotIn(bad, self.page)


class SdrLine(unittest.TestCase):
    def build(self, history):
        d, roll = tg.make_coverage()
        return generate_sdr.build_sdr(roll, d["records"], tg.FREQS, tg.results_from_log(), tg.NOW, history=history)

    def entry(self, sdr):
        return next(k for k in sdr["keySecurityIndicators"] if k["ksiId"] == K)

    def test_a_30_day_line_is_added_when_history_exists(self):
        sdr = self.build(summary({0: "pass", 1: "pass", 2: "fail"}))
        texts = [e["evidenceText"] for e in self.entry(sdr)["ksiEvidence"]]
        self.assertIn("30-day history: 2 of 3 recorded days passed, 1 failed, 27 days without a record.", texts)
        generate_sdr.validate_sdr(sdr)

    def test_the_line_is_a_valid_evidence_item_with_a_date(self):
        item = self.entry(self.build(summary()))["ksiEvidence"][-1]
        self.assertEqual(item["evidenceType"], "Report")
        self.assertRegex(item["lastUpdated"], r"^\d{4}-\d{2}-\d{2}$")

    def test_nothing_is_added_without_history(self):
        for h in (None, hs.summarize([], NOW)):
            sdr = self.build(h)
            self.assertFalse(any("30-day history" in e["evidenceText"] for k in sdr["keySecurityIndicators"] for e in k["ksiEvidence"]))

    def test_other_ksis_without_a_series_get_no_line(self):
        sdr = self.build(summary())
        other = next(k for k in sdr["keySecurityIndicators"] if k["ksiId"] == "KSI-CMT-LMC")
        self.assertFalse(any("30-day history" in e["evidenceText"] for e in other["ksiEvidence"]))

    def test_the_sdr_stays_free_of_messages_and_leaks(self):
        text = json.dumps(self.build(summary()))
        self.assertEqual(generate_sdr.find_leaks(text), [])


if __name__ == "__main__":
    unittest.main()
