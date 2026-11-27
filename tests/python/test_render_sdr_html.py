import json
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import coverage  # noqa: E402
import generate_sdr  # noqa: E402
import render_sdr_html  # noqa: E402
import test_coverage as tc  # noqa: E402
import test_generate_sdr as tg  # noqa: E402

XSS = "<script>alert(1)</script>"


def build(record_text=XSS):
    d = tc.base_data()
    d["records"]["KSI-CMT-VTD"] = dict(tc.FULL_RECORD, measures=record_text,
                                       **{"control-decisions": tc.decide_all_open(d["ksis"])})
    d["ksis"]["KSI-CMT-VTD"] = dict(d["ksis"]["KSI-CMT-VTD"], name=XSS, statement=XSS)
    d["manifests"] = {tc.AR1: tc.manifest(**{"org/a": "collected", "org/b": "collected"}),
                      tc.AR2: tc.manifest(**{"org/a": "collected", "org/b": "error"})}
    cov = json.loads(json.dumps(coverage.rollup(d, "integration")))
    sdr = generate_sdr.build_sdr(cov, d["records"], tg.FREQS, tg.results_from_log(),
                                 datetime(2026, 11, 24, tzinfo=timezone.utc))
    # Evidence text is attacker-influenced in real runs; make it hostile here too.
    sdr["keySecurityIndicators"][0]["ksiEvidence"].append(
        {"evidenceType": "Report", "evidenceText": f"{tc.AR1}: failed {XSS}"})
    return sdr, cov


class Viewer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdr, cls.cov = build()
        cls.page = render_sdr_html.render(cls.sdr, cls.cov)

    def test_script_in_data_renders_as_text(self):
        self.assertNotIn(XSS, self.page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.page)

    def test_only_our_inline_script_exists(self):
        self.assertEqual(len(re.findall(r"<script\b", self.page)), 1)

    def test_offline(self):
        self.assertIsNone(re.search(r"""(src|href|action)\s*=\s*["']?\s*(https?:)?//""", self.page))
        self.assertNotIn("<link", self.page)
        self.assertNotIn("<img", self.page)
        self.assertNotIn("@import", self.page)
        self.assertNotIn("url(", self.page)

    def test_banner(self):
        self.assertIn("Local run. Not certification evidence.", self.page)

    def test_state_and_result_are_separate_signals(self):
        self.assertIn('class="state state-in-progress"', self.page)
        self.assertIn('class="result result-failed"', self.page)
        card = re.search(r'<details class="ksi" id="ksi-KSI-CMT-VTD".*?</summary>', self.page, re.S).group(0)
        self.assertIn('data-state="In progress"', card)
        self.assertIn('data-result="failed"', card)

    def test_all_ksis_listed_and_filterable(self):
        self.assertEqual(self.page.count('class="ksi"'), len(self.cov["ksis"]))
        self.assertIn('id="q"', self.page)

    def test_ksi_page_content(self):
        for needle in ("Targets reached", "missing: org/b", "addressed", "cm-3, cm-3.2", "Planned cycle: daily"):
            self.assertIn(needle, self.page)

    def test_result_parsing(self):
        entry = {"ksiEvidence": [{"evidenceText": "A.AR1: failed (evaluator opa)."},
                                 {"evidenceText": "A.AR2: not evaluated. Target coverage unknown."}]}
        res = render_sdr_html.results_by_ar(entry)
        self.assertEqual(res, {"A.AR1": "failed", "A.AR2": "not evaluated"})
        self.assertEqual(render_sdr_html.overall_result(res), "failed")
        self.assertEqual(render_sdr_html.overall_result({}), "no results")


if __name__ == "__main__":
    unittest.main()
