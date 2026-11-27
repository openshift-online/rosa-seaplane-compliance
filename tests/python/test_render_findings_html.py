import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_sdr  # noqa: E402
import render_sdr_html  # noqa: E402
import test_build_findings as tb  # noqa: E402
import test_render_sdr_html as base  # noqa: E402

XSS = "<script>alert(1)</script>"
IMG = "<img src=x onerror=alert(1)>"


def report(hostile=True):
    target = IMG if hostile else "central"
    evs = [
        tb.evaluation(tb.AR_IAM, target, tb.tag(f"{target}: iam-user {XSS} holds 1 active long-term credential(s) (access-key) {XSS}",
                                                "credentials.long-term-active")),
        tb.evaluation(tb.AR2, "org/a", tb.tag("org/a: PR #7 (x) merged to main without a non-author approval", "merge-review.no-approval")),
        tb.evaluation(tb.AR_LOG, "central", tb.tag("central: the Prowler collection was incomplete, so nothing can be concluded",
                                                  "change-logging.collection-incomplete")),
    ]
    manifests = {tb.AR2: {"targets": [{"name": "org/b", "status": "error", "error": f"denied {XSS}"}]}}
    return tb.build(evs, manifests)


class FindingsTab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdr, cls.cov = base.build()
        cls.rep = report()
        cls.page = render_sdr_html.render(cls.sdr, cls.cov, None, cls.rep)

    def test_hostile_text_renders_as_text(self):
        for raw in (XSS, IMG):
            self.assertNotIn(raw, self.page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.page)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", self.page)

    def test_only_our_one_inline_script(self):
        self.assertEqual(len(re.findall(r"<script\b", self.page)), 1)

    def test_offline(self):
        self.assertIsNone(re.search(r"""(src|href|action)\s*=\s*["']?\s*(https?:)?//""", self.page))
        for bad in ("<link", "<img", "@import", "url(", "<iframe", "fetch(", "XMLHttpRequest"):
            self.assertNotIn(bad, self.page)

    def test_tab_is_present_alongside_ksis(self):
        self.assertIn('<nav class="tabs">', self.page)
        self.assertIn('data-tab="page-findings">Findings</a>', self.page)
        self.assertIn('data-tab="page-ksis">KSIs</a>', self.page)
        self.assertIn('id="page-findings"', self.page)

    def test_three_kinds_findings_gaps_and_limits_are_separate_sections(self):
        for needle in ("<h2>Findings</h2>", "<h2>Gaps in our own work</h2>", "<h2>Limits of the checks</h2>"):
            self.assertIn(needle, self.page)
        order = [self.page.index(x) for x in ("<h2>Findings</h2>", "<h2>Gaps in our own work</h2>", "<h2>Limits of the checks</h2>")]
        self.assertEqual(order, sorted(order))
        for kind in ("violation", "incomplete-evidence", "not-reached"):
            self.assertIn(f'data-state="{kind}"', self.page)  # each kind appears as its own group

    def test_filters_exist_and_use_kind_and_requirement(self):
        for needle in ('id="fq"', 'id="fkind"', 'id="far"', 'id="fshown"', 'class="ksi findrow"'):
            self.assertIn(needle, self.page)
        self.assertIn(f'data-result="{tb.AR2}"', self.page)

    def test_fix_hint_rule_and_limit_are_shown(self):
        self.assertIn("merge-review.no-approval", self.page)
        self.assertIn("Fix:", self.page)
        self.assertIn("cannot see admin bypass", self.page)

    def test_not_started_ksis_are_collapsed_to_one_line(self):
        self.assertIn("Not started (1): KSI-A-TWO", self.page)
        self.assertEqual(self.page.count("<tr><td><span class=\"id\">KSI-A-TWO"), 0)

    def test_the_tab_is_absent_without_findings_and_the_rest_is_unchanged(self):
        without = render_sdr_html.render(self.sdr, self.cov, None, None)
        self.assertNotIn("page-findings", without)
        self.assertNotIn("merge-review.no-approval", without)

    def test_no_findings_message(self):
        empty = tb.build([tb.evaluation(tb.AR2, "org/a")])
        self.assertIn("No findings.", render_sdr_html.render(self.sdr, self.cov, None, empty))


class SdrUntouched(unittest.TestCase):
    def test_the_sdr_never_contains_findings_messages_or_subjects(self):
        sdr, _ = base.build()
        text = json.dumps(sdr)
        for needle in ("[rule:", "merge-review.", "credentials.long-term", "findings"):
            self.assertNotIn(needle, text)
        self.assertEqual(generate_sdr.find_leaks(text), [])


if __name__ == "__main__":
    unittest.main()
