import json
import re
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_trace  # noqa: E402
import render_sdr_html  # noqa: E402
import test_render_sdr_html as base  # noqa: E402
import trace_fakes as fk  # noqa: E402

SAMPLE = json.loads((ROOT / "tests/fixtures/trace.sample.json").read_text())
XSS = "<script>alert(1)</script>"
A1, A2, B1 = fk.AR_A1, fk.AR_A2, fk.AR_B1
slug = render_sdr_html.ar_slug


def page_for(ar_id, page):
    m = re.search(rf'<section class="page arpage" id="{slug(ar_id)}">.*?</section>', page, re.S)
    assert m, ar_id
    return m.group(0)


class TracePages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sdr, cov = base.build()
        cls.page = render_sdr_html.render(sdr, cov, SAMPLE)
        cls.plain = render_sdr_html.render(sdr, cov)

    def test_hostile_text_renders_as_text_everywhere(self):
        self.assertNotIn(XSS, self.page)
        self.assertGreater(self.page.count("&lt;script&gt;alert(1)&lt;/script&gt;"), 4)  # AR text, message, error, rationale, title

    def test_automation_exemption_is_stated_where_it_applies_and_only_there(self):
        self.assertIn("5 of 12 merged PRs counted as approved by automation", self.page)
        self.assertIn("approval pending", self.page)
        self.assertEqual(self.page.count('<strong>Automation exemption</strong>'), 1)

    def test_only_our_one_inline_script(self):
        self.assertEqual(len(re.findall(r"<script\b", self.page)), 1)

    def test_offline(self):
        self.assertIsNone(re.search(r"""(src|href|action)\s*=\s*["']?\s*(https?:)?//""", self.page))
        for bad in ("<link", "<img", "@import", "url(", "<iframe", "fetch(", "XMLHttpRequest"):
            self.assertNotIn(bad, self.page)

    def test_banner_and_tabs(self):
        self.assertIn("Local run. Not certification evidence.", self.page)
        self.assertIn('<nav class="tabs">', self.page)
        self.assertNotIn('<nav class="tabs">', self.plain)  # without a trace the viewer is as before

    def test_index_is_the_landing_page_and_lists_every_ar(self):
        first = re.search(r'<section class="page"', self.page).start()
        self.assertTrue(self.page[first:].startswith('<section class="page" id="page-ars">'))
        for ar in (A1, A2, B1):
            self.assertIn(f'href="#{slug(ar)}"', self.page)

    def test_every_internal_link_resolves(self):
        ids = set(re.findall(r'\bid="([^"]+)"', self.page))
        for target in set(re.findall(r'href="#([^"]+)"', self.page)):
            self.assertIn(target, ids, target)

    def test_ar_pages_and_ksi_cards_link_both_ways(self):
        ar_page = page_for(A1, self.page)
        self.assertIn('href="#ksi-KSI-CMT-VTD"', ar_page)
        self.assertIn('href="#page-ars"', ar_page)
        ksi_card = re.search(r'<details class="ksi" id="ksi-KSI-CMT-VTD".*?</details>', self.page, re.S).group(0)
        self.assertIn(f'href="#{slug(A1)}"', ksi_card)
        self.assertIn(f'href="#{slug(B1)}"', ksi_card)

    def test_state_and_result_are_separate_signals(self):
        row = re.search(rf'<tr class="arrow"[^>]*>(?:(?!</tr>).)*{A1}.*?</tr>', self.page, re.S).group(0)
        self.assertIn('class="state state-implemented"', row)
        self.assertIn('class="result result-failed"', row)
        self.assertIn('data-state="Implemented"', row)
        self.assertIn('data-result="failed"', row)

    def test_unevaluated_ar_says_not_evaluated_never_passed(self):
        ar = page_for(B1, self.page)
        self.assertIn("not evaluated", ar)
        self.assertNotIn("result-passed", ar)

    def test_results_are_ar_level_only(self):
        ar = page_for(A1, self.page)
        scope = re.search(r"<strong>Scope</strong>.*?</li>\s*<li><strong>Source", ar, re.S).group(0)
        for word in ("failed", "passed"):
            self.assertNotIn(word, scope)  # per-target lines carry reach, never a verdict
        self.assertIn("one result and one message for the whole AR, not one per target", ar)
        self.assertEqual(ar.count('class="result result-'), 2)  # header and the Result step, the same AR-level value
        self.assertNotIn("per_target", self.page)

    def test_scope_strip_shows_reached_error_and_not_reached(self):
        ar = page_for(A1, self.page)
        self.assertIn("acct-one: reached", ar)
        self.assertIn("acct-two: error", ar)
        self.assertIn("acct-three: not reached", ar)
        self.assertIn("1/3 reached", ar)
        self.assertIn("denied &lt;script&gt;", ar)

    def test_undefined_fields_are_marked_not_blank(self):
        for ar in (A1, B1):
            self.assertGreaterEqual(page_for(ar, self.page).count("not defined yet"), 2)  # Fails when, Failure handling

    def test_look_here_box_on_every_ar_page(self):
        for ar in (A1, A2, B1):
            box = page_for(ar, self.page)
            self.assertIn("Why did it fail? Look here", box)
            self.assertIn(f"ls evidence/output/{ar}/", box)
        a1 = page_for(A1, self.page)
        self.assertIn(".complytime/scan/report-fake-20260101-000000.md", a1)
        self.assertIn("conftest test evidence/output/FAKE.A.CTRL01.AR01/acct-one.json -p opa/dom-a/policy --all-namespaces", a1)
        self.assertIn("The one message the scan recorded for this AR", a1)

    def test_why_groups_by_framework_with_rationales_and_no_mapping_notes(self):
        a1, b1 = page_for(A1, self.page), page_for(B1, self.page)
        for needle in ("KSIs", "NIST 800-53", "Change control.", "Testing of changes.", "CM-03 (02)", "strength 7"):
            self.assertIn(needle, a1)
        self.assertIn("No mapping from this AR.", b1)  # B1 has no mapping to the third framework
        self.assertIn("Another certification appears here as one more block", a1)

    def test_how_is_the_ordered_assessor_trace(self):
        a1 = page_for(A1, self.page)
        order = [a1.index(f"<strong>{s}</strong>") for s in
                 ("Scope", "Source", "Shape", "Logic", "What it checks", "Fails when", "Failure handling", "Cadence", "Result")]
        self.assertEqual(order, sorted(order))

    def test_cadence_wording_is_truthful(self):
        a1 = page_for(A1, self.page)
        self.assertIn("Planned cycle: weekly. Currently run manually from a developer laptop", a1)

    def test_missing_line(self):
        a1 = page_for(A1, self.page)
        self.assertIn("<strong>Missing:</strong>", a1)
        self.assertIn("reach 2 target(s) not collected", a1)
        self.assertIn("KSI-CMT-VTD: reach all targets", a1)
        self.assertIn("not mapped to any requirement", page_for(A2, self.page))

    def test_index_filter_controls(self):
        for el in ('id="arq"', 'id="arstate"', 'id="arresult"'):
            self.assertIn(el, self.page)
        rows = re.findall(r'<tr class="arrow"([^>]*)>', self.page)
        self.assertEqual(len(rows), 3)
        for attrs in rows:  # the filter reads these
            for a in ("data-text=", "data-state=", "data-result="):
                self.assertIn(a, attrs)

    def test_existing_ksi_views_are_unchanged(self):
        self.assertIn('id="page-ksis"', self.page)
        self.assertEqual(self.page.count('class="ksi"'), len(base.build()[1]["ksis"]))


class SampleDoesNotDrift(unittest.TestCase):
    """The committed sample must keep the shape build_trace really produces."""

    def shape(self, value):
        if isinstance(value, dict):
            return {k: self.shape(v) for k, v in value.items()}
        return None

    def test_same_keys_as_a_fresh_build(self):
        with tempfile.TemporaryDirectory() as t:
            fresh = build_trace.build(fk.make_repo(Path(t)), fk.coverage_for(), datetime(2026, 1, 2, tzinfo=timezone.utc), "integration")
        for top in ("meta", "frameworks", "controls", "links", "results"):
            self.assertEqual(type(SAMPLE[top]), type(fresh[top]), top)
        self.assertEqual(set(SAMPLE), set(fresh))
        self.assertEqual(set(SAMPLE["meta"]), set(fresh["meta"]))
        ar = next(iter(fresh["ars"]))
        self.assertEqual(set(SAMPLE["ars"][ar]), set(fresh["ars"][ar]))
        self.assertEqual(set(SAMPLE["ars"][ar]["impl"]), set(fresh["ars"][ar]["impl"]))
        self.assertEqual(set(SAMPLE["links"][0]), set(fresh["links"][0]))
        self.assertEqual(set(SAMPLE["scope"][ar]), set(fresh["scope"][ar]))
        self.assertEqual(set(SAMPLE["results"][ar]), set(fresh["results"][ar]))

    def test_sample_is_synthetic(self):
        text = json.dumps(SAMPLE)
        self.assertNotIn("openshift-online", text)
        self.assertNotIn("/Users/", text)
        self.assertIsNone(re.search(r"[0-9]{12}", text))


if __name__ == "__main__":
    unittest.main()
