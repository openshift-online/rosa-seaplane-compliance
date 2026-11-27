import copy
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_findings as bf  # noqa: E402

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
AR2, AR_IAM, AR_LOG = "RSC.CMT.CTRL01.AR02", "RSC.IAM.CTRL01.AR01", "RSC.CMT.CTRL02.AR01"
ID12 = "7" * 12  # fake account number, built at run time: no 12-digit literal is committed

ARS = {
    AR2: {"id": AR2, "text": "Every merge was approved.", "control": "RSC.CMT.CTRL01"},
    AR_IAM: {"id": AR_IAM, "text": "No long-term credentials.", "control": "RSC.IAM.CTRL01"},
    AR_LOG: {"id": AR_LOG, "text": "Changes are logged.", "control": "RSC.CMT.CTRL02"},
}


def tag(text, rule):
    return f"{text} [rule: {rule}]"


def evaluation(ar, target, *messages, at="2026-11-24T10:00:00Z"):
    return {"ar": ar, "file": f"{target}.json", "target": target, "evidence_generated_at": at, "messages": list(messages)}


def coverage(*, missing=()):
    def method(ar, **scope):
        return {"ar": ar, "implemented": True, "scope": {"run": True, "reached": 1, "total": 1, "missing": [], **scope}}
    return {
        "environment": "integration",
        "ksis": [
            {"id": "KSI-A-ONE", "name": "One", "state": "Covered", "type": "auto", "methods_implemented": 2,
             "methods": [method(AR2, missing=list(missing)), method(AR_IAM)],
             "controls": {"open": ["x-2", "x-1"]}, "controls_decided": 1, "controls_total": 3,
             "narrative": False, "has_record": True, "next": ["decide 2 open controls"]},
            {"id": "KSI-A-TWO", "name": "Two", "state": "Not started", "type": "auto", "methods_implemented": 0,
             "methods": [], "controls": {"open": ["y-1"]}, "controls_decided": 0, "controls_total": 1,
             "narrative": False, "has_record": False, "next": ["implement 2 more automated methods"]},
            {"id": "KSI-A-THREE", "name": "Three", "state": "Covered", "type": "auto", "methods_implemented": 1,
             "methods": [method(AR_LOG), method(AR2)],
             "controls": {"open": []}, "controls_decided": 1, "controls_total": 1,
             "narrative": True, "has_record": True, "next": []},
        ],
    }


RULES = bf.load_rules()
LIMITS = {AR2: [{"text": "cannot see admin bypass", "source": "evidence/known-gaps.yaml"}]}


def build(evaluations, manifests=None, cov=None, now=NOW, evidence_ars=None):
    # Unless a test says otherwise, every requirement with a method has an evidence directory.
    evidence_ars = {AR2, AR_IAM, AR_LOG} if evidence_ars is None else evidence_ars
    return bf.build_report(evaluations, manifests or {}, ARS, cov or coverage(), RULES, LIMITS, now, evidence_ars)


class Parsing(unittest.TestCase):
    def test_tagged_and_untagged(self):
        self.assertEqual(bf.parse_denial(tag("repo: PR #1 bad", "merge-review.self-merge"), RULES),
                         ("merge-review.self-merge", "repo: PR #1 bad"))
        self.assertEqual(bf.parse_denial("repo: no tag here", RULES), (bf.UNCLASSIFIED, "repo: no tag here"))

    def test_tag_must_be_last_and_tolerates_trailing_space(self):
        self.assertEqual(bf.parse_denial("a [rule: x.y]  ", RULES)[0], "x.y")
        self.assertEqual(bf.parse_denial("a [rule: x.y] more", RULES)[0], bf.UNCLASSIFIED)

    def test_subject_pattern_and_fallback(self):
        entry = RULES["rules"]["merge-review.no-approval"]
        self.assertEqual(bf.subject_of(entry, "org/r: PR #12 (a) merged", "org/r"), "PR #12")
        self.assertEqual(bf.subject_of(entry, "nothing to see", "org/r"), "org/r")
        self.assertEqual(bf.subject_of(None, "x", "org/r"), "org/r")


class Report(unittest.TestCase):
    def test_a_finding_has_everything_needed_to_write_a_recommendation(self):
        rep = build([evaluation(AR2, "org/r", tag("org/r: PR #7 (a) merged to main without a non-author approval", "merge-review.no-approval"))])
        (f,) = rep["findings"]
        self.assertEqual((f["ar"], f["control"], f["target"], f["rule"], f["kind"], f["subject"]),
                         (AR2, "RSC.CMT.CTRL01", "org/r", "merge-review.no-approval", "violation", "PR #7"))
        self.assertEqual(f["ar_text"], "Every merge was approved.")
        self.assertEqual(f["ksis"], ["KSI-A-ONE", "KSI-A-THREE"])  # the KSIs this AR serves
        self.assertTrue(f["fix"] and f["title"])
        self.assertNotIn("[rule:", f["message"])  # the tag is parsed out

    def test_three_kinds_are_kept_apart(self):
        rep = build(
            [evaluation(AR_IAM, "central", tag("central: iam-user bot holds 1 active long-term credential(s) (access-key)", "credentials.long-term-active")),
             evaluation(AR_LOG, "central", tag("central: the Prowler collection was incomplete, so nothing can be concluded", "change-logging.collection-incomplete"))],
            manifests={AR_IAM: {"targets": [{"name": "central", "status": "collected"}, {"name": "regional", "status": "error", "error": "denied"}]}},
        )
        kinds = {f["rule"]: f["kind"] for f in rep["findings"]}
        self.assertEqual(kinds["credentials.long-term-active"], "violation")
        self.assertEqual(kinds["change-logging.collection-incomplete"], "incomplete-evidence")
        self.assertEqual(kinds["collection.target-not-reached"], "not-reached")
        self.assertEqual(rep["meta"]["counts"]["by_kind"], {"incomplete-evidence": 1, "not-reached": 1, "violation": 1})
        unreached = [f for f in rep["findings"] if f["kind"] == "not-reached"][0]
        self.assertEqual((unreached["target"], unreached["message"]), ("regional", "error: denied"))

    def test_a_target_that_coverage_expects_but_no_manifest_lists_is_not_reached(self):
        rep = build([evaluation(AR2, "org/a")], manifests={AR2: {"targets": [{"name": "org/a", "status": "collected"}]}},
                    cov=coverage(missing=["org/b"]))
        (f,) = [x for x in rep["findings"] if x["kind"] == "not-reached"]
        self.assertEqual((f["target"], f["message"]), ("org/b", "not listed in the collector's manifest"))

    def test_an_error_in_the_manifest_is_reported_once_even_if_coverage_also_lists_it(self):
        rep = build([evaluation(AR2, "org/a")],
                    manifests={AR2: {"targets": [{"name": "org/b", "status": "error", "error": "boom"}]}},
                    cov=coverage(missing=["org/b"]))
        self.assertEqual(len([f for f in rep["findings"] if f["kind"] == "not-reached" and f["target"] == "org/b"]), 1)

    def test_a_requirement_with_a_method_but_no_evidence_is_flagged(self):
        rep = build([evaluation(AR2, "org/a")], evidence_ars={AR2})
        missing = {f["ar"] for f in rep["findings"] if f["rule"] == "collection.no-evidence"}
        self.assertEqual(missing, {AR_IAM, AR_LOG})

    def test_an_untagged_denial_is_counted_and_never_hidden(self):
        rep = build([evaluation(AR2, "org/a", "org/a: a denial nobody gave a rule")])
        self.assertEqual(rep["meta"]["unclassified"], 1)
        self.assertEqual(rep["findings"][0]["rule"], bf.UNCLASSIFIED)
        self.assertEqual(rep["findings"][0]["kind"], "violation")

    def test_identical_denials_are_one_finding(self):
        m = tag("org/a: PR #1 (x) merged to main by its own author (x), bypassing the merge gate", "merge-review.self-merge")
        self.assertEqual(len(build([evaluation(AR2, "org/a", m, m)])["findings"]), 1)

    def test_subjects_sort_naturally(self):
        msgs = [tag(f"org/a: PR #{i} (x) merged to main without a non-author approval", "merge-review.no-approval") for i in (10, 9, 100, 2)]
        rep = build([evaluation(AR2, "org/a", *msgs)])
        self.assertEqual([f["subject"] for f in rep["findings"]], ["PR #2", "PR #9", "PR #10", "PR #100"])

    def test_findings_are_ordered_and_building_twice_is_identical_except_the_timestamp(self):
        evs = [evaluation(AR_IAM, "z", tag("z: iam-user b holds 1 active long-term credential(s) (access-key)", "credentials.long-term-active")),
               evaluation(AR2, "org/b", tag("org/b: PR #2 (x) merged to main without a non-author approval", "merge-review.no-approval")),
               evaluation(AR2, "org/a", tag("org/a: PR #9 (x) merged to main without a non-author approval", "merge-review.no-approval"))]
        a = build(evs, now=NOW)
        b = build(list(reversed(evs)), now=datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertNotEqual(a["meta"]["generated_at"], b["meta"]["generated_at"])
        a["meta"]["generated_at"] = b["meta"]["generated_at"] = None
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual([f["target"] for f in a["findings"]], ["org/a", "org/b", "z"])

    def test_counts_per_kind_ar_and_rule(self):
        rep = build([evaluation(AR2, "org/a", tag("org/a: PR #1 (x) merged to main without a non-author approval", "merge-review.no-approval"),
                                tag("org/a: PR #2 (x) merged to main without a non-author approval", "merge-review.no-approval"))])
        c = rep["meta"]["counts"]
        self.assertEqual(c["by_rule"]["merge-review.no-approval"], 2)
        self.assertEqual(c["by_ar"][AR2], {"violation": 2})

    def test_evidence_timestamps_are_reported(self):
        rep = build([evaluation(AR2, "a", at="2026-11-24T09:00:00Z"), evaluation(AR2, "b", at="2026-11-24T11:00:00Z")])
        self.assertEqual(rep["meta"]["evidence_generated_at"], {"oldest": "2026-11-24T09:00:00Z", "newest": "2026-11-24T11:00:00Z"})
        self.assertEqual(rep["meta"]["evidence_files"], 2)

    def test_twelve_digit_numbers_are_masked_everywhere(self):
        rep = build([evaluation(AR2, f"acct-{ID12}", tag(f"acct-{ID12}: PR #1 (x) merged to main without a non-author approval {ID12}", "merge-review.no-approval"))])
        self.assertNotIn(ID12, json.dumps(rep))
        self.assertNotIn(ID12, bf.render_markdown(rep))


class Gaps(unittest.TestCase):
    def test_gaps_per_ksi(self):
        rep = build([evaluation(AR2, "org/a")], cov=coverage(missing=["org/z"]))
        gaps = {g["ksi"]: g for g in rep["gaps"]}
        one = gaps["KSI-A-ONE"]
        self.assertEqual((one["state"], one["methods_implemented"], one["open_controls"]), ("Covered", 2, ["x-1", "x-2"]))
        self.assertEqual(one["explanations"], "not written, or proposed and awaiting review")
        self.assertEqual(one["targets_not_reached"], [{"ar": AR2, "target": "org/z"}])
        self.assertEqual(one["next"], ["decide 2 open controls"])
        self.assertEqual(gaps["KSI-A-TWO"]["explanations"], "no KSI record yet")
        self.assertEqual(gaps["KSI-A-THREE"]["explanations"], "written")
        self.assertEqual(list(gaps), sorted(gaps))

    def test_gaps_are_not_findings(self):
        rep = build([evaluation(AR2, "org/a")])
        self.assertEqual(rep["findings"], [])
        self.assertTrue(rep["gaps"])


class Limits(unittest.TestCase):
    def test_limits_are_listed_per_requirement_with_their_source(self):
        rep = build([evaluation(AR2, "org/a")])
        self.assertEqual(rep["limits"][AR2]["limits"], LIMITS[AR2])
        self.assertEqual(rep["limits"][AR2]["ar_text"], "Every merge was approved.")


class Markdown(unittest.TestCase):
    def setUp(self):
        self.rep = build(
            [evaluation(AR2, "org/a", *[tag(f"org/a: PR #{i} (x) merged to main without a non-author approval", "merge-review.no-approval") for i in range(1, 16)])],
            manifests={AR2: {"targets": [{"name": "org/b", "status": "error", "error": "denied"}]}})
        self.md = bf.render_markdown(self.rep)

    def test_sections_and_kinds_are_separate(self):
        order = [self.md.index(x) for x in ("## Summary", "## Findings", "### Violations", "### Not reached", "## Gaps in our own work", "## Limits of the checks")]
        self.assertEqual(order, sorted(order))

    def test_only_the_first_subjects_are_shown_with_a_pointer_to_the_full_list(self):
        self.assertIn("and 5 more (full list in findings.json)", self.md)
        self.assertIn("PR #1;", self.md)
        self.assertIn("PR #10;", self.md)  # natural order: 1..10 first, so 11..15 are the "5 more"
        self.assertNotIn("PR #11", self.md)

    def test_it_says_it_is_deterministic_and_local(self):
        self.assertIn("no AI, no network", self.md)
        self.assertIn("do not publish", self.md)

    def test_fix_hint_and_limits_appear(self):
        self.assertIn("Fix:", self.md)
        self.assertIn("cannot see admin bypass", self.md)


class Evaluate(unittest.TestCase):
    """The collecting step, with a stand-in for conftest (no real policy engine needed)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "opa/d/policy").mkdir(parents=True)
        ev = self.root / "evidence/output" / AR2
        ev.mkdir(parents=True)
        (ev / "org-a.json").write_text(json.dumps({"repository": "org/a", "generated_at": "2026-11-24T10:00:00Z"}))
        (ev / "manifest.json").write_text("{}")
        self.fake = self.root / "fake_conftest.py"
        self.fake.write_text(
            "import json, sys\n"
            "files = [a for a in sys.argv[2:] if a.endswith('.json') and not a.startswith('-')]\n"
            "open(sys.argv[0] + '.args', 'w').write(json.dumps(sys.argv[1:]))\n"
            "print(json.dumps([{'filename': f, 'failures': [{'msg': 'org/a: x [rule: merge-review.self-merge]'}]} for f in files]))\n"
            "sys.exit(1)\n")

    def test_it_evaluates_evidence_files_only_never_the_manifest_and_reads_messages_back(self):
        out = bf.evaluate(self.root / "evidence/output", [self.root / "opa/d/policy"], [sys.executable, str(self.fake)], self.root)
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["ar"], out[0]["target"], out[0]["evidence_generated_at"]), (AR2, "org/a", "2026-11-24T10:00:00Z"))
        self.assertEqual(out[0]["messages"], ["org/a: x [rule: merge-review.self-merge]"])
        args = json.loads(Path(str(self.fake) + ".args").read_text())
        self.assertFalse(any("manifest.json" in a for a in args))
        self.assertIn("--all-namespaces", args)
        self.assertIn("opa/d/policy", args)

    def test_unreadable_conftest_output_is_an_error(self):
        self.fake.write_text("print('not json')\n")
        with self.assertRaises(bf.FindingsError):
            bf.evaluate(self.root / "evidence/output", [self.root / "opa/d/policy"], [sys.executable, str(self.fake)], self.root)

    def test_missing_evidence_is_a_clear_error_that_says_what_to_run(self):
        shutil.rmtree(self.root / "evidence")
        (self.root / "evidence").mkdir()
        cov = self.root / "coverage.json"
        cov.write_text(json.dumps(coverage()))
        with self.assertRaises(bf.FindingsError) as cm:
            bf.build(self.root, self.root / "evidence/output", cov, NOW, [sys.executable, str(self.fake)])
        self.assertIn("make run-local", str(cm.exception))

    def test_missing_coverage_is_a_clear_error(self):
        with self.assertRaises(bf.FindingsError) as cm:
            bf.build(self.root, self.root / "evidence/output", self.root / "nope.json", NOW, [sys.executable, str(self.fake)])
        self.assertIn("make coverage", str(cm.exception))


class Conftest(unittest.TestCase):
    def test_conftest_bin_wins(self):
        with mock.patch.dict(os.environ, {"CONFTEST_BIN": "/x/conftest"}):
            self.assertEqual(bf.conftest_argv(), ["/x/conftest"])

    def test_nothing_available_is_a_clear_error(self):
        with mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(bf.shutil, "which", return_value=None):
            os.environ.pop("CONFTEST_BIN", None)
            with self.assertRaises(bf.FindingsError):
                bf.conftest_argv()

    def test_container_fallback_uses_the_pinned_image_read_only(self):
        def which(name):
            return "/usr/bin/podman" if name == "podman" else None
        with mock.patch.dict(os.environ, {}), mock.patch.object(bf.shutil, "which", side_effect=which):
            os.environ.pop("CONFTEST_BIN", None)
            argv = bf.conftest_argv()
        self.assertEqual(argv[:3], ["podman", "run", "--rm"])
        self.assertTrue(any(a.endswith(":/project:ro") for a in argv))
        self.assertEqual(argv[-1], bf.CONFTEST_IMAGE)

    def test_the_container_image_matches_the_version_the_test_runner_pins(self):
        pinned = re.search(r"openpolicyagent/conftest:(v[0-9.]+)", (ROOT / "tests/run.sh").read_text()).group(1)
        self.assertTrue(bf.CONFTEST_IMAGE.endswith(pinned))


class NoNetwork(unittest.TestCase):
    def test_building_and_rendering_never_open_a_socket(self):
        def boom(*a, **k):
            raise AssertionError("the findings report must not use the network")
        with mock.patch.object(socket, "socket", boom), mock.patch.object(socket, "create_connection", boom):
            rep = build([evaluation(AR2, "org/a", tag("org/a: PR #1 (x) merged to main by its own author (x), bypassing the merge gate", "merge-review.self-merge"))])
            bf.render_markdown(rep)
            bf.load_rules()
            bf.load_limits()

    def test_the_module_imports_no_network_client(self):
        text = (ROOT / "scripts/build_findings.py").read_text()
        for needle in ("import requests", "urllib", "http.client", "import socket", "anthropic", "openai"):
            self.assertNotIn(needle, text)


def conftest_available():
    return bool(os.environ.get("CONFTEST_BIN") or shutil.which("conftest"))


@unittest.skipUnless(conftest_available(), "conftest is not installed: skipping the integration test through the real policies")
class RealPolicies(unittest.TestCase):
    """The fail fixtures through the real Rego: every denial is tagged, classified and explained."""

    def run_fixtures(self, which):
        with tempfile.TemporaryDirectory() as t:
            ev = Path(t) / "evidence"
            for fx in sorted((ROOT / "tests/fixtures").iterdir()):
                if (fx / f"{which}.json").is_file():
                    (ev / fx.name).mkdir(parents=True)
                    shutil.copy(fx / f"{which}.json", ev / fx.name / f"{which}.json")
            return bf.evaluate(ev, sorted(ROOT.glob("opa/*/policy")), bf.conftest_argv(), ROOT), ev

    def test_every_denial_on_the_fail_fixtures_is_tagged_with_a_known_rule_and_a_subject(self):
        evals, _ = self.run_fixtures("fail")
        rules = bf.load_rules()
        total = 0
        for ev in evals:
            self.assertTrue(ev["messages"], f"{ev['ar']}: the fail fixture produced no denial")
            for raw in ev["messages"]:
                rule, message = bf.parse_denial(raw, rules)
                self.assertIn(rule, rules["rules"], f"untagged or unknown rule on: {raw}")
                total += 1
                self.assertNotEqual(bf.subject_of(rules["rules"][rule], message, "T").strip(), "")
        self.assertGreater(total, 5)

    def test_the_pass_fixtures_produce_no_findings(self):
        evals, _ = self.run_fixtures("pass")
        self.assertTrue(evals)
        self.assertEqual([m for ev in evals for m in ev["messages"]], [])

    def test_the_whole_report_builds_over_the_fail_fixtures(self):
        evals, _ = self.run_fixtures("fail")
        _, ars = bf.build_trace.load_catalogs(ROOT)
        rep = bf.build_report(evals, {}, ars, coverage(), RULES, LIMITS, NOW)
        self.assertEqual(rep["meta"]["unclassified"], 0)
        self.assertGreater(rep["meta"]["counts"]["by_kind"]["violation"], 0)


if __name__ == "__main__":
    unittest.main()
