import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "evidence/lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_record as br  # noqa: E402
import day_window  # noqa: E402
import history  # noqa: E402
from history_fakes import ts, utc  # noqa: E402

NOW = utc(2026, 11, 27, 12, 0)
EVIDENCE_AT = NOW - timedelta(minutes=20)
OUTPUT_AT = NOW - timedelta(minutes=10)
GIT = {"commit": "c" * 40, "dirty": False}
AR1, AR2, AR3 = "RSC.T.CTRL01.AR01", "RSC.T.CTRL01.AR02", "RSC.T.CTRL02.AR01"
# AR1, AR2 judge events; AR3 judges the present; AR2 also has a rule that reads the present.
BASIS = {AR1: {"basis": "event", "state_rules": set()}, AR2: {"basis": "event", "state_rules": {"s.head"}},
         AR3: {"basis": "state", "state_rules": set()}}


def coverage(methods_by_ksi, at=OUTPUT_AT):
    return {"generated_at": ts(at), "environment": "integration",
            "ksis": [{"id": k, "methods": [{"ar": ar, "kind": kind, "implemented": impl} for ar, kind, impl in ms]}
                     for k, ms in methods_by_ksi.items()]}


def trace(scopes, at=OUTPUT_AT):
    return {"meta": {"generated_at": ts(at)}, "scope": scopes}


def scope(statuses, run=True, expected=None):
    names = [f"t{i}" for i in range(len(statuses))]
    return {"run": run, "expected": names if expected is None else expected,
            "targets": [{"name": n, "status": s} for n, s in zip(names, statuses)]}


def findings(rows, at=OUTPUT_AT):
    return {"meta": {"generated_at": ts(at), "evidence_generated_at": {"oldest": ts(EVIDENCE_AT - timedelta(minutes=3)), "newest": ts(EVIDENCE_AT)}},
            "findings": [{"ar": ar, "kind": kind, "rule": rule} for ar, kind, rule in rows]}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ev = self.root / "evidence"
        (self.root / "config/prowler").mkdir(parents=True)
        (self.root / "config/prowler/checks.yaml").write_text('prowler-version: "9.9.9"\n')
        (self.root / "opa/d/policy").mkdir(parents=True)
        (self.root / "opa/d/policy/x.rego").write_text("package x\n")

    day = "2026-11-26"   # the day the evidence of an event method covers (yesterday, for NOW)

    def write_evidence(self, ar, files=None, at=EVIDENCE_AT):
        """Evidence of an AR. An event method's files say which day they cover, as the collectors do."""
        event = BASIS.get(ar, {}).get("basis") == "event"
        w = day_window.day_for(self.day)
        stated = {"covers_date": self.day, "window": {"start": w["start"], "end": w["end"]}} if event else {}
        d = self.ev / ar
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps({"ar": ar, "generated_at": ts(at), "targets": [],
                                                     **({"covers_date": self.day} if event else {})}))
        for name, doc in (files if files is not None else {"t0.json": {"generated_at": ts(at)}}).items():
            (d / name).write_text(json.dumps({**stated, **doc}))

    def build(self, cov, tr, fi, **kw):
        kw.setdefault("basis", BASIS)
        return br.build_record(cov, tr, fi, self.ev, self.root, NOW, GIT, run_id="20261127T120000Z-abcdef", **kw)


class Semantics(unittest.TestCase):
    def test_pass_fail_error(self):
        self.assertEqual(br.method_outcome(0, 0, []), "pass")
        self.assertEqual(br.method_outcome(2, 0, []), "fail")
        self.assertEqual(br.method_outcome(0, 1, []), "error")
        self.assertEqual(br.method_outcome(0, 0, ["targets not reached"]), "error")

    def test_a_violation_wins_over_incomplete_evidence(self):
        self.assertEqual(br.method_outcome(1, 3, ["evidence incomplete"]), "fail")


class Building(Fixture):
    def one(self, rows=(), statuses=("reached", "reached"), evidence=True, **kw):
        if evidence:
            self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]})
        return self.build(cov, trace({AR1: scope(list(statuses), **kw)}), findings(list(rows)))["methods"][0]

    def test_pass(self):
        m = self.one()
        self.assertEqual((m["result"], m["violations"], m["incomplete"], m["targets_expected"], m["targets_reached"]),
                         ("pass", 0, 0, 2, 2))
        self.assertEqual(m["method_kind"], "intent")

    def test_fail_counts_violations_and_rules(self):
        m = self.one([(AR1, "violation", "a.b"), (AR1, "violation", "a.b"), (AR1, "violation", "c.d")])
        self.assertEqual((m["result"], m["violations"]), ("fail", 3))
        self.assertEqual(m["rules_failed"], [{"rule": "a.b", "count": 2}, {"rule": "c.d", "count": 1}])

    def test_incomplete_evidence_is_an_error_never_a_pass(self):
        m = self.one([(AR1, "incomplete-evidence", "a.b")])
        self.assertEqual((m["result"], m["incomplete"]), ("error", 1))

    def test_an_unreached_target_is_an_error(self):
        m = self.one(statuses=("reached", "error"))
        self.assertEqual((m["result"], m["targets_reached"], m["targets_expected"]), ("error", 1, 2))

    def test_a_method_with_no_evidence_is_an_error_not_omitted(self):
        self.write_evidence(AR2)  # the run produced evidence for another AR, but none for this one
        m = self.one(evidence=False, run=False)
        self.assertEqual((m["result"], m["evidence_sha256"]), ("error", None))

    def test_no_evidence_at_all_means_no_record(self):
        with self.assertRaises(br.RecordError):
            self.one(evidence=False, run=False)

    def test_evidence_that_says_it_is_incomplete_is_an_error(self):
        self.write_evidence(AR1, {"t0.json": {"generated_at": ts(EVIDENCE_AT), "collection": {"complete": False}}})
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]})
        m = self.build(cov, trace({AR1: scope(["reached", "reached"])}), findings([]))["methods"][0]
        self.assertEqual(m["result"], "error")

    def test_unparseable_evidence_is_an_error(self):
        self.write_evidence(AR1)
        (self.ev / AR1 / "bad.json").write_text("{nope")
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]})
        self.assertEqual(self.build(cov, trace({AR1: scope(["reached"])}), findings([]))["methods"][0]["result"], "error")

    def test_unimplemented_methods_are_not_part_of_the_record(self):
        self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True), (AR2, "Behavioral", False)]})
        ms = self.build(cov, trace({AR1: scope(["reached"])}), findings([]))["methods"]
        self.assertEqual([m["ar"] for m in ms], [AR1])

    def test_an_ar_serving_two_ksis_gets_an_entry_per_ksi(self):
        self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)], "KSI-CCC-DDD": [(AR1, "Intent", True)]})
        ms = self.build(cov, trace({AR1: scope(["reached"])}), findings([(AR1, "violation", "a.b")]))["methods"]
        self.assertEqual([(m["ksi"], m["result"]) for m in ms], [("KSI-AAA-BBB", "fail"), ("KSI-CCC-DDD", "fail")])

    def test_kinds_are_normalised(self):
        self.write_evidence(AR1)
        self.write_evidence(AR2)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Behavioral", True), (AR2, "Weird", True)]})
        tr = trace({AR1: scope(["reached"]), AR2: scope(["reached"])})
        self.assertEqual([m["method_kind"] for m in self.build(cov, tr, findings([]))["methods"]], ["behavioral", "other"])

    def test_run_level_fields(self):
        self.write_evidence(AR1)
        rec = self.build(coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]}), trace({AR1: scope(["reached"])}), findings([]))
        self.assertEqual(rec["run_id"], "20261127T120000Z-abcdef")
        self.assertEqual((rec["covers_date"], rec["backfill"]), ("2026-11-26", False))
        self.assertEqual((rec["recorded_at"], rec["environment"], rec["pipeline"]), (ts(NOW), "integration", GIT))
        self.assertEqual(rec["tools"], {"prowler": "9.9.9"})
        self.assertEqual(rec["started_at"], ts(EVIDENCE_AT - timedelta(minutes=3)))
        self.assertEqual(rec["finished_at"], ts(OUTPUT_AT))
        self.assertRegex(rec["policy_sha256"], r"^[0-9a-f]{64}$")

    def test_the_record_validates_against_the_schema(self):
        self.write_evidence(AR1)
        rec = self.build(coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]}), trace({AR1: scope(["reached"])}), findings([]))
        br.validate(rec)

    def test_schema_rejects_bad_records(self):
        import jsonschema
        self.write_evidence(AR1)
        good = self.build(coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]}), trace({AR1: scope(["reached"])}), findings([]))
        bad = json.loads(json.dumps(good))
        bad["methods"][0]["result"] = "maybe"
        with self.assertRaises(jsonschema.ValidationError):
            br.validate(bad)
        bad = json.loads(json.dumps(good))
        bad["extra"] = 1
        with self.assertRaises(jsonschema.ValidationError):
            br.validate(bad)
        bad = json.loads(json.dumps(good))
        del bad["methods"][0]["evidence_sha256"]
        with self.assertRaises(jsonschema.ValidationError):
            br.validate(bad)


class Hashes(Fixture):
    def test_evidence_hash_is_deterministic_and_content_sensitive(self):
        self.write_evidence(AR1, {"a.json": {"x": 1}, "b.json": {"y": 2}})
        h1 = br.evidence_hash(self.ev / AR1)
        self.assertEqual(h1, br.evidence_hash(self.ev / AR1))
        (self.ev / AR1 / "a.json").write_text(json.dumps({"x": 2}))
        self.assertNotEqual(h1, br.evidence_hash(self.ev / AR1))

    def test_evidence_hash_of_nothing_is_none(self):
        self.assertIsNone(br.evidence_hash(self.ev / "absent"))
        (self.ev / "empty").mkdir(parents=True)
        self.assertIsNone(br.evidence_hash(self.ev / "empty"))

    def test_file_names_are_part_of_the_hash(self):
        self.write_evidence(AR1, {"a.json": {"x": 1}})
        self.write_evidence(AR2, {"b.json": {"x": 1}})
        # manifests differ only by the ar name; compare a directory with the same bytes under another name
        (self.ev / AR1 / "manifest.json").unlink()
        (self.ev / AR2 / "manifest.json").unlink()
        self.assertNotEqual(br.evidence_hash(self.ev / AR1), br.evidence_hash(self.ev / AR2))

    def test_policy_hash_changes_when_a_policy_changes(self):
        h = br.policy_hash(self.root)
        (self.root / "opa/d/policy/x.rego").write_text("package y\n")
        self.assertNotEqual(h, br.policy_hash(self.root))


class Windows(Fixture):
    def test_an_event_methods_window_is_the_day_its_evidence_states(self):
        self.write_evidence(AR1)
        self.assertEqual(br.ar_window(self.ev / AR1), {"start": "2026-11-26T00:00:00Z", "end": "2026-11-27T00:00:00Z"})

    def test_state_checks_have_no_window(self):
        self.write_evidence(AR3)
        self.assertIsNone(br.ar_window(self.ev / AR3))

    def test_the_window_spans_all_targets(self):
        self.write_evidence(AR1, {"a.json": {"window": {"start": "2026-11-26T00:00:00Z", "end": "2026-11-27T00:00:00Z"}},
                                  "b.json": {"window": {"start": "2026-11-26T00:00:00Z", "end": "2026-11-27T00:00:00Z"}}})
        self.assertEqual(br.ar_window(self.ev / AR1), {"start": "2026-11-26T00:00:00Z", "end": "2026-11-27T00:00:00Z"})


class MismatchedDays(Fixture):
    """Evidence collected for one day is never recorded as another's."""

    def attempt(self, covers_date, backfill=False):
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]})
        return self.build(cov, trace({AR1: scope(["reached"])}), findings([]), covers_date=covers_date, backfill=backfill)

    def test_matching_evidence_is_recorded(self):
        self.write_evidence(AR1)
        self.assertEqual(self.attempt("2026-11-26")["methods"][0]["result"], "pass")

    def test_evidence_of_another_day_is_refused(self):
        self.write_evidence(AR1)
        with self.assertRaises(br.RecordError) as cm:
            self.attempt("2026-11-25", backfill=True)
        self.assertIn("not 2026-11-25", str(cm.exception))

    def test_a_window_that_is_not_the_day_is_refused(self):
        self.write_evidence(AR1, {"t0.json": {"generated_at": ts(EVIDENCE_AT), "window": {"start": "2026-11-26T00:00:00Z", "end": "2026-11-26T12:00:00Z"}}})
        with self.assertRaises(br.RecordError):
            self.attempt("2026-11-26")

    def test_evidence_that_states_no_day_is_refused(self):
        self.write_evidence(AR1)
        (self.ev / AR1 / "t0.json").write_text(json.dumps({"generated_at": ts(EVIDENCE_AT)}))
        with self.assertRaises(br.RecordError) as cm:
            self.attempt("2026-11-26")
        self.assertIn("no stated day", str(cm.exception))

    def test_a_manifest_for_another_day_is_refused(self):
        self.write_evidence(AR1)
        (self.ev / AR1 / "manifest.json").write_text(json.dumps({"ar": AR1, "generated_at": ts(EVIDENCE_AT), "targets": [], "covers_date": "2026-11-20"}))
        with self.assertRaises(br.RecordError):
            self.attempt("2026-11-26")

    def test_one_stray_file_is_enough_to_refuse(self):
        self.write_evidence(AR1, {"a.json": {"generated_at": ts(EVIDENCE_AT)}, "b.json": {"generated_at": ts(EVIDENCE_AT), "covers_date": "2026-11-01"}})
        with self.assertRaises(br.RecordError):
            self.attempt("2026-11-26")

    def test_state_evidence_states_no_day_and_is_not_checked(self):
        self.write_evidence(AR3)
        cov = coverage({"KSI-AAA-BBB": [(AR3, "Behavioral", True)]})
        self.assertEqual(self.build(cov, trace({AR3: scope(["reached"])}), findings([]))["methods"][0]["result"], "pass")

    def test_the_backfill_flag_must_match_the_day(self):
        self.write_evidence(AR1)
        with self.assertRaises(br.RecordError) as cm:
            self.attempt("2026-11-26", backfill=True)
        self.assertIn("yesterday", str(cm.exception))
        self.day = "2026-11-20"
        self.write_evidence(AR1)
        with self.assertRaises(br.RecordError) as cm:
            self.attempt("2026-11-20", backfill=False)
        self.assertIn("past day", str(cm.exception))


class Freshness(Fixture):
    def outputs(self, at=OUTPUT_AT):
        return {"output/coverage.json": ts(at), "output/trace.json": ts(at), "output/findings.json": ts(at)}

    def test_fresh_outputs_pass(self):
        self.write_evidence(AR1)
        br.check_fresh(self.outputs(), self.ev, NOW, 24)

    def test_outputs_older_than_the_evidence_are_refused(self):
        self.write_evidence(AR1)
        with self.assertRaises(br.RecordError) as cm:
            br.check_fresh(self.outputs(EVIDENCE_AT - timedelta(minutes=1)), self.ev, NOW, 24)
        self.assertIn("older than the evidence", str(cm.exception))

    def test_one_stale_output_is_enough_to_refuse(self):
        self.write_evidence(AR1)
        out = self.outputs()
        out["output/trace.json"] = ts(EVIDENCE_AT - timedelta(hours=1))
        with self.assertRaises(br.RecordError) as cm:
            br.check_fresh(out, self.ev, NOW, 24)
        self.assertIn("trace.json", str(cm.exception))

    def test_missing_evidence_is_refused(self):
        with self.assertRaises(br.RecordError):
            br.check_fresh(self.outputs(), self.ev, NOW, 24)

    def test_evidence_too_old_to_be_this_run_is_refused(self):
        self.write_evidence(AR1, at=NOW - timedelta(hours=30))
        with self.assertRaises(br.RecordError) as cm:
            br.check_fresh(self.outputs(NOW), self.ev, NOW, 24)
        self.assertIn("hours old", str(cm.exception))
        br.check_fresh(self.outputs(NOW), self.ev, NOW, None)  # the age guard can be switched off

    def test_an_output_with_no_time_is_refused(self):
        self.write_evidence(AR1)
        out = self.outputs()
        out["output/findings.json"] = None
        with self.assertRaises(br.RecordError):
            br.check_fresh(out, self.ev, NOW, 24)

    def test_build_record_applies_the_check(self):
        self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]}, at=EVIDENCE_AT - timedelta(minutes=1))
        with self.assertRaises(br.RecordError):
            self.build(cov, trace({AR1: scope(["reached"])}), findings([]))


class Privacy(Fixture):
    def test_records_are_clean(self):
        self.write_evidence(AR1)
        rec = self.build(coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]}), trace({AR1: scope(["reached"])}),
                         findings([(AR1, "violation", "a.b")]))
        text = json.dumps(rec)
        for needle in ("/Users", "arn:aws", "@"):
            self.assertNotIn(needle, text)

    def test_sensitive_patterns_are_refused(self):
        fake_id = "7" * 12
        for bad in (f"acct {fake_id}", f"arn:aws:iam::{fake_id}:role/x", "someone@example.com", "/Users/x", "file:///tmp/x"):
            with self.assertRaises(br.RecordError, msg=bad):
                br.assert_clean({"x": bad})

    def test_a_leak_through_a_rule_id_is_refused_at_build_time(self):
        self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]})
        with self.assertRaises(br.RecordError):
            self.build(cov, trace({AR1: scope(["reached"])}), findings([(AR1, "violation", "x" + "7" * 12)]))

    def test_the_record_can_be_appended_to_a_store(self):
        self.write_evidence(AR1)
        rec = self.build(coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]}), trace({AR1: scope(["reached"])}), findings([]))
        store = history.Store(history.LocalBackend(self.root / "h"))
        store.init()
        store.put_record(rec)
        self.assertEqual(store.records()[0]["run_id"], rec["run_id"])


class StateAndEvent(Fixture):
    def two(self, rows=(), **kw):
        self.day = kw.get("covers_date", self.day)
        self.write_evidence(AR1, {"t0.json": {"generated_at": ts(EVIDENCE_AT)}})
        self.write_evidence(AR3, {"t0.json": {"generated_at": ts(EVIDENCE_AT - timedelta(minutes=2))},
                                  "t1.json": {"generated_at": ts(EVIDENCE_AT - timedelta(minutes=1))}},
                             at=EVIDENCE_AT - timedelta(minutes=3))
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True), (AR3, "Behavioral", True)]})
        tr = trace({AR1: scope(["reached"]), AR3: scope(["reached"])})
        return {m["ar"]: m for m in self.build(cov, tr, findings(list(rows)), **kw)["methods"]}

    def test_basis_is_recorded_per_method(self):
        by = self.two()
        self.assertEqual((by[AR1]["basis"], by[AR3]["basis"]), ("event", "state"))

    def test_an_event_method_records_its_window_and_no_collection_time(self):
        m = self.two()[AR1]
        self.assertEqual(m["window"], {"start": "2026-11-26T00:00:00Z", "end": "2026-11-27T00:00:00Z"})
        self.assertIsNone(m["collected_at"])

    def test_a_state_method_records_when_it_looked_and_no_window(self):
        m = self.two()[AR3]
        self.assertIsNone(m["window"])
        self.assertEqual(m["collected_at"], ts(EVIDENCE_AT - timedelta(minutes=1)))  # the newest of its evidence

    def test_a_state_method_with_no_evidence_has_no_collection_time_and_is_an_error(self):
        self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True), (AR3, "Behavioral", True)]})
        by = {m["ar"]: m for m in self.build(cov, trace({AR1: scope(["reached"]), AR3: scope([], run=False, expected=["x"])}), findings([]))["methods"]}
        self.assertEqual((by[AR3]["result"], by[AR3]["collected_at"]), ("error", None))

    def test_an_ar_without_a_declared_basis_is_refused(self):
        self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True)]})
        with self.assertRaises(br.RecordError) as cm:
            self.build(cov, trace({AR1: scope(["reached"])}), findings([]), basis={})
        self.assertIn("ar-basis.yaml", str(cm.exception))

    def test_the_normal_run_judges_state_rules_of_an_event_method(self):
        self.write_evidence(AR2)
        cov = coverage({"KSI-AAA-BBB": [(AR2, "Behavioral", True)]})
        m = self.build(cov, trace({AR2: scope(["reached"])}), findings([(AR2, "violation", "s.head")]))["methods"][0]
        self.assertEqual((m["result"], m["violations"]), ("fail", 1))


class Backfill(StateAndEvent):
    def test_state_methods_are_not_collected_for_a_past_day(self):
        by = self.two(covers_date="2026-11-20", backfill=True)
        m = by[AR3]
        self.assertEqual(m["result"], "not_collected")
        self.assertEqual((m["violations"], m["incomplete"], m["targets_expected"], m["targets_reached"]), (0, 0, 0, 0))
        self.assertEqual((m["window"], m["collected_at"], m["evidence_sha256"], m["rules_failed"]), (None, None, None, []))

    def test_a_past_days_event_window_is_that_day_not_the_run(self):
        m = self.two(covers_date="2026-11-20", backfill=True)[AR1]
        self.assertEqual(m["window"], {"start": "2026-11-20T00:00:00Z", "end": "2026-11-21T00:00:00Z"})

    def test_todays_state_is_never_used_for_a_past_day_even_if_it_failed(self):
        self.write_evidence(AR3)
        cov = coverage({"KSI-AAA-BBB": [(AR3, "Behavioral", True)]})
        m = self.build(cov, trace({AR3: scope(["reached"])}), findings([(AR3, "violation", "a.b")]),
                       covers_date="2026-11-20", backfill=True)["methods"][0]
        self.assertEqual((m["result"], m["violations"], m["rules_failed"]), ("not_collected", 0, []))

    def test_event_methods_get_real_results_in_a_backfill(self):
        by = self.two([(AR1, "violation", "a.b")], covers_date="2026-11-20", backfill=True)
        self.assertEqual((by[AR1]["result"], by[AR1]["violations"]), ("fail", 1))

    def test_rules_that_read_the_present_are_ignored_for_an_event_method_in_a_backfill(self):
        self.day = "2026-11-20"
        self.write_evidence(AR2)
        cov = coverage({"KSI-AAA-BBB": [(AR2, "Behavioral", True)]})
        rows = [(AR2, "violation", "s.head"), (AR2, "violation", "e.merge")]
        m = self.build(cov, trace({AR2: scope(["reached"])}), findings(rows), covers_date="2026-11-20", backfill=True)["methods"][0]
        self.assertEqual((m["result"], m["violations"], m["rules_failed"]), ("fail", 1, [{"rule": "e.merge", "count": 1}]))
        m = self.build(cov, trace({AR2: scope(["reached"])}), findings([(AR2, "violation", "s.head")]),
                       covers_date="2026-11-20", backfill=True)["methods"][0]
        self.assertEqual((m["result"], m["violations"]), ("pass", 0))

    def test_a_backfill_record_validates_and_says_so(self):
        self.day = "2026-11-20"
        self.write_evidence(AR1)
        self.write_evidence(AR3)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True), (AR3, "Behavioral", True)]})
        rec = self.build(cov, trace({AR1: scope(["reached"]), AR3: scope(["reached"])}), findings([]),
                         covers_date="2026-11-20", backfill=True)
        br.check_record(rec)
        self.assertEqual((rec["covers_date"], rec["backfill"]), ("2026-11-20", True))

    def test_schema_rejects_a_backfill_that_claims_a_result_for_a_state_method(self):
        import jsonschema
        rec = self.two(covers_date="2026-11-20", backfill=True)
        self.write_evidence(AR1)
        cov = coverage({"KSI-AAA-BBB": [(AR3, "Behavioral", True)]})
        good = self.build(cov, trace({AR3: scope(["reached"])}), findings([]), covers_date="2026-11-20", backfill=True)
        bad = json.loads(json.dumps(good))
        bad["methods"][0].update({"result": "pass", "collected_at": ts(EVIDENCE_AT)})
        with self.assertRaises(jsonschema.ValidationError):
            br.validate(bad)
        del rec


class SchemaFlavours(Fixture):
    """The three kinds of record: a normal day, a backfilled day, and a rerun of a day."""

    def base(self, **kw):
        self.day = kw.get("covers_date", self.day)
        self.write_evidence(AR1, {"t0.json": {"generated_at": ts(EVIDENCE_AT)}})
        self.write_evidence(AR3)
        cov = coverage({"KSI-AAA-BBB": [(AR1, "Intent", True), (AR3, "Behavioral", True)]})
        return self.build(cov, trace({AR1: scope(["reached"]), AR3: scope(["reached"])}), findings([]), **kw)

    def test_normal_day(self):
        rec = self.base()
        br.check_record(rec)
        self.assertFalse(rec["backfill"])
        self.assertEqual({m["result"] for m in rec["methods"]}, {"pass"})

    def test_backfilled_day(self):
        rec = self.base(covers_date="2026-11-20", backfill=True)
        br.check_record(rec)
        self.assertEqual({m["ar"]: m["result"] for m in rec["methods"]}, {AR1: "pass", AR3: "not_collected"})

    def test_a_rerun_is_a_new_record_for_the_same_day(self):
        a = self.base()
        b = br.build_record(coverage({"KSI-AAA-BBB": [(AR1, "Intent", True), (AR3, "Behavioral", True)]}),
                            trace({AR1: scope(["reached"]), AR3: scope(["reached"])}), findings([]),
                            self.ev, self.root, NOW + timedelta(hours=3), GIT, basis=BASIS, max_age_hours=None)
        self.assertEqual(a["covers_date"], b["covers_date"])
        self.assertNotEqual(a["run_id"], b["run_id"])
        store = history.Store(history.LocalBackend(self.root / "h"))
        store.init()
        store.put_record(a)
        store.put_record(b)
        self.assertEqual(len(store.records(validator=br.check_record)), 2)

    def test_a_record_cannot_cover_a_day_that_is_not_complete(self):
        for bad in ("2026-11-27", "2026-11-28"):
            with self.assertRaises(br.RecordError, msg=bad):
                self.base(covers_date=bad)
        self.day = "2026-11-26"
        rec = self.base()
        rec["covers_date"] = "2026-11-28"
        with self.assertRaises(br.RecordError):
            br.check_record(rec)


class Dates(unittest.TestCase):
    def test_default_is_yesterday_a_normal_run(self):
        self.assertEqual(br.resolve_covers_date(None, NOW), ("2026-11-26", False))
        self.assertEqual(br.resolve_covers_date("", NOW), ("2026-11-26", False))

    def test_yesterday_named_is_a_normal_run_and_any_earlier_day_a_backfill(self):
        self.assertEqual(br.resolve_covers_date("2026-11-26", NOW), ("2026-11-26", False))
        self.assertEqual(br.resolve_covers_date("2026-11-25", NOW), ("2026-11-25", True))
        self.assertEqual(br.resolve_covers_date("2026-09-01", NOW), ("2026-09-01", True))

    def test_today_and_the_future_are_refused_as_not_complete(self):
        for bad in ("2026-11-27", "2026-11-28"):
            with self.assertRaises(br.RecordError, msg=bad) as cm:
                br.resolve_covers_date(bad, NOW)
            self.assertIn("not a complete day", str(cm.exception))

    def test_junk_and_the_ninety_day_limit_are_refused(self):
        for bad in ("tomorrow", "2026-13-01", "27/11/2026", "2026-08-01"):
            with self.assertRaises(br.RecordError, msg=bad):
                br.resolve_covers_date(bad, NOW)

    def test_the_day_is_the_utc_day(self):
        late = utc(2026, 11, 27, 23, 59)
        self.assertEqual(br.resolve_covers_date(None, late), ("2026-11-26", False))
        self.assertEqual(br.resolve_covers_date(None, late + timedelta(minutes=2))[0], "2026-11-27")

    def test_a_check_before_collecting_applies_the_settle_delay_a_record_does_not(self):
        early = utc(2026, 11, 27, 0, 30)
        self.assertEqual(br.resolve_covers_date(None, early), ("2026-11-26", False))          # evidence already collected
        with self.assertRaises(br.RecordError) as cm:
            br.resolve_covers_date(None, early, settle=True)
        self.assertIn("RSC_ALLOW_EARLY", str(cm.exception))
        self.assertEqual(br.resolve_covers_date(None, early, settle=True, allow_early=True), ("2026-11-26", False))
        self.assertEqual(br.resolve_covers_date(None, early, settle=True, settle_minutes=30), ("2026-11-26", False))


class BasisFile(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "b.yaml"
            p.write_text(text)
            return br.load_basis(p)

    def test_shipped_declaration_loads(self):
        b = br.load_basis()
        self.assertEqual(b["RSC.CMT.CTRL01.AR02"]["basis"], "event")
        self.assertEqual(b["RSC.CMT.CTRL01.AR01"]["basis"], "state")
        self.assertIn("deployment.head-not-deployed", b["RSC.CMT.CTRL03.AR01"]["state_rules"])

    def test_good(self):
        b = self.load("X.AR1:\n  basis: event\n  state_rules: [a.b]\nX.AR2:\n  basis: state\n")
        self.assertEqual(b, {"X.AR1": {"basis": "event", "state_rules": {"a.b"}}, "X.AR2": {"basis": "state", "state_rules": set()}})

    def test_bad_basis_is_refused(self):
        for text in ("X.AR1:\n  basis: sometimes\n", "X.AR1:\n  note: no basis\n", "X.AR1:\n  basis: state\n  state_rules: [a.b]\n",
                     "X.AR1:\n  basis: event\n  state_rules: a.b\n"):
            with self.assertRaises(br.RecordError, msg=text):
                self.load(text)


if __name__ == "__main__":
    unittest.main()


class HashesAreNotAccountIds(unittest.TestCase):
    """A run of 12 digits inside a hex hash must not trip the leak check (about 2% of
    random SHA-256 strings contain one, and a record carries several hashes), but the same
    digits anywhere else still must."""

    def test_digit_run_inside_a_hash_field_is_allowed(self):
        digits = "7" * 12
        for field in br.HASH_FIELDS:
            br.assert_clean({field: "ab" + digits + "cd" * 20})
        br.assert_clean({"methods": [{"evidence_sha256": digits + "ab" * 26}], "pipeline": {"commit": "e" + digits + "f"}})

    def test_the_same_digits_in_any_other_field_are_refused(self):
        digits = "7" * 12
        for bad in ({"note": "ab" + digits + "cd"}, {"x": {"y": [f"x{digits}"]}}, {"evidence_sha256_note": digits}):
            with self.assertRaises(br.RecordError, msg=str(bad)):
                br.assert_clean(bad)

    def test_a_non_string_hash_field_is_still_scanned(self):
        with self.assertRaises(br.RecordError):
            br.assert_clean({"commit": {"leak": "7" * 12}})
