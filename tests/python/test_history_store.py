import json
import os
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import history  # noqa: E402
from history_fakes import ENDPOINT, FakeS3, make_record, utc  # noqa: E402

M = {("KSI-AAA-BBB", "AR.1"): "pass"}


class Backends(unittest.TestCase):
    """The local folder and S3 (stubbed CLI) must behave identically."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def backends(self):
        yield "local", history.LocalBackend(Path(self.tmp.name) / "h")
        yield "s3", history.S3Backend("bkt", "pre/history", ENDPOINT, runner=FakeS3())
        yield "s3 without conditional writes", history.S3Backend("bkt", "pre/history", None, runner=FakeS3(no_conditional=True))

    def test_get_missing_is_none(self):
        for name, b in self.backends():
            self.assertIsNone(b.get("v1/INIT"), name)

    def test_put_then_get_and_list(self):
        for name, b in self.backends():
            b.put_new("v1/runs/2026/11/01/x.json", b"one")
            b.put_new("v1/runs/2026/11/02/y.json", b"two")
            b.put_new("v1/INIT", b"i")
            self.assertEqual(b.get("v1/runs/2026/11/01/x.json"), b"one", name)
            self.assertEqual(b.list("v1/runs/"), ["v1/runs/2026/11/01/x.json", "v1/runs/2026/11/02/y.json"], name)
            self.assertEqual(b.list("v1/ledger/"), [], name)

    def test_never_overwrites(self):
        for name, b in self.backends():
            b.put_new("v1/runs/2026/11/01/x.json", b"one")
            with self.assertRaises(history.AlreadyExists, msg=name):
                b.put_new("v1/runs/2026/11/01/x.json", b"two")
            self.assertEqual(b.get("v1/runs/2026/11/01/x.json"), b"one", name)

    def test_unsafe_keys_are_refused(self):
        for name, b in self.backends():
            for bad in ("../x", "/abs", "a/../b", ""):
                with self.assertRaises(history.StoreError, msg=f"{name} {bad!r}"):
                    b.get(bad)

    def test_local_writes_leave_no_temp_files(self):
        b = history.LocalBackend(Path(self.tmp.name) / "h")
        b.put_new("v1/runs/2026/11/01/x.json", b"one")
        names = [p.name for p in (Path(self.tmp.name) / "h").rglob("*") if p.is_file()]
        self.assertEqual(names, ["x.json"])

    def test_s3_uses_a_conditional_put_and_checks_first(self):
        fake = FakeS3()
        b = history.S3Backend("bkt", "pre/history", ENDPOINT, runner=fake)
        b.put_new("v1/INIT", b"i")
        ops = [c[c.index("s3api") + 1] for c in fake.calls]
        self.assertEqual(ops, ["head-object", "put-object"])
        self.assertIn("--if-none-match", fake.calls[-1])
        self.assertIn(ENDPOINT, fake.calls[0])

    def test_s3_keys_are_under_the_prefix(self):
        fake = FakeS3()
        history.S3Backend("bkt", "pre/history", None, runner=fake).put_new("v1/INIT", b"i")
        self.assertEqual(list(fake.objects), ["pre/history/v1/INIT"])


class StoreSemantics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def stores(self):
        yield "local", history.Store(history.LocalBackend(Path(self.tmp.name) / "h"))
        yield "s3", history.Store(history.S3Backend("bkt", "pre/history", ENDPOINT, runner=FakeS3()))

    def test_uninitialised_is_not_empty_history(self):
        for name, s in self.stores():
            with self.assertRaises(history.NotInitialised, msg=name):
                s.records()
            with self.assertRaises(history.NotInitialised, msg=name):
                s.put_record(make_record(utc(2026, 11, 1), M))

    def test_init_is_idempotent(self):
        for name, s in self.stores():
            self.assertTrue(s.init(), name)
            self.assertFalse(s.init(), name)
            self.assertEqual(s.require_init()["layout"], "rsc-history")
            self.assertNotIn("ledger_prefix", s.require_init())  # no ledger: the layout is just INIT and runs/

    def test_incompatible_marker_is_an_error(self):
        for name, s in self.stores():
            s.backend.put_new("v1/INIT", json.dumps({"layout": "other", "version": 1}).encode())
            with self.assertRaises(history.Incompatible, msg=name):
                s.require_init()
            with self.assertRaises(history.Incompatible, msg=name):
                s.init()

    def test_corrupt_marker_is_unreadable(self):
        for name, s in self.stores():
            s.backend.put_new("v1/INIT", b"not json")
            with self.assertRaises(history.Unreadable, msg=name):
                s.require_init()

    def test_unreadable_store_is_an_error_not_no_history(self):
        s = history.Store(history.S3Backend("bkt", "p", None, runner=FakeS3(fail_all="An error occurred (AccessDenied)")))
        with self.assertRaises(history.Unreadable):
            s.records()
        with self.assertRaises(history.Unreadable):
            s.init()

    def test_record_layout_and_roundtrip(self):
        for name, s in self.stores():
            s.init()
            rec = make_record(utc(2026, 11, 5, 9), M)
            key = s.put_record(rec)
            self.assertEqual(key, f"v1/runs/2026/11/05/{rec['run_id']}.json", name)
            self.assertEqual(s.records(), [rec], name)

    def test_a_rerun_of_a_day_appends_and_never_replaces(self):
        for name, s in self.stores():
            s.init()
            first = make_record(utc(2026, 11, 5, 9), M, suffix="aaaaaa")
            second = make_record(utc(2026, 11, 5, 15), {("KSI-AAA-BBB", "AR.1"): "fail"}, suffix="bbbbbb")
            s.put_record(first)
            s.put_record(second)
            with self.assertRaises(history.AlreadyExists, msg=name):
                s.put_record(first)
            self.assertEqual([r["run_id"] for r in s.records()], [first["run_id"], second["run_id"]], name)

    def test_date_range_filter_is_inclusive(self):
        for name, s in self.stores():
            s.init()
            for d in (1, 2, 3, 4):
                s.put_record(make_record(utc(2026, 11, d), M))
            got = [r["run_id"][:8] for r in s.records(since=date(2026, 11, 2), until=date(2026, 11, 3))]
            self.assertEqual(got, ["20261102", "20261103"], name)

    def test_a_corrupt_record_fails_closed(self):
        for name, s in self.stores():
            s.init()
            s.put_record(make_record(utc(2026, 11, 1), M))
            s.backend.put_new("v1/runs/2026/11/02/20261102T090000Z-c0ffee.json", b"{broken")
            with self.assertRaises(history.Unreadable, msg=name):
                s.records()

    def test_a_record_that_does_not_match_its_key_fails_closed(self):
        for name, s in self.stores():
            s.init()
            rec = make_record(utc(2026, 11, 1), M)
            s.backend.put_new("v1/runs/2026/11/09/20261109T090000Z-abcdef.json", json.dumps(rec).encode())
            with self.assertRaises(history.Unreadable, msg=name):
                s.records()

    def test_an_unexpected_object_in_the_runs_area_fails_closed(self):
        for name, s in self.stores():
            s.init()
            s.backend.put_new("v1/runs/stray.txt", b"x")
            with self.assertRaises(history.Unreadable, msg=name):
                s.records()

    def test_a_record_is_filed_under_the_day_it_covers_not_the_day_it_was_made(self):
        for name, s in self.stores():
            s.init()
            rec = make_record(utc(2026, 11, 27, 9), M, covers="2026-11-20", backfill=True, basis={"AR.1": "event"})
            key = s.put_record(rec)
            self.assertEqual(key, f"v1/runs/2026/11/20/{rec['run_id']}.json", name)
            self.assertEqual([r["run_id"] for r in s.records(since=date(2026, 11, 20), until=date(2026, 11, 20))], [rec["run_id"]], name)
            self.assertEqual(s.records(since=date(2026, 11, 27)), [], name)

    def test_a_record_filed_under_the_wrong_covered_day_fails_closed(self):
        for name, s in self.stores():
            s.init()
            rec = make_record(utc(2026, 11, 27, 9), M, covers="2026-11-20")
            s.backend.put_new(f"v1/runs/2026/11/21/{rec['run_id']}.json", json.dumps(rec).encode())
            with self.assertRaises(history.Unreadable, msg=name):
                s.records()

    def test_a_record_without_a_covered_day_cannot_be_appended(self):
        for name, s in self.stores():
            s.init()
            rec = make_record(utc(2026, 11, 27, 9), M)
            del rec["covers_date"]
            with self.assertRaises(history.Unreadable, msg=name):
                s.put_record(rec)

    def test_records_come_back_in_covered_day_order_then_finish_time(self):
        for name, s in self.stores():
            s.init()
            late_for_old_day = make_record(utc(2026, 11, 27, 9), M, covers="2026-11-10", suffix="aaaaaa")
            normal = make_record(utc(2026, 11, 12, 9), M, suffix="bbbbbb")
            s.put_record(normal)
            s.put_record(late_for_old_day)
            self.assertEqual([r["covers_date"] for r in s.records()], ["2026-11-10", "2026-11-12"], name)

    def test_a_validator_can_reject_a_stored_record_and_the_history_fails_closed(self):
        for name, s in self.stores():
            s.init()
            s.put_record(make_record(utc(2026, 11, 1), M))
            def reject(rec):
                raise ValueError("schema says no\nsecond line")
            with self.assertRaises(history.Unreadable, msg=name) as cm:
                s.records(validator=reject)
            self.assertIn("schema says no", str(cm.exception))
            self.assertNotIn("second line", str(cm.exception))

    def test_bad_run_ids_and_days_are_refused(self):
        for bad in ("", "x", "2026-11-01", "20261101T090000Z"):
            with self.assertRaises(history.Unreadable, msg=bad):
                history.check_run_id(bad)
        for bad in (None, "", "2026-13-01", "yesterday"):
            with self.assertRaises(history.Unreadable, msg=str(bad)):
                history.parse_day(bad)

    def test_run_id_shape(self):
        rid = history.new_run_id(utc(2026, 11, 5, 9, 30))
        self.assertRegex(rid, r"^20261105T093000Z-[0-9a-f]{6}$")
        self.assertNotEqual(history.new_run_id(utc(2026, 11, 5)), history.new_run_id(utc(2026, 11, 5)))


class Selection(unittest.TestCase):
    def test_bucket_selects_s3_with_the_push_evidence_variables(self):
        b = history.open_backend({"RSC_S3_BUCKET": "bkt", "RSC_S3_PREFIX": "pfx", "RSC_S3_ENDPOINT_URL": "http://x:1"})
        self.assertIsInstance(b, history.S3Backend)
        self.assertEqual((b.bucket, b.prefix, b.endpoint), ("bkt", "pfx/history", "http://x:1"))

    def test_default_prefix(self):
        self.assertEqual(history.open_backend({"RSC_S3_BUCKET": "bkt"}).prefix, "rosa-seaplane-compliance/history")

    def test_no_bucket_selects_the_local_default_or_override(self):
        b = history.open_backend({})
        self.assertIsInstance(b, history.LocalBackend)
        self.assertEqual(b.root, ROOT / ".history")
        self.assertEqual(history.open_backend({"RSC_HISTORY_DIR": "/tmp/x"}).root, Path("/tmp/x"))

    def test_the_local_default_is_gitignored(self):
        self.assertIn(".history/", (ROOT / ".gitignore").read_text().splitlines())


if __name__ == "__main__":
    unittest.main()
