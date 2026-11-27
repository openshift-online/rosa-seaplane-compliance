import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("entrypoint", ROOT / "containers/complyctl/entrypoint.py")
entrypoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entrypoint)

AR1, AR2 = "RSC.CMT.CTRL01.AR01", "RSC.CMT.CTRL01.AR02"


def write(root: Path, ar: str, declared: str, name="evidence.json"):
    d = root / ar
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps({"assessment_requirement": declared}))


class MissingEvidence(unittest.TestCase):
    def test_all_present(self):
        with tempfile.TemporaryDirectory() as t:
            write(Path(t), AR1, AR1)
            write(Path(t), AR2, AR2)
            self.assertEqual(entrypoint.missing_evidence([AR1, AR2], Path(t)), [])

    def test_missing_directory_is_reported(self):
        with tempfile.TemporaryDirectory() as t:
            write(Path(t), AR1, AR1)
            self.assertEqual(entrypoint.missing_evidence([AR1, AR2], Path(t)), [AR2])

    def test_empty_directory_is_reported(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / AR1).mkdir()
            self.assertEqual(entrypoint.missing_evidence([AR1], Path(t)), [AR1])

    def test_evidence_declaring_another_ar_does_not_count(self):
        with tempfile.TemporaryDirectory() as t:
            write(Path(t), AR1, AR2)
            self.assertEqual(entrypoint.missing_evidence([AR1], Path(t)), [AR1])

    def test_unparseable_evidence_does_not_count(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / AR1
            d.mkdir()
            (d / "evidence.json").write_text("not json")
            self.assertEqual(entrypoint.missing_evidence([AR1], Path(t)), [AR1])


class PolicyArs(unittest.TestCase):
    def test_reads_ars_from_policies(self):
        import os
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            # The order follows the policy files, which is not what matters: every AR the policies assess.
            self.assertEqual(sorted(entrypoint.policy_ars()), sorted([
                AR1, AR2, "RSC.CMT.CTRL02.AR01", "RSC.CMT.CTRL03.AR01", "RSC.CMT.CTRL03.AR02",
                "RSC.IAM.CTRL01.AR01", "RSC.IAM.CTRL01.AR02"]))
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()


class GenerationCache(unittest.TestCase):
    """The opa provider keys its generated scan config by input path, so policies sharing
    an input path overwrite each other; the entrypoint must force regeneration."""

    def test_reset_removes_both_caches_and_keeps_the_rest(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t) / ".complytime"
            for sub in ("generation/x", "opa/generated/y", "scan", "opa/results"):
                (ws / sub).mkdir(parents=True)
                (ws / sub / "f").write_text("x")
            entrypoint.reset_generation_cache(ws)
            self.assertFalse((ws / "generation").exists())
            self.assertFalse((ws / "opa/generated").exists())
            self.assertTrue((ws / "scan/f").exists())
            self.assertTrue((ws / "opa/results/f").exists())

    def test_reset_is_harmless_when_nothing_exists(self):
        with tempfile.TemporaryDirectory() as t:
            entrypoint.reset_generation_cache(Path(t) / "nope")

    def test_every_scan_is_preceded_by_a_reset(self):
        import os
        from unittest import mock
        calls = []
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            with mock.patch.object(entrypoint, "reset_generation_cache", side_effect=lambda *a: calls.append("reset")), \
                 mock.patch.object(entrypoint, "run", side_effect=lambda cmd, check=True: calls.append(cmd[1] if cmd[0] == "complyctl" else cmd[0])), \
                 mock.patch.object(entrypoint, "missing_evidence", return_value=[]), \
                 mock.patch.object(entrypoint.subprocess, "run"), \
                 mock.patch.dict(os.environ, {"GITHUB_TOKEN": "x", "RSC_EVIDENCE_DIR": str(ROOT / "evidence/output")}):
                entrypoint.main()
        finally:
            os.chdir(cwd)
        scans = [i for i, c in enumerate(calls) if c == "scan"]
        self.assertGreaterEqual(len(scans), 2)  # one per domain
        for i in scans:
            self.assertEqual(calls[i - 1], "reset")


class TheDay(unittest.TestCase):
    """`make run-local` decides the UTC day of the event checks once and tells every collector."""

    NOW = datetime(2026, 11, 27, 9, 0, tzinfo=timezone.utc)

    def fix(self, **env):
        environ = dict(env)
        day = entrypoint.fix_the_day(environ, self.NOW)
        return day, environ

    def test_default_is_yesterday_and_every_collector_is_told(self):
        day, environ = self.fix()
        self.assertEqual((day["covers_date"], day["backfill"]), ("2026-11-26", False))
        self.assertEqual(environ["RSC_DATE"], "2026-11-26")

    def test_an_explicit_yesterday_is_accepted(self):
        self.assertEqual(self.fix(RSC_DATE="2026-11-26")[1]["RSC_DATE"], "2026-11-26")

    def test_today_the_future_and_junk_are_refused(self):
        for bad in ("2026-11-27", "2026-12-01", "tomorrow"):
            with self.assertRaises(SystemExit, msg=bad):
                self.fix(RSC_DATE=bad)

    def test_a_past_day_is_a_backfill_and_run_local_sends_you_to_make_daily(self):
        with self.assertRaises(SystemExit) as cm:
            self.fix(RSC_DATE="2026-11-20")
        self.assertIn("make daily DATE=", str(cm.exception))

    def test_a_day_that_has_not_settled_is_refused_unless_allowed(self):
        early = self.NOW.replace(hour=0, minute=30)
        with self.assertRaises(SystemExit):
            entrypoint.fix_the_day({}, early)
        self.assertEqual(entrypoint.fix_the_day({"RSC_ALLOW_EARLY": "1"}, early)["covers_date"], "2026-11-26")
        self.assertEqual(entrypoint.fix_the_day({"RSC_SETTLE_MINUTES": "10"}, early)["covers_date"], "2026-11-26")

