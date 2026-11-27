import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import fedramp_data  # noqa: E402


class NormalizeControlId(unittest.TestCase):
    def test_spellings_agree(self):
        for raw in ("CM-03 (02)", "cm-3.2", "CM-3 (2)", " cm-03.02 "):
            self.assertEqual(fedramp_data.normalize_control_id(raw), "cm-3.2")

    def test_base_control(self):
        self.assertEqual(fedramp_data.normalize_control_id("AU-02"), "au-2")
        self.assertEqual(fedramp_data.normalize_control_id("ac-12"), "ac-12")

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            fedramp_data.normalize_control_id("not a control")


class Dataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = fedramp_data.load_dataset()
        cls.ksis = fedramp_data.load_ksis(cls.dataset)

    def test_version_pinned(self):
        self.assertEqual(self.dataset["info"]["version"], "2026.11.02.01")

    def test_46_ksis(self):
        self.assertEqual(len(self.ksis), 46)

    def test_302_distinct_related_controls(self):
        self.assertEqual(len(fedramp_data.related_controls(self.ksis)), 302)

    def test_varies_by_class_statement_resolved(self):
        self.assertTrue(self.ksis["KSI-CNA-EIS"]["statement"])
        self.assertFalse(self.ksis["KSI-CNA-EIS"]["statement"].startswith("**Optional:**"))
        self.assertTrue(all(k["statement"] for k in self.ksis.values()))

    def test_vtd_controls(self):
        self.assertEqual(self.ksis["KSI-CMT-VTD"]["controls"],
                         ["cm-3", "cm-3.2", "cm-4.2", "cm-6.2", "ir-9.4", "si-2"])

    def test_vendored_schemas_load(self):
        for p in (ROOT / "mappings/vendor/fedramp/schemas").glob("*.json"):
            json.loads(p.read_text())


if __name__ == "__main__":
    unittest.main()
