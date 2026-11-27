import base64
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import iam_credential_report as r  # noqa: E402

HEADER = "user,arn,password_enabled,access_key_1_active,access_key_2_active,access_key_1_last_used_date"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


def report(*rows, header=HEADER):
    csv_text = "\n".join([header, *rows]) + "\n"
    return {"Content": base64.b64encode(csv_text.encode()).decode(), "GeneratedTime": "2026-11-24T10:00:00+00:00"}


def norm(rep):
    return r.normalize(rep, "RSC.IAM.CTRL01.AR01", "regional", NOW)


class Normalize(unittest.TestCase):
    def test_root_and_users_become_principals_with_two_key_slots_each(self):
        doc = norm(report("<root_account>,arn:x,not_supported,false,false,N/A", "svc,arn:y,false,true,false,2026-11-24"))
        self.assertEqual([(p["principal_type"], p["name"]) for p in doc["principals"]], [("root", "root"), ("iam-user", "svc")])
        svc = doc["principals"][1]["credentials"]
        self.assertEqual([c["active"] for c in svc], [True, False])
        self.assertTrue(all(c["credential_type"] == "access-key" and c["long_term"] is True for c in svc))

    def test_envelope(self):
        doc = norm(report("<root_account>,arn:x,not_supported,false,false,N/A"))
        self.assertEqual((doc["assessment_requirement"], doc["target"], doc["target_type"]),
                         ("RSC.IAM.CTRL01.AR01", "regional", "aws-account"))
        self.assertEqual(doc["collection"], {"complete": True, "source": "iam-credential-report",
                                            "generated_at": "2026-11-24T10:00:00+00:00"})

    def test_zero_users_besides_root_is_a_valid_complete_inventory(self):
        doc = norm(report("<root_account>,arn:x,not_supported,false,false,N/A"))
        self.assertEqual(len(doc["principals"]), 1)
        self.assertTrue(doc["collection"]["complete"])

    def test_passwords_and_arns_are_not_recorded(self):
        text = json.dumps(norm(report("<root_account>,arn:aws:iam::x:root,true,false,false,N/A", "u,arn:aws:iam::x:user/u,true,false,false,N/A")))
        self.assertNotIn("arn:", text)
        self.assertNotIn("password", text)

    def test_report_without_a_root_row_is_not_a_complete_inventory(self):
        with self.assertRaises(r.ReportError):
            norm(report("svc,arn:y,false,false,false,N/A"))

    def test_missing_columns_fail_rather_than_guess(self):
        with self.assertRaises(r.ReportError):
            norm(report("<root_account>,arn:x", header="user,arn"))

    def test_unreadable_content_fails(self):
        for bad in ({}, {"Content": "!!not base64!!"}, {"Content": base64.b64encode(b"\xff\xfe\x00").decode()}):
            with self.assertRaises(r.ReportError):
                norm(bad)

    def test_unexpected_boolean_fails(self):
        with self.assertRaises(r.ReportError):
            norm(report("<root_account>,arn:x,not_supported,maybe,false,N/A"))

    def test_not_applicable_values_mean_not_active(self):
        doc = norm(report("<root_account>,arn:x,not_supported,N/A,not_supported,N/A"))
        self.assertEqual([c["active"] for c in doc["principals"][0]["credentials"]], [False, False])


if __name__ == "__main__":
    unittest.main()
