#!/usr/bin/env python3
"""Normalize an IAM credential report into principal-credentials evidence.

    aws iam get-credential-report --output json | \\
        iam_credential_report.py --ar <AR id> --target <logical account name>

Reads the `get-credential-report` JSON on stdin and prints the evidence document
described in schemas/principal-credentials.cue. Only access keys are recorded:
console passwords and MFA belong to people and are out of scope for the control.
The root user is a principal like any other (its keys count).

It fails, rather than guess, when the report is malformed or missing a column, so
an unreadable inventory becomes a collection error and is never read as a pass.
Zero IAM users is valid; the root row is always present in a real report.
"""
import argparse
import base64
import csv
import io
import json
import sys
from datetime import datetime, timezone

REQUIRED = ("user", "access_key_1_active", "access_key_2_active")
ROOT_ROW = "<root_account>"


class ReportError(ValueError):
    pass


def parse_bool(value: str, column: str, user: str) -> bool:
    v = (value or "").strip().lower()
    if v in ("true", "false"):
        return v == "true"
    # "N/A" and "not_supported" mean the column does not apply to this principal.
    if v in ("n/a", "not_supported", ""):
        return False
    raise ReportError(f"unexpected value {value!r} in {column} for {user!r}")


def normalize(report: dict, ar: str, target: str, now: datetime = None) -> dict:
    try:
        text = base64.b64decode(report["Content"]).decode()
    except (KeyError, ValueError, UnicodeDecodeError) as e:
        raise ReportError(f"credential report content is missing or unreadable: {e}") from None
    reader = csv.DictReader(io.StringIO(text))
    missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
    if missing:
        raise ReportError(f"credential report is missing columns: {', '.join(missing)}")
    principals = []
    for row in reader:
        user = row["user"]
        credentials = [
            {"credential_type": "access-key", "long_term": True,
             "active": parse_bool(row[f"access_key_{n}_active"], f"access_key_{n}_active", user)}
            for n in (1, 2)
        ]
        principals.append({"principal_type": "root" if user == ROOT_ROW else "iam-user",
                           "name": "root" if user == ROOT_ROW else user, "credentials": credentials})
    if not any(p["principal_type"] == "root" for p in principals):
        raise ReportError("credential report has no root row; it is not a complete inventory")
    now = now or datetime.now(timezone.utc)
    generated = report.get("GeneratedTime") or now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "assessment_requirement": ar,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target,
        "target_type": "aws-account",
        "collection": {"complete": True, "source": "iam-credential-report", "generated_at": str(generated)},
        "principals": principals,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ar", required=True)
    ap.add_argument("--target", required=True)
    args = ap.parse_args()
    try:
        print(json.dumps(normalize(json.load(sys.stdin), args.ar, args.target), indent=2))
    except (ReportError, ValueError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
