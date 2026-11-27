"""No AWS account ID may ever be committed: this repo is public.

Scans every tracked file for a 12-digit number or an ARN with an account in it.
There is deliberately no allowlist: tests build fake IDs at run time instead of
writing them down, so a hit here is always a real problem to fix.
"""
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWELVE_DIGITS = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
ACCOUNT_ARN = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:")


def tracked_text_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    for name in out.split(b"\0"):
        if not name:
            continue
        path = ROOT / name.decode()
        if not path.is_file():
            continue
        try:
            yield path, path.read_text()
        except UnicodeDecodeError:
            continue  # binary


class NoAccountIds(unittest.TestCase):
    def test_no_account_ids_in_tracked_files(self):
        hits = []
        for path, text in tracked_text_files():
            for n, line in enumerate(text.splitlines(), 1):
                if TWELVE_DIGITS.search(line) or ACCOUNT_ARN.search(line):
                    hits.append(f"{path.relative_to(ROOT)}:{n}")
        self.assertEqual(hits, [], "12-digit numbers or account ARNs found (account IDs must never be committed)")

    def test_the_detector_detects(self):
        fake = "7" * 12
        self.assertTrue(TWELVE_DIGITS.search(f"acct {fake}"))
        self.assertTrue(ACCOUNT_ARN.search(f"arn:aws:iam::{fake}:role/x"))
        self.assertFalse(TWELVE_DIGITS.search("2026-11-24T09:29:26Z or 20261124092926"))


if __name__ == "__main__":
    unittest.main()
