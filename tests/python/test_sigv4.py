import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import sigv4  # noqa: E402

# The example credentials and clock of the AWS Signature Version 4 test suite (public documentation).
CREDS = {"AccessKeyId": "AKIDEXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
NOW = datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc)


def signature(headers):
    return headers["Authorization"].split("Signature=")[1]


class AwsTestVectors(unittest.TestCase):
    def test_get_vanilla(self):
        _, h = sigv4.sign_get("https://example.amazonaws.com", "/", {}, CREDS, "us-east-1", "service", NOW)
        self.assertEqual(signature(h), "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
        self.assertIn("Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request", h["Authorization"])
        self.assertIn("SignedHeaders=host;x-amz-date", h["Authorization"])

    def test_get_vanilla_query_order_key_case(self):
        url, h = sigv4.sign_get("https://example.amazonaws.com", "/", {"Param2": "value2", "Param1": "value1"},
                                CREDS, "us-east-1", "service", NOW)
        self.assertEqual(signature(h), "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")
        self.assertEqual(url, "https://example.amazonaws.com/?Param1=value1&Param2=value2")


class QueryCanonicalization(unittest.TestCase):
    """The cases that broke `curl --aws-sigv4`: PromQL has spaces, commas, quotes and braces."""

    def test_spaces_are_percent_20_never_plus(self):
        self.assertEqual(sigv4.canonical_query({"query": "sum by (a) (up)"}), "query=sum%20by%20%28a%29%20%28up%29")

    def test_commas_quotes_braces_and_equals(self):
        got = sigv4.canonical_query({"query": 'up{cluster="mc01",job="x"} == 1'})
        self.assertEqual(got, "query=up%7Bcluster%3D%22mc01%22%2Cjob%3D%22x%22%7D%20%3D%3D%201")
        self.assertNotIn("+", got)

    def test_unreserved_characters_stay(self):
        self.assertEqual(sigv4.canonical_query({"a-b_c.d~e": "x-y_z.w~v"}), "a-b_c.d~e=x-y_z.w~v")

    def test_sorted_by_encoded_name(self):
        self.assertEqual(sigv4.canonical_query({"b": "1", "a": "2", "A": "3"}), "A=3&a=2&b=1")

    def test_the_url_sent_carries_exactly_the_canonical_query_that_was_signed(self):
        params = {"query": 'sum by (cluster, app) (argocd_app_info{name=~"a.*"})', "step": "60"}
        url, _ = sigv4.sign_get("https://x.example.com/prod", "/api/v1/query_range", params, CREDS, "us-east-1", "execute-api", NOW)
        self.assertTrue(url.endswith("?" + sigv4.canonical_query(params)))
        self.assertTrue(url.startswith("https://x.example.com/prod/api/v1/query_range?"))

    def test_signature_depends_on_the_query(self):
        sigs = {signature(sigv4.sign_get("https://x.example.com", "/q", {"query": q}, CREDS, "us-east-1", "execute-api", NOW)[1])
                for q in ("up", "up ", "up,", 'up"')}
        self.assertEqual(len(sigs), 4)


class Headers(unittest.TestCase):
    def test_session_token_is_signed_and_sent(self):
        creds = dict(CREDS, SessionToken="tok/en+1")
        _, h = sigv4.sign_get("https://x.example.com", "/", {}, creds, "us-east-1", "execute-api", NOW)
        self.assertEqual(h["x-amz-security-token"], "tok/en+1")
        self.assertIn("SignedHeaders=host;x-amz-date;x-amz-security-token", h["Authorization"])

    def test_no_token_means_no_token_header(self):
        _, h = sigv4.sign_get("https://x.example.com", "/", {}, CREDS, "us-east-1", "execute-api", NOW)
        self.assertNotIn("x-amz-security-token", h)

    def test_same_inputs_same_signature_and_the_clock_matters(self):
        a = sigv4.sign_get("https://x.example.com", "/", {"q": "1"}, CREDS, "us-east-1", "execute-api", NOW)
        b = sigv4.sign_get("https://x.example.com", "/", {"q": "1"}, CREDS, "us-east-1", "execute-api", NOW)
        c = sigv4.sign_get("https://x.example.com", "/", {"q": "1"}, CREDS, "us-east-1", "execute-api",
                           datetime(2015, 8, 30, 12, 37, 0, tzinfo=timezone.utc))
        self.assertEqual(a, b)
        self.assertNotEqual(signature(a[1]), signature(c[1]))

    def test_path_segments_are_encoded_twice_except_for_s3(self):
        self.assertEqual(sigv4.canonical_path("/a b/c", "execute-api"), "/a%2520b/c")
        self.assertEqual(sigv4.canonical_path("/a b/c", "s3"), "/a b/c")
        self.assertEqual(sigv4.canonical_path("", "execute-api"), "/")


if __name__ == "__main__":
    unittest.main()
