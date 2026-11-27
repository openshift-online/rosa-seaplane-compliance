"""AWS Signature Version 4 for a GET, standard library only.

Why this exists: `curl --aws-sigv4` signs a query string wrongly when it contains
spaces or commas (PromQL always does) unless the caller percent-encodes it by hand, and
a naive `-G --data-urlencode` fails with "the request signature we calculated does not
match". Here the query is canonicalized once, exactly as the specification says, and the
same canonical form is what is sent.

    url, headers = sign_get(base_url, "/api/v1/query", {"query": 'up{a="b"}'}, credentials,
                            region="us-east-1", service="execute-api")

`credentials` is {"AccessKeyId", "SecretAccessKey", optional "SessionToken"}. Nothing here
reads the environment, the clock (pass `now` in tests) or the network. Verified against
the AWS Signature Version 4 test suite vectors in tests/python/test_sigv4.py.
"""
import hashlib
import hmac
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_PAYLOAD_SHA256 = hashlib.sha256(b"").hexdigest()


def _enc(value: str) -> str:
    """RFC 3986 percent-encoding: unreserved characters stay, everything else (including
    the space, as %20, never '+') is encoded."""
    return quote(str(value), safe="-_.~")


def canonical_query(params: dict) -> str:
    """Sorted by encoded name then encoded value, joined as name=value pairs."""
    pairs = sorted((_enc(k), _enc(v)) for k, v in params.items())
    return "&".join(f"{k}={v}" for k, v in pairs)


def canonical_path(path: str, service: str) -> str:
    """Every service except S3 encodes each path segment twice."""
    path = path or "/"
    if service == "s3":
        return path
    return "/".join(_enc(_enc(segment)) for segment in path.split("/")) or "/"


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    key = _hmac(("AWS4" + secret).encode(), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    return key


def sign_get(base_url: str, path: str, params: dict, credentials: dict, region: str, service: str,
             now: datetime = None) -> tuple:
    """Return (full url with the canonical query, headers to send) for a signed GET."""
    parts = urlsplit(base_url)
    host = parts.netloc
    full_path = parts.path.rstrip("/") + path
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")

    headers = {"host": host, "x-amz-date": amz_date}
    if credentials.get("SessionToken"):
        headers["x-amz-security-token"] = credentials["SessionToken"]
    signed = ";".join(sorted(headers))
    canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in sorted(headers))

    query = canonical_query(params)
    canonical_request = "\n".join(["GET", canonical_path(full_path, service), query,
                                   canonical_headers, signed, EMPTY_PAYLOAD_SHA256])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join([ALGORITHM, amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()])
    signature = hmac.new(signing_key(credentials["SecretAccessKey"], date, region, service),
                         to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (f"{ALGORITHM} Credential={credentials['AccessKeyId']}/{scope}, "
                                f"SignedHeaders={signed}, Signature={signature}")
    url = f"{parts.scheme}://{host}{full_path}" + (f"?{query}" if query else "")
    return url, headers
