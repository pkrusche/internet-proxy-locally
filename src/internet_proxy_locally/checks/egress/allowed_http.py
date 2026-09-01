"""allowed-http: a plain-HTTP GET to an allowlisted host reaches it."""

from __future__ import annotations

from .models import Check, RawOutcome
from .transport import ProxyClient

ALLOWED_HTTP_HOST = "pypi.org"  # must be on the allowlist


def test_allowed_http(client: ProxyClient) -> RawOutcome:
    resp = client.http_get(f"http://{ALLOWED_HTTP_HOST}/")
    if resp.status is not None and resp.status < 400:
        return RawOutcome(
            "pass",
            f"reached {ALLOWED_HTTP_HOST} ({resp.first_line})",
            headers=resp.headers,
        )
    return RawOutcome("fail", f"expected success, got: {resp.first_line}")


CHECK = Check(
    "allowed-http",
    "quick",
    "allow",
    test_allowed_http,
    False,
    "A plain-HTTP GET to an allowlisted host reaches it.",
)
