"""allowed-https: a CONNECT tunnel to an allowlisted host completes a real
TLS handshake, so ordinary HTTPS works through the proxy."""

from __future__ import annotations

from .models import Check
from .transport import ProxyClient

ALLOWED_HTTPS_HOST = "pypi.org"  # must be on the allowlist


def test_allowed_https(client: ProxyClient) -> tuple[str, str]:
    ok, detail = client.tls_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", ALLOWED_HTTPS_HOST)
    return ("pass" if ok else "fail"), detail


CHECK = Check(
    "allowed-https",
    "quick",
    "allow",
    test_allowed_https,
    False,
    "A CONNECT tunnel to an allowlisted host completes a real TLS "
    "handshake, so ordinary HTTPS works through the proxy.",
)
