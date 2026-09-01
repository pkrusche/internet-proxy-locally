"""connect-raw-tunnel: what the engine does when a tunnel to an allowlisted
host on 443 carries plaintext rather than TLS."""

from __future__ import annotations

from .models import Check
from .targets import ALLOWED_HTTPS_HOST
from .transport import ProxyClient


def test_raw_tunnel(client: ProxyClient) -> tuple[str, str]:
    payload = (
        f"GET / HTTP/1.1\r\nHost: {ALLOWED_HTTPS_HOST}\r\nConnection: close\r\n\r\n"
    ).encode()
    data, detail = client.raw_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", payload)
    if not data:
        return "denied", detail
    return "allowed", detail


CHECK = Check(
    "connect-raw-tunnel",
    "full",
    "record",
    test_raw_tunnel,
    False,
    "What the engine does when a tunnel to an allowlisted host on "
    "443 carries plaintext rather than TLS.",
)
