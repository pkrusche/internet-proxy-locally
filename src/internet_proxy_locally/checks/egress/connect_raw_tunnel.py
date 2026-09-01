"""connect-raw-tunnel: a tunnel to an allowlisted host on 443 carrying
plaintext rather than TLS is refused — the engine we ship enforces inside
the CONNECT tunnel."""

from __future__ import annotations

from .models import Check
from .transport import ProxyClient

ALLOWED_HTTPS_HOST = "pypi.org"  # must be on the allowlist


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
    "deny",
    test_raw_tunnel,
    False,
    "A tunnel to an allowlisted host on 443 carrying plaintext "
    "rather than TLS is refused — enforcement inside the CONNECT "
    "tunnel.",
)
