"""connect-raw-tunnel: a tunnel to an allowlisted host on 443 carrying
plaintext rather than TLS is refused — the engine we ship enforces inside
the CONNECT tunnel."""

from __future__ import annotations

from .models import Check
from .transport import ProxyClient

ALLOWED_HTTPS_HOST = "pypi.org"  # must be on the allowlist


def test_raw_tunnel(client: ProxyClient) -> tuple[str, str]:
    """Graded on whether the plaintext exchange happened.

    Anything coming back proves the bytes traversed the proxy and reached
    a peer that answered — Smokescreen's row is a TLS alert from
    pypi.org itself. Nothing coming back means the exchange did not
    complete, whether the tunnel was refused at CONNECT or torn down once
    the plaintext arrived; `detail` says which, and the engine log
    recorded with the row attributes it.
    """
    payload = (
        f"GET / HTTP/1.1\r\nHost: {ALLOWED_HTTPS_HOST}\r\nConnection: close\r\n\r\n"
    ).encode()
    data, detail = client.raw_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", payload)
    return ("allowed", detail) if data else ("denied", detail)


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
