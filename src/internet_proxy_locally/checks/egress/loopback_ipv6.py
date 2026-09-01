"""loopback-ipv6: CONNECT to [::1] is refused."""

from __future__ import annotations

from .models import Check
from .probes import _classify_deny_connect
from .transport import ProxyClient


def test_ipv6_loopback(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "[::1]:80")


CHECK = Check(
    "loopback-ipv6",
    "quick",
    "deny",
    test_ipv6_loopback,
    False,
    "CONNECT to [::1] is refused.",
)
