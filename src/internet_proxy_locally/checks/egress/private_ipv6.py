"""private-ipv6: CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is
refused."""

from __future__ import annotations

from .models import Check
from .probes import _deny_all
from .transport import ProxyClient


def test_ipv6_private(client: ProxyClient) -> tuple[str, str]:
    return _deny_all(client, "[fd00::1]:80", "[fe80::1]:80")


CHECK = Check(
    "private-ipv6",
    "quick",
    "deny",
    test_ipv6_private,
    False,
    "CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is refused.",
)
