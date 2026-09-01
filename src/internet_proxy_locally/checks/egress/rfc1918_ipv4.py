"""rfc1918-ipv4: CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is
refused."""

from __future__ import annotations

from .models import Check
from .probes import _deny_all
from .transport import ProxyClient


def test_rfc1918(client: ProxyClient) -> tuple[str, str]:
    return _deny_all(client, "10.0.0.1:80", "192.168.1.1:80", "172.16.0.1:80")


CHECK = Check(
    "rfc1918-ipv4",
    "quick",
    "deny",
    test_rfc1918,
    False,
    "CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is refused.",
)
