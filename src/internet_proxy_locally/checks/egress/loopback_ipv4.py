"""loopback-ipv4: CONNECT to 127.0.0.1 is refused."""

from __future__ import annotations

from .models import Check
from .probes import _classify_deny_connect
from .transport import ProxyClient


def test_loopback(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "127.0.0.1:80")


CHECK = Check(
    "loopback-ipv4",
    "quick",
    "deny",
    test_loopback,
    False,
    "CONNECT to 127.0.0.1 is refused.",
)
