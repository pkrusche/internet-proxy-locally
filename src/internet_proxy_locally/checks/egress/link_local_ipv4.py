"""link-local-ipv4: CONNECT to 169.254.0.0/16 is refused."""

from __future__ import annotations

from .models import Check
from .probes import _classify_deny_connect
from .transport import ProxyClient


def test_link_local(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "169.254.1.1:80")


CHECK = Check(
    "link-local-ipv4",
    "quick",
    "deny",
    test_link_local,
    False,
    "CONNECT to 169.254.0.0/16 is refused.",
)
