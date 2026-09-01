"""direct-ip-connect: a destination written as a bare address is refused.

Under a hostname allowlist it can only ever be denied; which rule denies
it is what the cause column shows.
"""

from __future__ import annotations

from .models import Check
from .probes import _classify_deny_connect
from .transport import ProxyClient


def test_direct_ip_connect(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "1.1.1.1:443")


CHECK = Check(
    "direct-ip-connect",
    "quick",
    "deny",
    test_direct_ip_connect,
    False,
    "A destination written as a bare address is refused. Under a "
    "hostname allowlist it can only ever be denied; which rule "
    "denies it is what the cause column shows.",
)
