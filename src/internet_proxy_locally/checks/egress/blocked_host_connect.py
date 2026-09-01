"""blocked-host-connect: CONNECT to a host that is not on the allowlist is
refused — the default-deny rule, on the tunnel path."""

from __future__ import annotations

from .models import Check
from .probes import _classify_deny_connect
from .targets import BLOCKED_HOST
from .transport import ProxyClient


def test_blocked_host_connect(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, f"{BLOCKED_HOST}:443")


CHECK = Check(
    "blocked-host-connect",
    "quick",
    "deny",
    test_blocked_host_connect,
    False,
    "CONNECT to a host that is not on the allowlist is refused "
    "— the default-deny rule, on the tunnel path.",
)
