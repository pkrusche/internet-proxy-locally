"""blocked-host-http: a plain-HTTP GET to a host that is not on the
allowlist is refused — the same rule on the request path."""

from __future__ import annotations

from .models import Check
from .probes import _classify_deny_http
from .targets import BLOCKED_HOST
from .transport import ProxyClient


def test_blocked_host_http(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_http(client, f"http://{BLOCKED_HOST}/")


CHECK = Check(
    "blocked-host-http",
    "quick",
    "deny",
    test_blocked_host_http,
    False,
    "A plain-HTTP GET to a host that is not on the allowlist is "
    "refused — the same rule on the request path.",
)
