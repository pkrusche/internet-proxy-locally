"""metadata-endpoint: the cloud metadata address is refused over both
CONNECT and plain HTTP."""

from __future__ import annotations

from .models import Check
from .probes import _classify_deny_connect, _classify_deny_http
from .transport import ProxyClient


def test_metadata(client: ProxyClient) -> tuple[str, str]:
    o1, d1 = _classify_deny_connect(client, "169.254.169.254:80")
    o2, d2 = _classify_deny_http(client, "http://169.254.169.254/latest/meta-data/")
    if "fail" in (o1, o2):
        return "fail", f"CONNECT: {d1}; GET: {d2}"
    if "error" in (o1, o2):
        return "error", f"CONNECT: {d1}; GET: {d2}"
    # Avoid "metadata": classification must use the engine's reason, not ours.
    return "pass", f"denied for CONNECT and GET (CONNECT: {d1}; GET: {d2})"


CHECK = Check(
    "metadata-endpoint",
    "quick",
    "deny",
    test_metadata,
    False,
    "The cloud metadata address is refused over both CONNECT and plain HTTP.",
)
