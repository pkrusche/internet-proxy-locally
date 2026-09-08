"""connect-sni-mismatch: a tunnel to one allowlisted host carrying a
ClientHello for another is refused — the engine we ship enforces inside the
CONNECT tunnel."""

from __future__ import annotations

from .models import Check
from .transport import ProxyClient

ALLOWED_HTTPS_HOST = "pypi.org"  # must be on the allowlist
ALLOWED_ALT_HOST = "files.pythonhosted.org"  # allowlisted, used as mismatching SNI


def test_sni_mismatch(client: ProxyClient) -> tuple[str, str]:
    """CONNECT to one allowlisted host with the SNI of another."""
    ok, detail = client.tls_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", ALLOWED_ALT_HOST)
    if ok:
        return "allowed", f"mismatched SNI accepted: {detail}"
    if detail.startswith("CONNECT denied:"):
        return "denied", detail
    return "error", f"origin/TLS failure is not an attributable policy denial: {detail}"


CHECK = Check(
    "connect-sni-mismatch",
    "full",
    "deny",
    test_sni_mismatch,
    False,
    "A tunnel to one allowlisted host carrying a ClientHello for "
    "another is refused — enforcement inside the CONNECT tunnel.",
)
