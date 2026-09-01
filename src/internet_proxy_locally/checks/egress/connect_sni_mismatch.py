"""connect-sni-mismatch: what the engine does when a tunnel to one
allowlisted host carries a ClientHello for another: enforcement inside the
tunnel, or none."""

from __future__ import annotations

from .models import Check
from .targets import ALLOWED_HTTPS_HOST
from .transport import ProxyClient

ALLOWED_ALT_HOST = "files.pythonhosted.org"  # allowlisted, used as mismatching SNI


def test_sni_mismatch(client: ProxyClient) -> tuple[str, str]:
    """CONNECT to one allowlisted host with the SNI of another."""
    ok, detail = client.tls_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", ALLOWED_ALT_HOST)
    if ok:
        return "allowed", f"mismatched SNI accepted: {detail}"
    return "denied", detail


CHECK = Check(
    "connect-sni-mismatch",
    "full",
    "record",
    test_sni_mismatch,
    False,
    "What the engine does when a tunnel to one allowlisted host "
    "carries a ClientHello for another: enforcement inside the "
    "tunnel, or none.",
)
