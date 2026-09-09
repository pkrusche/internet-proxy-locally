"""connect-sni-mismatch: a tunnel to one allowlisted host carrying a
ClientHello for another is refused — the engine we ship enforces inside the
CONNECT tunnel."""

from __future__ import annotations

from .models import Check
from .transport import ProxyClient

ALLOWED_HTTPS_HOST = "pypi.org"  # must be on the allowlist
ALLOWED_ALT_HOST = "files.pythonhosted.org"  # allowlisted, used as mismatching SNI


def test_sni_mismatch(client: ProxyClient) -> tuple[str, str]:
    """CONNECT to one allowlisted host with the SNI of another.

    A handshake that fails inside an established tunnel is not on its own
    a policy verdict — the origin could be the one refusing. So the
    mismatch is measured against a control to the same host with a
    *matching* SNI, the way dns-mixed-answers grades against its own
    control probe. If the control completes and only the mismatch fails,
    the SNI is the sole difference and the refusal is the proxy's; if
    neither completes, nothing is attributable and the row stays an error
    rather than banking a pass.
    """
    ok, detail = client.tls_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", ALLOWED_ALT_HOST)
    if ok:
        return "allowed", f"mismatched SNI accepted: {detail}"
    if detail.startswith("CONNECT denied:"):
        return "denied", detail
    control_ok, control_detail = client.tls_in_tunnel(
        f"{ALLOWED_HTTPS_HOST}:443", ALLOWED_HTTPS_HOST
    )
    if not control_ok:
        return "error", (
            f"mismatched SNI refused ({detail}), but the matching-SNI control to "
            f"the same host did not complete either ({control_detail}) — so the "
            "failure is not attributable to policy"
        )
    return "denied", (
        f"mismatched SNI refused: {detail} — the matching-SNI control to the same "
        f"host completed ({control_detail}), so the refusal is the proxy's rather "
        "than the origin's"
    )


CHECK = Check(
    "connect-sni-mismatch",
    "full",
    "deny",
    test_sni_mismatch,
    False,
    "A tunnel to one allowlisted host carrying a ClientHello for "
    "another is refused — enforcement inside the CONNECT tunnel.",
)
