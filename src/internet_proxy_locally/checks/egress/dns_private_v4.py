"""dns-private-ipv4: an *allowlisted* name that resolves to a private IPv4
address is refused, so the denial can only have come from validating the
resolved address (nip.io)."""

from __future__ import annotations

from .models import Check, RawOutcome
from .probes import _connect_attempt
from .transport import ProxyClient


def test_dns_private_v4(client: ProxyClient) -> RawOutcome:
    targets = (
        "10.0.0.1.nip.io:80",
        "192.168.1.1.nip.io:80",
        "127.0.0.1.nip.io:80",
        "169.254.169.254.nip.io:80",
    )
    attempts = [
        _connect_attempt(client, i, t, t.rsplit(":", 1)[0])
        for i, t in enumerate(targets)
    ]
    bad = [a for a in attempts if a.outcome == "established"]
    if bad:
        detail = "; ".join(
            f"{a.target} established (resolved {a.local_resolved})" for a in bad
        )
        return RawOutcome("fail", detail, attempts=attempts)
    return RawOutcome(
        "pass",
        "allowlisted hostnames resolving to private/loopback/metadata IPv4 "
        "all denied; resolved IPs recorded per attempt",
        attempts=attempts,
    )


CHECK = Check(
    "dns-private-ipv4",
    "full",
    "deny",
    test_dns_private_v4,
    True,
    "An *allowlisted* name that resolves to a private IPv4 address "
    "is refused, so the denial can only have come from validating "
    "the resolved address (nip.io).",
)
