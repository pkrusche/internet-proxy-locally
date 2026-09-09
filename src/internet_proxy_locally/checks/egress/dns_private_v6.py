"""dns-private-ipv6: the same, for IPv6 (sslip.io)."""

from __future__ import annotations

from .models import Check, RawOutcome
from .probes import _connect_attempt
from .transport import ProxyClient


def test_dns_private_v6(client: ProxyClient) -> RawOutcome:
    # sslip.io: dashes become colons, so "0--1" => 0::1 (== ::1),
    # "fe80--1" => fe80::1. The bare "--1.sslip.io" spelling also resolves
    # to ::1 but is an invalid IDNA label (a label may not start with two
    # hyphens): Smokescreen rejects it as `invalid domain ... idna: invalid
    # label` and Pipelock as `no such host`, so neither engine ever reached
    # the SSRF check and the row scored a pass for the wrong reason
    # (measured 2026-08-19). "0--1" is the equivalent, valid spelling.
    targets = ("0--1.sslip.io:80", "fe80--1.sslip.io:80", "fd00--1.sslip.io:80")
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
    errors = [a.detail for a in attempts if a.outcome == "error"]
    if errors:
        return RawOutcome("error", "; ".join(errors), attempts=attempts)
    return RawOutcome(
        "pass",
        "allowlisted hostnames resolving to private/loopback IPv6 all "
        "denied; resolved IPs recorded per attempt",
        attempts=attempts,
    )


CHECK = Check(
    "dns-private-ipv6",
    "full",
    "deny",
    test_dns_private_v6,
    True,
    "The same, for IPv6 (sslip.io).",
)
