"""Verify that an allowlisted PTR cannot authorize an IP-literal destination."""

from __future__ import annotations

from . import fixture_log
from .models import Check, RawOutcome
from .probes import _connect_attempt
from .transport import ProxyClient

# The reverse-DNS fixture: the local resolver answers PTR for this address
# with an allowlisted hostname. The address is public — so the SSRF floors
# stay out of it and the hostname allowlist really is the rule under test —
# and no other check connects to it.
PTR_FIXTURE_ADDRESS = "1.0.0.1"
PTR_FIXTURE_CLAIMS = "pypi.org"


def _ptr_queries(lines: list[str], address: str) -> int:
    """How many PTR lookups for `address` the fixture logged. dnsmasq's
    `--log-queries` writes `query[PTR] <reversed>.in-addr.arpa from ...`."""
    reversed_name = ".".join(reversed(address.split("."))) + ".in-addr.arpa"
    return sum(1 for line in lines if "query[PTR]" in line and reversed_name in line)


def test_ptr_allowlist(client: ProxyClient) -> RawOutcome:
    fixture_lines = fixture_log.FIXTURE_LOG_SOURCE()
    if not any("IPL-FIXTURE" in line for line in fixture_lines):
        return RawOutcome(
            "skip",
            (
                "the local DNS fixture is not observable from here, so the PTR claim "
                f"for {PTR_FIXTURE_ADDRESS} cannot be known to be live. Run "
                "`ipl-lab up` and `ipl-lab check`, which wires "
                "the fixture's container through automatically"
            ),
        )

    target = f"{PTR_FIXTURE_ADDRESS}:443"
    attempt = _connect_attempt(client, 0, target, PTR_FIXTURE_ADDRESS, resolve=False)
    asked = _ptr_queries(
        fixture_log.FIXTURE_LOG_SOURCE(), PTR_FIXTURE_ADDRESS
    ) - _ptr_queries(fixture_lines, PTR_FIXTURE_ADDRESS)

    if attempt.outcome == "established":
        return RawOutcome(
            "fail",
            (
                f"{target} was reached even though only {PTR_FIXTURE_CLAIMS} is "
                f"allowlisted — the address inherited an allowlisted name from its "
                f"reverse record"
            ),
            attempts=[attempt],
        )

    detail = f"denied: {attempt.detail}"
    detail += (
        f"; the engine made {asked} reverse lookup(s) for it and refused anyway"
        if asked
        else "; the engine performed no reverse lookup, so the allowlist was never "
        "offered the PTR name"
    )
    return RawOutcome("pass", detail, attempts=[attempt])


CHECK = Check(
    "ptr-allowlist",
    "full",
    "deny",
    test_ptr_allowlist,
    True,
    "An address whose PTR record claims an allowlisted hostname is "
    "still refused, so a reverse lookup cannot satisfy the allowlist.",
)
