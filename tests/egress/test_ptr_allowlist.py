"""ptr-allowlist: `checks/egress.py` guards a bypass the rest of the suite
cannot see: Squid retries a `dstdomain` miss as a reverse lookup, so an
address whose PTR names an allowlisted host is allowed through. Measured
before the fix (docs/findings.md), and `direct-ip-connect` passed
throughout — it uses an address with no PTR claim."""

from __future__ import annotations

import ipaddress
import unittest
from pathlib import Path

from internet_proxy_locally.checks.egress import fixture_log, ptr_allowlist, transport
from tests.egress import support


@support.requires_openssl
class PtrAllowlistTest(unittest.TestCase):
    def setUp(self) -> None:
        self._source = fixture_log.FIXTURE_LOG_SOURCE
        self.addCleanup(
            lambda: setattr(fixture_log, "FIXTURE_LOG_SOURCE", self._source)
        )
        self.asked = False
        fixture_log.FIXTURE_LOG_SOURCE = lambda: [
            "IPL-FIXTURE trap listening on 10.0.0.2:443"
        ]

    def client(self, allow: bool) -> transport.ProxyClient:
        def host_allowed(host: str) -> bool:
            self.asked = True
            return allow

        _, port = support.start_mock(self, mode="strict", host_allowed=host_allowed)
        return transport.ProxyClient("127.0.0.1", port)

    def test_fails_when_the_address_is_reachable(self) -> None:
        raw = ptr_allowlist.test_ptr_allowlist(self.client(allow=True))
        self.assertEqual(raw.outcome, "fail", raw.detail)
        self.assertIn(ptr_allowlist.PTR_FIXTURE_ADDRESS, raw.detail)
        self.assertIn("reverse record", raw.detail)

    def test_passes_when_denied(self) -> None:
        raw = ptr_allowlist.test_ptr_allowlist(self.client(allow=False))
        self.assertEqual(raw.outcome, "pass", raw.detail)

    def test_reports_whether_a_reverse_lookup_happened(self) -> None:
        """An engine that never reverse-resolves passes without the
        fallback having been offered. The detail must not imply otherwise."""
        raw = ptr_allowlist.test_ptr_allowlist(self.client(allow=False))
        self.assertIn("no reverse lookup", raw.detail)

        # The query line appears only once the probe has been made, as it
        # would in a live fixture — the check subtracts what was already
        # there so an earlier run's lookups are not counted as this one's.
        reversed_name = (
            ".".join(reversed(ptr_allowlist.PTR_FIXTURE_ADDRESS.split(".")))
            + ".in-addr.arpa"
        )
        self.asked = False
        fixture_log.FIXTURE_LOG_SOURCE = lambda: (
            ["IPL-FIXTURE trap listening on 10.0.0.2:443"]
            + (
                [f"dnsmasq: query[PTR] {reversed_name} from 192.168.64.1"]
                if self.asked
                else []
            )
        )
        raw = ptr_allowlist.test_ptr_allowlist(self.client(allow=False))
        self.assertIn("1 reverse lookup(s)", raw.detail)

    def test_a_previous_runs_lookup_is_not_counted(self) -> None:
        reversed_name = (
            ".".join(reversed(ptr_allowlist.PTR_FIXTURE_ADDRESS.split(".")))
            + ".in-addr.arpa"
        )
        fixture_log.FIXTURE_LOG_SOURCE = lambda: [
            "IPL-FIXTURE trap listening on 10.0.0.2:443",
            f"dnsmasq: query[PTR] {reversed_name} from 192.168.64.1",
        ]
        raw = ptr_allowlist.test_ptr_allowlist(self.client(allow=False))
        self.assertIn("no reverse lookup", raw.detail)

    def test_skips_without_an_observable_fixture(self) -> None:
        # Without the fixture the PTR claim is not live, and the address
        # would be denied for the ordinary reason — a pass proving nothing.
        fixture_log.FIXTURE_LOG_SOURCE = list
        raw = ptr_allowlist.test_ptr_allowlist(self.client(allow=False))
        self.assertEqual(raw.outcome, "skip", raw.detail)

    def test_the_fixture_address_is_public_and_unused_elsewhere(self) -> None:
        address = ipaddress.ip_address(ptr_allowlist.PTR_FIXTURE_ADDRESS)
        self.assertFalse(
            address.is_private or address.is_loopback or address.is_link_local,
            "a private address would trip the SSRF floors instead of the allowlist",
        )
        # It must not collide with an address another check connects to, or
        # the fixture's PTR claim would leak into that check's result.
        needle = f'"{ptr_allowlist.PTR_FIXTURE_ADDRESS}:'
        package_dir = Path(ptr_allowlist.__file__).parent
        for path in sorted(package_dir.glob("*.py")):
            if path.name == "ptr_allowlist.py":
                continue
            self.assertNotIn(
                needle,
                path.read_text(),
                f"{path.name} must not connect to the PTR fixture's own address",
            )


if __name__ == "__main__":
    unittest.main()
