"""dns-private-ipv6: the same, for IPv6 (sslip.io)."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import dns_private_v6, transport
from tests.egress import support


@support.requires_openssl
class DnsPrivateV6Test(unittest.TestCase):
    def test_passes_when_every_target_is_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        raw = dns_private_v6.test_dns_private_v6(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertEqual(len(raw.attempts), 3)

    def test_fails_when_any_target_is_wrongly_allowed(self) -> None:
        support.assert_each_target_matters(
            self,
            dns_private_v6.test_dns_private_v6,
            ("0--1.sslip.io:80", "fe80--1.sslip.io:80", "fd00--1.sslip.io:80"),
        )


if __name__ == "__main__":
    unittest.main()
