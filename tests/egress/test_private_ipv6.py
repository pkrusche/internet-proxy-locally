"""private-ipv6: CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is
refused."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import private_ipv6, transport
from tests.egress import support


@support.requires_openssl
class PrivateIpv6Test(unittest.TestCase):
    def test_passes_when_both_addresses_are_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = private_ipv6.test_ipv6_private(client)
        self.assertEqual(outcome, "pass", detail)

    def test_fails_when_wrongly_allowed(self) -> None:
        support.assert_each_target_matters(
            self,
            private_ipv6.test_ipv6_private,
            ("[fd00::1]:80", "[fe80::1]:80"),
        )


if __name__ == "__main__":
    unittest.main()
