"""direct-ip-connect: a destination written as a bare address is refused."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import direct_ip_connect, transport
from tests.egress import support


@support.requires_openssl
class DirectIpConnectTest(unittest.TestCase):
    def test_passes_when_the_address_is_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = direct_ip_connect.test_direct_ip_connect(client)
        self.assertEqual(outcome, "pass", detail)

    def test_fails_when_the_address_is_wrongly_allowed(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: True
        )
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = direct_ip_connect.test_direct_ip_connect(client)
        self.assertEqual(outcome, "fail", detail)


if __name__ == "__main__":
    unittest.main()
