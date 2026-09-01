"""rfc1918-ipv4: CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is
refused."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import rfc1918_ipv4, transport
from tests.egress import support


@support.requires_openssl
class Rfc1918Ipv4Test(unittest.TestCase):
    def test_passes_when_every_range_is_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = rfc1918_ipv4.test_rfc1918(client)
        self.assertEqual(outcome, "pass", detail)

    def test_fails_when_any_range_is_wrongly_allowed(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: True
        )
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = rfc1918_ipv4.test_rfc1918(client)
        self.assertEqual(outcome, "fail", detail)


if __name__ == "__main__":
    unittest.main()
