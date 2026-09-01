"""link-local-ipv4: CONNECT to 169.254.0.0/16 is refused."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import link_local_ipv4, transport
from tests.egress import support


@support.requires_openssl
class LinkLocalIpv4Test(unittest.TestCase):
    def test_passes_when_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = link_local_ipv4.test_link_local(client)
        self.assertEqual(outcome, "pass", detail)

    def test_fails_when_wrongly_allowed(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: True
        )
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = link_local_ipv4.test_link_local(client)
        self.assertEqual(outcome, "fail", detail)


if __name__ == "__main__":
    unittest.main()
