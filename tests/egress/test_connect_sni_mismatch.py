"""connect-sni-mismatch: what the engine does when a tunnel to one
allowlisted host carries a ClientHello for another."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import connect_sni_mismatch, transport
from tests.egress import support


@support.requires_openssl
class ConnectSniMismatchTest(unittest.TestCase):
    def test_denied_when_the_engine_enforces_inside_the_tunnel(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = connect_sni_mismatch.test_sni_mismatch(client)
        self.assertEqual(outcome, "denied", detail)

    def test_allowed_when_the_engine_does_not_inspect_the_tunnel(self) -> None:
        _, port = support.start_mock(self, mode="lenient")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = connect_sni_mismatch.test_sni_mismatch(client)
        self.assertEqual(outcome, "allowed", detail)


if __name__ == "__main__":
    unittest.main()
