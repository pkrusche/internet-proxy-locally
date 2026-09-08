"""connect-raw-tunnel: what the engine does when a tunnel to an allowlisted
host on 443 carries plaintext rather than TLS."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import connect_raw_tunnel, transport
from tests.egress import support


@support.requires_openssl
class ConnectRawTunnelTest(unittest.TestCase):
    def test_empty_close_is_inconclusive_without_origin_observation(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = connect_raw_tunnel.test_raw_tunnel(client)
        self.assertEqual(outcome, "error", detail)

    def test_allowed_when_the_engine_forwards_the_bytes(self) -> None:
        _, port = support.start_mock(self, mode="lenient")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = connect_raw_tunnel.test_raw_tunnel(client)
        self.assertEqual(outcome, "allowed", detail)


if __name__ == "__main__":
    unittest.main()
