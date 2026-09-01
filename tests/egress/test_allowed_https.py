"""allowed-https: a CONNECT tunnel to an allowlisted host completes a real
TLS handshake."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import allowed_https, transport
from tests.egress import support


@support.requires_openssl
class AllowedHttpsTest(unittest.TestCase):
    def test_passes_when_the_handshake_completes(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = allowed_https.test_allowed_https(client)
        self.assertEqual(outcome, "pass", detail)
        self.assertIn("handshake OK", detail)

    def test_fails_when_the_tunnel_is_denied(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: False
        )
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = allowed_https.test_allowed_https(client)
        self.assertEqual(outcome, "fail", detail)


if __name__ == "__main__":
    unittest.main()
