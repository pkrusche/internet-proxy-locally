"""connect-sni-mismatch: what the engine does when a tunnel to one
allowlisted host carries a ClientHello for another."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import connect_sni_mismatch, denial, transport
from tests.egress import support


@support.requires_openssl
class ConnectSniMismatchTest(unittest.TestCase):
    def test_denied_when_the_engine_enforces_inside_the_tunnel(self) -> None:
        """The matching-SNI control completes against the same host, so the
        mismatch failing is the proxy's doing and not the origin's."""
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = connect_sni_mismatch.test_sni_mismatch(client)
        self.assertEqual(outcome, "denied", detail)
        self.assertEqual(denial.classify_denial(detail), "sni-mismatch")

    def test_error_when_the_control_probe_fails_too(self) -> None:
        """Without a working control the handshake failure is unattributable
        — an origin that refuses everything must not bank a pass."""
        server, port = support.start_mock(self, mode="strict")
        server.tls_ctx = None  # no cert: every handshake in a tunnel closes
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = connect_sni_mismatch.test_sni_mismatch(client)
        self.assertEqual(outcome, "error", detail)

    def test_allowed_when_the_engine_does_not_inspect_the_tunnel(self) -> None:
        _, port = support.start_mock(self, mode="lenient")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = connect_sni_mismatch.test_sni_mismatch(client)
        self.assertEqual(outcome, "allowed", detail)


if __name__ == "__main__":
    unittest.main()
