"""blocked-host-connect: CONNECT to a host that is not on the allowlist is
refused — the default-deny rule, on the tunnel path."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import blocked_host_connect, transport
from tests.egress import support


@support.requires_openssl
class BlockedHostConnectTest(unittest.TestCase):
    def test_passes_when_the_host_is_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = blocked_host_connect.test_blocked_host_connect(client)
        self.assertEqual(outcome, "pass", detail)

    def test_passes_when_the_denial_only_arrives_after_the_200(self) -> None:
        """A proxy that answers every CONNECT before it decides — Squid on
        an `ssl-bump` port — refuses by aborting the tunnel. Nothing is
        carried, so the row is a pass; grading the status line alone read
        an enforcing proxy as a hole (docs/tls-interception.md)."""
        _, port = support.start_mock(self, mode="bumping")
        client = transport.ProxyClient("127.0.0.1", port, tunnel_grace=0.3)
        outcome, detail = blocked_host_connect.test_blocked_host_connect(client)
        self.assertEqual(outcome, "pass", detail)
        self.assertIn("denied after CONNECT", detail)

    def test_fails_when_the_host_is_wrongly_allowed(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: True
        )
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = blocked_host_connect.test_blocked_host_connect(client)
        self.assertEqual(outcome, "fail", detail)


if __name__ == "__main__":
    unittest.main()
