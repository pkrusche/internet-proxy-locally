"""dns-private-ipv4: an *allowlisted* name that resolves to a private IPv4
address is refused (nip.io)."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import dns_private_v4, transport
from tests.egress import support


@support.requires_openssl
class DnsPrivateV4Test(unittest.TestCase):
    def test_passes_when_every_target_is_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        raw = dns_private_v4.test_dns_private_v4(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertEqual(len(raw.attempts), 4)

    def test_records_a_denial_inside_tls_rather_than_established(self) -> None:
        """A CONNECT acknowledgment must not mask a later TLS denial."""
        _, port = support.start_mock(self, mode="bumping")
        client = transport.ProxyClient("127.0.0.1", port)
        raw = dns_private_v4.test_dns_private_v4(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertEqual({a.outcome for a in raw.attempts}, {"denied"})
        self.assertEqual({a.cause for a in raw.attempts}, {None})

    def test_fails_when_any_target_is_wrongly_allowed(self) -> None:
        support.assert_each_target_matters(
            self,
            dns_private_v4.test_dns_private_v4,
            (
                "10.0.0.1.nip.io:80",
                "192.168.1.1.nip.io:80",
                "127.0.0.1.nip.io:80",
                "169.254.169.254.nip.io:80",
            ),
        )


if __name__ == "__main__":
    unittest.main()
