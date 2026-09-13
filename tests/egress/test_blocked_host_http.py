"""blocked-host-http: a plain-HTTP GET to a host that is not on the
allowlist is refused — the same rule on the request path."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import blocked_host_http, transport
from tests.egress import support


@support.requires_openssl
class BlockedHostHttpTest(unittest.TestCase):
    def test_passes_when_the_host_is_denied(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        result = blocked_host_http.test_blocked_host_http(client)
        self.assertEqual(result.outcome, "pass", result.detail)

    def test_fails_when_the_host_is_wrongly_allowed(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: True
        )
        client = transport.ProxyClient("127.0.0.1", port)
        result = blocked_host_http.test_blocked_host_http(client)
        self.assertEqual(result.outcome, "fail", result.detail)


if __name__ == "__main__":
    unittest.main()
