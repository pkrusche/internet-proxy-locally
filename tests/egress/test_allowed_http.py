"""allowed-http: a plain-HTTP GET to an allowlisted host reaches it."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import allowed_http, transport
from tests.egress import support


@support.requires_openssl
class AllowedHttpTest(unittest.TestCase):
    def test_passes_when_the_host_is_allowed(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        raw = allowed_http.test_allowed_http(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertIn(allowed_http.ALLOWED_HTTP_HOST, raw.detail)

    def test_fails_when_the_host_is_denied(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: False
        )
        client = transport.ProxyClient("127.0.0.1", port)
        raw = allowed_http.test_allowed_http(client)
        self.assertEqual(raw.outcome, "fail", raw.detail)


if __name__ == "__main__":
    unittest.main()
