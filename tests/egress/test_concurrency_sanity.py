"""concurrency-sanity: ten simultaneous CONNECTs to an allowed host all
succeed — the proxy is not serializing or dropping under trivial load."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from internet_proxy_locally.checks.egress import concurrency_sanity, transport
from tests.egress import support


@support.requires_openssl
class ConcurrencySanityTest(unittest.TestCase):
    def test_one_failed_connect_fails_the_check(self) -> None:
        client = transport.ProxyClient("127.0.0.1", 1)
        sock = Mock()
        with patch.object(
            client,
            "connect",
            side_effect=[(sock, 200, "OK")] * 9 + [(None, 403, "Denied")],
        ):
            outcome, detail = concurrency_sanity.test_concurrency(client)
        self.assertEqual(outcome, "fail")
        self.assertIn("9 established, 1 denied/failed", detail)
        self.assertEqual(sock.close.call_count, 9)
        self.assertEqual(concurrency_sanity.CHECK.expectation, "allow")

    def test_passes_when_all_connects_establish(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = concurrency_sanity.test_concurrency(client)
        self.assertEqual(outcome, "pass")
        self.assertIn("10 established, 0 denied/failed", detail)

    def test_counts_denials_when_the_host_is_blocked(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: False
        )
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = concurrency_sanity.test_concurrency(client)
        self.assertEqual(outcome, "fail")
        self.assertIn("0 established, 10 denied/failed", detail)


if __name__ == "__main__":
    unittest.main()
