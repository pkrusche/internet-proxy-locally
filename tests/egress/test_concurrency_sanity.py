"""concurrency-sanity: ten simultaneous CONNECTs to an allowed host all
succeed — the proxy is not serializing or dropping under trivial load."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import concurrency_sanity, transport
from tests.egress import support


@support.requires_openssl
class ConcurrencySanityTest(unittest.TestCase):
    def test_always_records_and_counts_established_connects(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = concurrency_sanity.test_concurrency(client)
        self.assertEqual(outcome, "record")
        self.assertIn("10 established, 0 denied/failed", detail)

    def test_counts_denials_when_the_host_is_blocked(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: False
        )
        client = transport.ProxyClient("127.0.0.1", port)
        outcome, detail = concurrency_sanity.test_concurrency(client)
        self.assertEqual(outcome, "record")
        self.assertIn("0 established, 10 denied/failed", detail)


if __name__ == "__main__":
    unittest.main()
