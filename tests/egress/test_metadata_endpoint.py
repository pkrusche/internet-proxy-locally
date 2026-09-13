"""metadata-endpoint: the cloud metadata address is refused over both
CONNECT and plain HTTP."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import metadata_endpoint, transport
from tests.egress import support


@support.requires_openssl
class MetadataEndpointTest(unittest.TestCase):
    def test_passes_when_denied_on_both_paths(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        client = transport.ProxyClient("127.0.0.1", port)
        result = metadata_endpoint.test_metadata(client)
        self.assertEqual(result.outcome, "pass", result.detail)
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual([a.n for a in result.attempts], [0, 1])
        self.assertEqual(result.attempts[0].target, "169.254.169.254:80")
        self.assertEqual(
            result.attempts[1].target, "http://169.254.169.254/latest/meta-data/"
        )

    def test_fails_when_wrongly_allowed(self) -> None:
        _, port = support.start_mock(
            self, mode="strict", host_allowed=lambda host: True
        )
        client = transport.ProxyClient("127.0.0.1", port)
        result = metadata_endpoint.test_metadata(client)
        self.assertEqual(result.outcome, "fail", result.detail)


if __name__ == "__main__":
    unittest.main()
