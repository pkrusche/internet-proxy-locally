"""Squid deny_info pages are served inside TLS without X-Squid-Error."""

from __future__ import annotations

import unittest
from pathlib import Path

from internet_proxy_locally.checks.egress import denial, probes, transport
from tests.egress import support


@support.requires_openssl
class SquidErrorPageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server, port = support.start_mock(
            self, mode="bumping", host_allowed=lambda host: True
        )
        self.client = transport.ProxyClient("127.0.0.1", port, timeout=1)

    def response(
        self, body: bytes, status: str = "403 Forbidden", extra: str = ""
    ) -> None:
        self.server.tunnel_response = (
            f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra}\r\n".encode()
            + body
        )

    def test_all_shipped_pages_are_denials_with_the_stated_cause(self) -> None:
        pages = Path(transport.__file__).parents[2] / "data/images/squid/errors"
        for name, cause in (
            ("ERR_IPL_NOT_ALLOWLISTED", "hostname-not-allowlisted"),
            ("ERR_IPL_IP_LITERAL", "ip-literal-destination"),
            ("ERR_IPL_PRIVATE_IP", "private-ip"),
            ("ERR_IPL_METADATA", "metadata"),
            ("ERR_IPL_PORT_NOT_ALLOWED", "port-not-allowed"),
        ):
            with self.subTest(page=name):
                self.response((pages / name).read_bytes())
                outcome, detail = probes._classify_deny_connect(
                    self.client, "example.com:443"
                )
                self.assertEqual(outcome, "pass", detail)
                self.assertEqual(denial.classify_denial(detail), cause)
                attempt = probes._connect_attempt(
                    self.client, 0, "example.com:443", "example.com", resolve=False
                )
                self.assertEqual(attempt.outcome, "denied", attempt.detail)
                self.assertEqual(denial.classify_denial(attempt.detail), cause)

    def test_generic_origin_403_is_still_inconclusive(self) -> None:
        self.response(
            b"<html><title>403 Forbidden</title><p>Access to private IP denied</p></html>"
        )
        outcome, detail = probes._classify_deny_connect(self.client, "example.com:443")
        self.assertEqual(outcome, "error", detail)
        self.assertIn("Access to private IP denied", detail)

    def test_service_unavailable_keeps_diagnostics_without_passing(self) -> None:
        self.response(
            b"<html><p>The requested URL could not be retrieved</p><p>SSL connection failed</p></html>",
            "503 Service Unavailable",
            "X-Squid-Error: ERR_SECURE_CONNECT_FAIL 0\r\n",
        )
        outcome, detail = probes._classify_deny_connect(self.client, "example.com:443")
        self.assertEqual(outcome, "error", detail)
        self.assertIn("503 Service Unavailable", detail)
        self.assertIn("SSL connection failed", detail)
        self.assertIn("ERR_SECURE_CONNECT_FAIL", detail)

    def test_project_marker_on_a_503_is_not_a_denial(self) -> None:
        self.response(
            b"internet-proxy-locally denied this request: test",
            "503 Service Unavailable",
        )
        self.assertEqual(
            probes._classify_deny_connect(self.client, "example.com:443")[0], "error"
        )
