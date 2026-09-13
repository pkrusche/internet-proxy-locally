"""Ordinary HTTP errors are not evidence of an enforced proxy policy."""

from __future__ import annotations

import unittest
from unittest.mock import Mock

from internet_proxy_locally.checks.egress.probes import _classify_deny_http
from internet_proxy_locally.checks.egress.transport import HttpResponse


class HttpDenialTest(unittest.TestCase):
    def classify(self, status, body="", headers=None):
        client = Mock()
        client.http_get.return_value = HttpResponse(
            status, headers or {}, body, f"HTTP/1.1 {status}"
        )
        return _classify_deny_http(client, "http://example.com/")[0]

    def test_generic_errors_authentication_and_gateway_failures_are_inconclusive(self):
        for status in (None, 100, 400, 401, 403, 407, 429, 500, 502, 503):
            with self.subTest(status=status):
                self.assertEqual(
                    self.classify(status, "Forbidden: private address"), "error"
                )
        for status in (200, 204, 301):
            self.assertEqual(self.classify(status), "fail")

    def test_explicit_engine_denials_are_recognized(self):
        self.assertEqual(
            self.classify(403, "blocked: domain not in allowlist: example.com\n"),
            "pass",
        )
        self.assertEqual(
            self.classify(
                403,
                "<html>403 Forbidden internet-proxy-locally denied this request: not allowlisted</html>",
            ),
            "pass",
        )
        self.assertEqual(
            self.classify(403, headers={"x-Squid-Error": "ERR_ACCESS_DENIED 0"}), "pass"
        )
        self.assertEqual(
            self.classify(
                407,
                headers={
                    "X-Smokescreen-Error": "Egress proxying is denied to host 'example.com:80': default rule policy used."
                },
            ),
            "pass",
        )

    def test_wrong_status_target_or_reason_does_not_supply_evidence(self):
        for status in (500, 502, 503):
            self.assertEqual(
                self.classify(
                    status,
                    "internet-proxy-locally denied this request: not allowlisted",
                    {"X-Squid-Error": "ERR_ACCESS_DENIED 0"},
                ),
                "error",
            )
        self.assertEqual(
            self.classify(403, "blocked: domain not in allowlist: other.test"), "error"
        )
        for reason in (
            "Proxy authentication required",
            "Egress proxying is denied to host 'other.test': default rule policy used.",
        ):
            self.assertEqual(
                self.classify(407, headers={"X-Smokescreen-Error": reason}), "error"
            )
        self.assertEqual(
            self.classify(403, headers={"X-Squid-Error": "ERR_DNS_FAIL 0"}), "error"
        )
