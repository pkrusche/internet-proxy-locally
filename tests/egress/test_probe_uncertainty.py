"""Inconclusive CONNECT attempts must never silently become policy passes."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from internet_proxy_locally.checks.egress import (
    dns_mixed,
    dns_private_v4,
    dns_private_v6,
    metadata_endpoint,
    probes,
    ptr_allowlist,
    transport,
)
from internet_proxy_locally.checks.egress.models import Attempt


class ProbeUncertaintyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = transport.ProxyClient("127.0.0.1", 1)
        self.error = Attempt(0, "fixture.test:443", [], "error", 200, 1, "TLS failed")

    def test_private_address_checks_preserve_errors(self) -> None:
        for module, fn in (
            (dns_private_v4, dns_private_v4.test_dns_private_v4),
            (dns_private_v6, dns_private_v6.test_dns_private_v6),
        ):
            with (
                self.subTest(module=module.__name__),
                patch.object(module, "_connect_attempt", return_value=self.error),
            ):
                self.assertEqual(fn(self.client).outcome, "error")

    def test_mixed_answer_errors_after_successful_control(self) -> None:
        control = Attempt(0, "control:443", [], "established", 200, 1, "HTTP 200")
        with patch.object(
            dns_mixed, "_connect_attempt", side_effect=[control, self.error, self.error]
        ):
            self.assertEqual(dns_mixed.test_dns_mixed(self.client).outcome, "error")

    def test_mixed_private_trap_hit_is_not_hidden_by_tls_errors(self) -> None:
        control = Attempt(0, "control:443", [], "established", 200, 1, "HTTP 200")
        previous = ["IPL-FIXTURE trap connect from=172.17.0.3:1234"]
        for new_hits in ([], ["IPL-FIXTURE trap connect from=172.17.0.3:5678"]):
            with (
                self.subTest(new_hits=new_hits),
                patch.object(
                    dns_mixed,
                    "_connect_attempt",
                    side_effect=[control, self.error, self.error],
                ),
                patch.object(
                    dns_mixed.fixture_log,
                    "FIXTURE_LOG_SOURCE",
                    side_effect=[previous, previous + new_hits],
                ),
            ):
                raw = dns_mixed.test_dns_mixed(self.client)
                self.assertEqual(raw.outcome, "allowed" if new_hits else "error")

    def test_ptr_error_is_not_a_denial(self) -> None:
        with (
            patch.object(ptr_allowlist, "_connect_attempt", return_value=self.error),
            patch.object(
                ptr_allowlist.fixture_log,
                "FIXTURE_LOG_SOURCE",
                return_value=["IPL-FIXTURE trap listening"],
            ),
        ):
            self.assertEqual(
                ptr_allowlist.test_ptr_allowlist(self.client).outcome, "error"
            )

    def test_metadata_requires_both_probes_to_be_conclusive(self) -> None:
        with (
            patch.object(
                metadata_endpoint,
                "_classify_deny_connect",
                return_value=("error", "TLS failed"),
            ),
            patch.object(
                metadata_endpoint, "_classify_deny_http", return_value=("pass", "403")
            ),
        ):
            self.assertEqual(metadata_endpoint.test_metadata(self.client)[0], "error")

    def test_one_demonstrated_bypass_is_not_hidden_by_an_error(self) -> None:
        with patch.object(
            probes,
            "_classify_deny_connect",
            side_effect=[("error", "timeout"), ("fail", "HTTP 200")],
        ):
            self.assertEqual(probes._deny_all(self.client, "a:443", "b:443")[0], "fail")

    def test_connect_gateway_error_is_not_a_denial(self) -> None:
        with patch.object(
            self.client, "connect", return_value=(None, 502, "Bad Gateway")
        ):
            self.assertEqual(
                probes._classify_deny_connect(self.client, "a:443")[0], "error"
            )
            self.assertEqual(
                probes._connect_attempt(
                    self.client, 0, "a:443", "a", resolve=False
                ).outcome,
                "error",
            )
