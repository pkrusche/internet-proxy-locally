"""dns-mixed-answers: pass/fail/skip grading. Every engine is graded
against the same `deny` expectation — the config this repo ships."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from internet_proxy_locally.checks import egress
from internet_proxy_locally.checks.egress import dns_mixed, runner, transport
from internet_proxy_locally.constants import ENGINES
from tests import mock_proxy
from tests.egress import support


@support.requires_openssl
class DnsMixedTest(unittest.TestCase):
    def _mixed_fixture_server(self, allowed_names: set[str]) -> int:
        """A mock allowing exactly `allowed_names` on top of the nip.io probe
        that gates the fixture-dependent tests.

        The mock decides by hostname, so it can stand in for an engine's
        *verdict* on the mixed names but not for the resolution behind it —
        which is fine: this exercises the check's own grading, and the real
        resolution behavior is measured in docs/findings.md.
        """
        allowed = set(mock_proxy.DEFAULT_ALLOWED) | {"1.1.1.1.nip.io"} | allowed_names
        _, port = support.start_mock(self, mode="strict", allowed=allowed)
        return port

    def test_mixed_answers_denies_when_only_the_control_is_reachable(self) -> None:
        port = self._mixed_fixture_server({dns_mixed.MIXED_FIXTURE_CONTROL})
        client = transport.ProxyClient("127.0.0.1", port)
        raw = dns_mixed.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "denied", raw.detail)
        self.assertEqual(len(raw.attempts), 1 + len(dns_mixed.MIXED_FIXTURE_TARGETS))

    def test_mixed_answers_reports_allowed_when_a_mixed_name_is_reachable(self) -> None:
        port = self._mixed_fixture_server(
            {dns_mixed.MIXED_FIXTURE_CONTROL, *dns_mixed.MIXED_FIXTURE_TARGETS}
        )
        client = transport.ProxyClient("127.0.0.1", port)
        raw = dns_mixed.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "allowed", raw.detail)
        for name in dns_mixed.MIXED_FIXTURE_TARGETS:
            self.assertIn(name, raw.detail)

    def test_allowed_mixed_answers_fail_without_an_invented_cause(self) -> None:
        """Grading no longer varies by engine: every engine is judged
        against the same `deny` expectation, so a connection that establishes
        fails the row regardless of which engine made it."""
        port = self._mixed_fixture_server(
            {dns_mixed.MIXED_FIXTURE_CONTROL, *dns_mixed.MIXED_FIXTURE_TARGETS}
        )
        with patch.object(runner, "TESTS", [dns_mixed.CHECK]):
            for engine in ENGINES:
                with self.subTest(engine=engine):
                    [row] = egress.run_suite(
                        f"http://127.0.0.1:{port}", engine, full=True
                    )
                    self.assertEqual(row.outcome, "fail", row.detail)
                    self.assertIn("established", row.detail)
                    self.assertIsNone(
                        row.cause, "nothing was denied, so there is no cause"
                    )

    def test_mixed_answers_skips_without_a_working_control(self) -> None:
        # No control means a denial below cannot be attributed to
        # mixed-answer handling, so the row must not bank a pass.
        port = self._mixed_fixture_server(set())
        client = transport.ProxyClient("127.0.0.1", port)
        raw = dns_mixed.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "skip", raw.detail)
        self.assertIn("control probe", raw.detail)
        self.assertEqual(len(raw.attempts), 1)


if __name__ == "__main__":
    unittest.main()
