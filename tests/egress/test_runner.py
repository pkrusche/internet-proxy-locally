"""Suite-level integration tests: running many checks together and
verifying the runner's orchestration (grading, fixture detection,
log-window capture) — not any single check's behavior."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from internet_proxy_locally.checks import egress
from internet_proxy_locally.checks.egress import catalogue, runner, transport
from tests import mock_proxy
from tests.egress import support


@support.requires_openssl
class EgressSuiteTest(unittest.TestCase):
    def run_suite(self, engine: str, mode: str, full: bool) -> dict[str, egress.Result]:
        _, port = support.start_mock(self, mode=mode)
        results = egress.run_suite(f"http://127.0.0.1:{port}", engine, full=full)
        return {r.name: r for r in results}

    # -- catalogue integrity --------------------------------------------

    def test_tests_ordering_matches_the_original_19_checks(self) -> None:
        """A guardrail against a transcription slip in catalogue.py: this
        exact order is what report.py renders docs/findings.md's tables
        in."""
        self.assertEqual(
            [c.name for c in catalogue.TESTS],
            [
                "allowed-http",
                "allowed-https",
                "blocked-host-connect",
                "blocked-host-http",
                "direct-ip-connect",
                "loopback-ipv4",
                "rfc1918-ipv4",
                "link-local-ipv4",
                "metadata-endpoint",
                "loopback-ipv6",
                "private-ipv6",
                "dns-private-ipv4",
                "dns-private-ipv6",
                "dns-rebinding",
                "dns-mixed-answers",
                "ptr-allowlist",
                "connect-sni-mismatch",
                "connect-raw-tunnel",
                "concurrency-sanity",
            ],
        )

    # -- quick suite ------------------------------------------------------

    def test_quick_suite_strict(self) -> None:
        results = self.run_suite("pipelock", "strict", full=False)
        expected_pass = [
            "allowed-http",
            "allowed-https",
            "blocked-host-connect",
            "blocked-host-http",
            "direct-ip-connect",
            "loopback-ipv4",
            "rfc1918-ipv4",
            "link-local-ipv4",
            "metadata-endpoint",
            "loopback-ipv6",
            "private-ipv6",
        ]
        for name in expected_pass:
            self.assertEqual(
                results[name].outcome, "pass", f"{name}: {results[name].detail}"
            )

    def test_open_proxy_is_reported_as_failure(self) -> None:
        # A mock that allows everything must make the deny tests fail.
        _, port = support.start_mock(
            self, mode="lenient", allowed=set(), host_allowed=lambda host: True
        )
        results = {
            r.name: r
            for r in egress.run_suite(
                f"http://127.0.0.1:{port}", "pipelock", full=False
            )
        }
        self.assertEqual(results["blocked-host-connect"].outcome, "fail")
        self.assertEqual(results["loopback-ipv4"].outcome, "fail")

    def test_quick_suite_strict_squid(self) -> None:
        # The graded deny/allow floors are engine-independent; Squid must
        # pass the same eleven the other two do.
        results = self.run_suite("squid", "strict", full=False)
        for name, result in results.items():
            self.assertEqual(result.outcome, "pass", f"{name}: {result.detail}")

    # -- full suite: CONNECT abuse -----------------------------------------

    def test_full_suite_strict_grades_pass(self) -> None:
        # pipelock is just a representative engine name here — grading no
        # longer varies by engine, only by what the mock actually did.
        results = self.run_suite("pipelock", "strict", full=True)
        # A close alone cannot attribute policy without an origin trap.
        self.assertEqual(
            results["connect-sni-mismatch"].outcome,
            "error",
            results["connect-sni-mismatch"].detail,
        )
        self.assertEqual(
            results["connect-raw-tunnel"].outcome,
            "error",
            results["connect-raw-tunnel"].detail,
        )
        # Fixture-dependent tests skip: *.nip.io is not in the mock allowlist.
        self.assertEqual(results["dns-private-ipv4"].outcome, "skip")
        self.assertEqual(results["dns-rebinding"].outcome, "skip")
        self.assertEqual(results["concurrency-sanity"].outcome, "record")

    def test_full_suite_lenient_grades_fail_on_every_engine(self) -> None:
        """No per-engine grading override exists any more: every engine is
        judged against the same `deny` expectation, the config this repo
        ships (docs/findings.md §2)."""
        for engine in ("pipelock", "smokescreen", "squid"):
            with self.subTest(engine=engine):
                results = self.run_suite(engine, "lenient", full=True)
                self.assertEqual(
                    results["connect-sni-mismatch"].outcome,
                    "fail",
                    results["connect-sni-mismatch"].detail,
                )
                self.assertEqual(
                    results["connect-raw-tunnel"].outcome,
                    "fail",
                    results["connect-raw-tunnel"].detail,
                )

    # -- fixture detection --------------------------------------------------

    def test_fixture_detection_activates_with_test_policy(self) -> None:
        _, port = support.start_mock(
            self,
            mode="strict",
            allowed=set(mock_proxy.DEFAULT_ALLOWED) | {"1.1.1.1.nip.io"},
        )
        client = transport.ProxyClient("127.0.0.1", port)
        self.assertTrue(runner.fixtures_active(client))


class LogDeltaTest(unittest.TestCase):
    def test_returns_new_lines(self) -> None:
        self.assertEqual(
            runner._log_delta(["a", "b"], ["a", "b", "c", "d"]), ["c", "d"]
        )

    def test_empty_before(self) -> None:
        self.assertEqual(runner._log_delta([], ["x"]), ["x"])

    def test_falls_back_on_rotation(self) -> None:
        self.assertEqual(runner._log_delta(["a"], ["b", "c"]), ["b", "c"])


@support.requires_openssl
class LogCaptureTest(unittest.TestCase):
    """`--backend-bin`/`--container` end to end, via a tiny fake backend
    that returns a growing log on every `logs` call — no real container
    runtime available in this environment (docs/security.md)."""

    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="ipl-logcap-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        counter_file = tmp / "counter"
        script = tmp / "fakebackend.py"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            f"state = pathlib.Path({str(counter_file)!r})\n"
            "n = int(state.read_text()) if state.exists() else 0\n"
            "n += 1\n"
            "state.write_text(str(n))\n"
            "for i in range(1, n + 1):\n"
            "    print(f'log line {i}')\n"
        )
        script.chmod(0o755)
        self.backend_bin = str(script)

    def test_each_result_gets_a_distinct_log_window(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        results = egress.run_suite(
            f"http://127.0.0.1:{port}",
            "pipelock",
            full=False,
            backend_bin=self.backend_bin,
            container="fake",
        )
        self.assertTrue(results)
        for r in results:
            self.assertEqual(len(r.engine_logs), 1, f"{r.name}: {r.engine_logs}")
        lines = [r.engine_logs[0] for r in results]
        self.assertEqual(
            len(lines), len(set(lines)), "each test's window should be distinct"
        )

    def test_no_capture_without_backend_args(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        results = egress.run_suite(f"http://127.0.0.1:{port}", "pipelock", full=False)
        self.assertTrue(all(r.engine_logs == [] for r in results))


if __name__ == "__main__":
    unittest.main()
