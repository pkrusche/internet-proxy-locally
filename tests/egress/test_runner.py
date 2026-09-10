"""Suite-level integration tests: running many checks together and
verifying the runner's orchestration (grading, fixture detection,
log-window capture) — not any single check's behavior."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from internet_proxy_locally.backend import Backend
from internet_proxy_locally.checks import egress
from internet_proxy_locally.checks.egress import catalogue, runner, transport
from internet_proxy_locally.constants import ENGINES
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

    def test_quick_suite_grades_a_late_denying_proxy_the_same_as_a_prompt_one(
        self,
    ) -> None:
        """The regression that made 13 of Squid's rows fail at once.

        A CONNECT acknowledgment and a successful local TLS handshake must
        not hide an explicit denial sent inside the TLS session.
        """
        prompt = self.run_suite("pipelock", "strict", full=False)
        late = self.run_suite("squid", "bumping", full=False)
        self.assertEqual(
            {name: r.outcome for name, r in late.items()},
            {name: r.outcome for name, r in prompt.items()},
        )
        # The intercepted denial states access denied, without a specific reason.
        self.assertEqual(late["blocked-host-connect"].cause, "proxy-access-denied")
        self.assertEqual(
            prompt["blocked-host-connect"].cause, "hostname-not-allowlisted"
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
        # Both rows ask whether the illegitimate exchange happened, not
        # what status came back: the mismatched handshake never completed
        # (and the matching-SNI control did, which attributes it), and the
        # plaintext request drew no response at all.
        self.assertEqual(
            results["connect-sni-mismatch"].outcome,
            "pass",
            results["connect-sni-mismatch"].detail,
        )
        self.assertEqual(
            results["connect-raw-tunnel"].outcome,
            "pass",
            results["connect-raw-tunnel"].detail,
        )
        # Fixture-dependent tests skip: *.nip.io is not in the mock allowlist.
        self.assertEqual(results["dns-private-ipv4"].outcome, "skip")
        self.assertEqual(results["dns-rebinding"].outcome, "skip")
        self.assertEqual(results["concurrency-sanity"].outcome, "pass")

    def test_full_suite_lenient_grades_fail_on_every_engine(self) -> None:
        """No per-engine grading override exists any more: every engine is
        judged against the same `deny` expectation, the config this repo
        ships (docs/findings.md §2)."""
        for engine in ENGINES:
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


class LogFetchTest(unittest.TestCase):
    def test_backend_log_flags_and_fixture_history(self) -> None:
        for binary, flags in [
            ("/usr/local/bin/container", ["-n", "200"]),
            ("docker", ["--tail", "200", "--timestamps"]),
        ]:
            with (
                self.subTest(binary=binary),
                patch(
                    "subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, "log\n", ""),
                ) as run,
            ):
                self.assertEqual(runner._fetch_logs(binary, "engine"), ["log"])
                self.assertEqual(
                    run.call_args.args[0], [binary, "logs", *flags, "engine"]
                )
                runner._fetch_logs(binary, "fixture", required=True)
                expected = [] if binary.endswith("container") else ["--timestamps"]
                self.assertEqual(
                    run.call_args.args[0], [binary, "logs", *expected, "fixture"]
                )

    def test_failed_fixture_fetch_is_an_error_not_a_transcript(self) -> None:
        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 1, "", "Unknown option '--timestamps'"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "cannot read fixture logs.*Unknown option"
            ):
                runner._fetch_logs("container", "fixture", required=True)
            self.assertEqual(runner._fetch_logs("container", "engine"), [])

    def test_fixture_fetch_timeout_is_explicit(self) -> None:
        with (
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("logs", 5)),
            self.assertRaisesRegex(RuntimeError, "cannot read fixture logs"),
        ):
            runner._fetch_logs("container", "fixture", required=True)

    def test_backend_tail_uses_apple_flags(self) -> None:
        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "one\ntwo\n", ""),
        ) as run:
            self.assertEqual(Backend("container").tail_logs("fixture", 1), "two")
            self.assertEqual(
                run.call_args.args[0], ["container", "logs", "-n", "1", "fixture"]
            )


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
