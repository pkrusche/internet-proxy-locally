"""Tests for checks/egress.py against the policy-enforcing mock proxy.

No network egress: the mock proxy answers everything locally, terminating
TLS with a throwaway self-signed certificate generated at setup time.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

import sys
sys.path.insert(0, str(REPO_ROOT / "tests"))
import mock_proxy  # noqa: E402


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


egress = load_module("egress", REPO_ROOT / "checks" / "egress.py")

OPENSSL = shutil.which("openssl")


def free_port() -> int:
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(OPENSSL, "openssl needed to generate the mock TLS certificate")
class EgressSuiteTest(unittest.TestCase):
    tmp: str
    certfile: str
    keyfile: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp(prefix="ipl-egress-test-")
        cls.certfile = f"{cls.tmp}/cert.pem"
        cls.keyfile = f"{cls.tmp}/key.pem"
        subprocess.run(
            [OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", cls.keyfile, "-out", cls.certfile, "-days", "1",
             "-subj", "/CN=mock-proxy.test"],
            check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def start(self, mode: str) -> tuple[mock_proxy.MockProxyServer, int]:
        port = free_port()
        server = mock_proxy.start_in_thread(
            port, mode=mode, certfile=self.certfile, keyfile=self.keyfile)
        self.addCleanup(server.shutdown)
        return server, port

    def run_suite(self, engine: str, mode: str, full: bool) -> dict[str, "egress.Result"]:
        _, port = self.start(mode)
        results = egress.run_suite(f"http://127.0.0.1:{port}", engine, full=full)
        return {r.name: r for r in results}

    # -- quick suite --------------------------------------------------------

    def test_quick_suite_strict(self) -> None:
        results = self.run_suite("pipelock", "strict", full=False)
        expected_pass = [
            "allowed-http", "allowed-https",
            "blocked-host-connect", "blocked-host-http",
            "direct-ip-connect", "loopback-ipv4", "rfc1918-ipv4",
            "link-local-ipv4", "metadata-endpoint",
            "loopback-ipv6", "private-ipv6",
        ]
        for name in expected_pass:
            self.assertEqual(results[name].outcome, "pass",
                             f"{name}: {results[name].detail}")

    def test_open_proxy_is_reported_as_failure(self) -> None:
        # A mock that allows everything must make the deny tests fail.
        port = free_port()
        server = mock_proxy.MockProxyServer(
            ("127.0.0.1", port),
            allowed=set(), mode="lenient",
            certfile=self.certfile, keyfile=self.keyfile)
        # Everything-allowed policy: patch the decision method.
        server.host_allowed = lambda host: True  # type: ignore[method-assign]
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)

        results = {r.name: r for r in
                   egress.run_suite(f"http://127.0.0.1:{port}", "pipelock", full=False)}
        self.assertEqual(results["blocked-host-connect"].outcome, "fail")
        self.assertEqual(results["loopback-ipv4"].outcome, "fail")

    # -- full suite: CONNECT abuse -----------------------------------------

    def test_full_suite_strict_pipelock_expectations(self) -> None:
        results = self.run_suite("pipelock", "strict", full=True)
        # Strict mock rejects mismatched SNI and raw bytes => pipelock passes.
        self.assertEqual(results["connect-sni-mismatch"].outcome, "pass",
                         results["connect-sni-mismatch"].detail)
        self.assertEqual(results["connect-raw-tunnel"].outcome, "pass",
                         results["connect-raw-tunnel"].detail)
        # Fixture-dependent tests skip: *.nip.io is not in the mock allowlist.
        self.assertEqual(results["dns-private-ipv4"].outcome, "skip")
        self.assertEqual(results["dns-rebinding"].outcome, "skip")
        self.assertEqual(results["concurrency-sanity"].outcome, "record")

    def test_full_suite_lenient_smokescreen_expectations(self) -> None:
        results = self.run_suite("smokescreen", "lenient", full=True)
        # Smokescreen behavior is recorded, not judged.
        self.assertEqual(results["connect-sni-mismatch"].outcome, "record",
                         results["connect-sni-mismatch"].detail)
        self.assertEqual(results["connect-raw-tunnel"].outcome, "record",
                         results["connect-raw-tunnel"].detail)

    def test_full_suite_lenient_squid_expectations(self) -> None:
        # Squid relays CONNECT tunnels without inspecting them, like
        # Smokescreen, so its tunnel behavior is recorded rather than
        # graded (docs/comparison.md).
        results = self.run_suite("squid", "lenient", full=True)
        self.assertEqual(results["connect-sni-mismatch"].outcome, "record",
                         results["connect-sni-mismatch"].detail)
        self.assertEqual(results["connect-raw-tunnel"].outcome, "record",
                         results["connect-raw-tunnel"].detail)

    def test_quick_suite_strict_squid(self) -> None:
        # The graded deny/allow floors are engine-independent; Squid must
        # pass the same eleven the other two do.
        results = self.run_suite("squid", "strict", full=False)
        for name, result in results.items():
            self.assertEqual(result.outcome, "pass", f"{name}: {result.detail}")

    def test_lenient_behavior_would_fail_pipelock_expectations(self) -> None:
        # If Pipelock behaved leniently, the suite must flag it.
        results = self.run_suite("pipelock", "lenient", full=True)
        self.assertEqual(results["connect-sni-mismatch"].outcome, "fail",
                         results["connect-sni-mismatch"].detail)
        self.assertEqual(results["connect-raw-tunnel"].outcome, "fail",
                         results["connect-raw-tunnel"].detail)

    def _mixed_fixture_server(self, allowed_names: set[str]) -> int:
        """A mock allowing exactly `allowed_names` on top of the nip.io probe
        that gates the fixture-dependent tests.

        The mock decides by hostname, so it can stand in for an engine's
        *verdict* on the mixed names but not for the resolution behind it —
        which is fine: this exercises the check's own grading, and the real
        resolution behavior is measured in docs/comparison.md.
        """
        port = free_port()
        allowed = set(mock_proxy.DEFAULT_ALLOWED) | {"1.1.1.1.nip.io"} | allowed_names
        server = mock_proxy.start_in_thread(
            port, allowed=allowed, mode="strict",
            certfile=self.certfile, keyfile=self.keyfile)
        self.addCleanup(server.shutdown)
        return port

    def test_mixed_answers_passes_when_only_the_control_is_reachable(self) -> None:
        port = self._mixed_fixture_server({egress.MIXED_FIXTURE_CONTROL})
        client = egress.ProxyClient("127.0.0.1", port)
        raw = egress.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertEqual(len(raw.attempts), 1 + len(egress.MIXED_FIXTURE_TARGETS))

    def test_mixed_answers_fails_when_a_mixed_name_is_reachable(self) -> None:
        port = self._mixed_fixture_server(
            {egress.MIXED_FIXTURE_CONTROL, *egress.MIXED_FIXTURE_TARGETS})
        client = egress.ProxyClient("127.0.0.1", port)
        raw = egress.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "fail", raw.detail)
        for name in egress.MIXED_FIXTURE_TARGETS:
            self.assertIn(name, raw.detail)

    def test_mixed_answers_skips_without_a_working_control(self) -> None:
        # No control means a denial below cannot be attributed to
        # mixed-answer handling, so the row must not bank a pass.
        port = self._mixed_fixture_server(set())
        client = egress.ProxyClient("127.0.0.1", port)
        raw = egress.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "skip", raw.detail)
        self.assertIn("control probe", raw.detail)
        self.assertEqual(len(raw.attempts), 1)

    def test_mixed_answers_failure_carries_no_invented_cause(self) -> None:
        """A failing deny-check has no denial to attribute. The detail must
        not read back as one — an earlier revision said "a private address"
        and got itself classified as `private-ip`."""
        port = self._mixed_fixture_server(
            {egress.MIXED_FIXTURE_CONTROL, *egress.MIXED_FIXTURE_TARGETS})
        results = {r.name: r for r in
                   egress.run_suite(f"http://127.0.0.1:{port}", "squid", full=True)}
        row = results["dns-mixed-answers"]
        self.assertEqual(row.outcome, "fail", row.detail)
        self.assertIsNone(row.cause)

    def test_fixture_detection_activates_with_test_policy(self) -> None:
        port = free_port()
        allowed = set(mock_proxy.DEFAULT_ALLOWED) | {"1.1.1.1.nip.io"}
        server = mock_proxy.start_in_thread(
            port, allowed=allowed, mode="strict",
            certfile=self.certfile, keyfile=self.keyfile)
        self.addCleanup(server.shutdown)
        client = egress.ProxyClient("127.0.0.1", port)
        self.assertTrue(egress.fixtures_active(client))

    def test_exit_code_reflects_failures(self) -> None:
        _, port = self.start("strict")
        rc_ok = egress.main(["--proxy", f"http://127.0.0.1:{port}",
                             "--engine", "pipelock", "--quick", "--json"])
        self.assertEqual(rc_ok, 0)


class ClassifyDenialTest(unittest.TestCase):
    """Best-effort denial-cause taxonomy (TODO.md §1)."""

    def test_metadata(self) -> None:
        text = "denied by mock policy: destination is the cloud metadata endpoint"
        self.assertEqual(egress.classify_denial(text), "metadata")

    def test_sni_mismatch(self) -> None:
        text = "tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): mismatch"
        self.assertEqual(egress.classify_denial(text), "sni-mismatch")

    def test_non_tls_in_tunnel(self) -> None:
        text = ("tunnel established; connection closed with no response to raw (non-TLS) "
                "bytes — consistent with a non-TLS-in-tunnel policy check")
        self.assertEqual(egress.classify_denial(text), "non-tls-in-tunnel")

    def test_private_ip(self) -> None:
        text = "denied by mock policy: destination resolves to a loopback address"
        self.assertEqual(egress.classify_denial(text), "private-ip")

    def test_timeout(self) -> None:
        self.assertEqual(egress.classify_denial("connection error: timed out"), "timeout")

    def test_hostname_not_allowlisted(self) -> None:
        text = "HTTP/1.1 403 Forbidden — denied by mock policy: hostname not on allowlist"
        self.assertEqual(egress.classify_denial(text), "hostname-not-allowlisted")

    def test_unknown_fallback(self) -> None:
        self.assertEqual(egress.classify_denial("connection reset by peer"), "unknown")


class SummarizeBodyTest(unittest.TestCase):
    """Squid answers denials with an HTML error page rather than a
    sentence. `summarize_body` has to flatten it without losing the reason
    classify_denial() reads out of `detail`."""

    def test_strips_tags_and_collapses_whitespace(self) -> None:
        body = ("<html><head><title>403 Forbidden</title></head><body>\n"
                "<p>internet-proxy-locally denied this   request:\n"
                "the destination is not in the allowlist.</p>\n</body></html>")
        summary = egress.summarize_body(body)
        self.assertNotIn("<", summary)
        self.assertIn("the destination is not in the allowlist.", summary)
        self.assertEqual(summary, " ".join(summary.split()))

    def test_reason_survives_for_classification(self) -> None:
        body = "<html><body><p>SSRF blocked, the destination resolves to a private address.</p></body></html>"
        self.assertEqual(egress.classify_denial(egress.summarize_body(body)), "private-ip")

    def test_truncates_overlong_bodies(self) -> None:
        summary = egress.summarize_body("x " * 4000, limit=100)
        self.assertLessEqual(len(summary), 102)
        self.assertTrue(summary.endswith("…"))

    def test_short_body_is_unchanged(self) -> None:
        self.assertEqual(egress.summarize_body("  denied by policy  "), "denied by policy")


class ClassifyDenialRealWordingTest(unittest.TestCase):
    """Verbatim engine wording captured on 2026-08-19 (docs/comparison.md).

    The invented strings in ClassifyDenialTest all classified correctly
    while the taxonomy was still keying on bare addresses and on the word
    "forbidden" — which is in every 403 line. These are the strings that
    caught it, so they are the ones worth pinning.
    """

    PIPELOCK = [
        # A destination echoed back is not a reason: all of these are
        # allowlist denials even though the text contains a private address.
        ("HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 127.0.0.1",
         "hostname-not-allowlisted"),
        ("HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1",
         "hostname-not-allowlisted"),
        ("HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254",
         "hostname-not-allowlisted"),
        ("HTTP/1.1 403 Forbidden — CONNECT blocked: SSRF blocked: 10.0.0.1.nip.io "
         "resolves to internal IP 10.0.0.1", "private-ip"),
        ("HTTP/1.1 403 Forbidden — CONNECT blocked: SSRF blocked: fe80--1.sslip.io "
         "resolves to non-overridable internal IP fe80::1", "private-ip"),
        ("HTTP/1.1 403 Forbidden — CONNECT blocked: SSRF blocked: 169.254.169.254.nip.io "
         "resolves to cloud metadata endpoint 169.254.169.254", "metadata"),
        ("HTTP/1.1 403 Forbidden — CONNECT blocked: DNS lookup for "
         "01010101.7f000002.rbndr.us returned no such host", "dns-failure"),
    ]

    SMOKESCREEN = [
        ("HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
         "'example.com:443': default rule policy used.", "hostname-not-allowlisted"),
        ("HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
         "'127.0.0.1:80': default rule policy used.", "hostname-not-allowlisted"),
        ("HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
         "'[fd00::1]:80': Destination host cannot be determined.", "unparseable-destination"),
        ("HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
         "'10.0.0.1.nip.io:80': no valid IP found among resolved addresses - 10.0.0.1 "
         "denied by rule 'Deny: Private Range'. .", "private-ip"),
        ("HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
         "'fe80--1.sslip.io:80': no valid IP found among resolved addresses - fe80::1 "
         "denied by rule 'Deny: Not Global Unicast'. .", "private-ip"),
        ("HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
         "'--1.sslip.io:80': invalid domain \"--1.sslip.io\": idna: invalid label \"--1\".",
         "unparseable-destination"),
        ("HTTP/1.1 502 Bad gateway — Failed to resolve remote hostname: lookup "
         "01010101.7f000002.rbndr.us: no such host", "dns-failure"),
    ]

    # Measured against real Squid 6.12 on 2026-08-25. The first four are
    # the custom `deny_info` pages in images/squid/errors, which exist so a
    # Squid denial states its cause the way the other two engines' do; the
    # last is Squid's own ERR_DNS_FAIL, which is not a policy verdict.
    SQUID = [
        ("HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
         "the destination is not in the allowlist.", "hostname-not-allowlisted"),
        ("HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
         "SSRF blocked, the destination resolves to a private, loopback, link-local or "
         "otherwise non-public address.", "private-ip"),
        ("HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
         "SSRF blocked, the destination resolves to a cloud metadata endpoint.", "metadata"),
        ("HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
         "CONNECT to this port is not allowed, tunnels are permitted to port 443 only.",
         "port-not-allowed"),
        ("HTTP/1.1 503 Service Unavailable — ERROR: The requested URL could not be retrieved "
         "The following error was encountered while trying to retrieve the URL: "
         "https://01010101.7f000002.rbndr.us/* Unable to determine IP address from host name "
         "01010101.7f000002.rbndr.us The DNS server returned: Server Failure: The name server "
         "was unable to process this query.", "dns-failure"),
    ]

    def test_squid_wording(self) -> None:
        for text, expected in self.SQUID:
            with self.subTest(text=text[:60]):
                self.assertEqual(egress.classify_denial(text), expected)

    def test_pipelock_wording(self) -> None:
        for text, expected in self.PIPELOCK:
            with self.subTest(text=text[:60]):
                self.assertEqual(egress.classify_denial(text), expected)

    def test_smokescreen_wording(self) -> None:
        for text, expected in self.SMOKESCREEN:
            with self.subTest(text=text[:60]):
                self.assertEqual(egress.classify_denial(text), expected)

    def test_no_real_denial_is_unknown(self) -> None:
        for text, _ in self.PIPELOCK + self.SMOKESCREEN + self.SQUID:
            with self.subTest(text=text[:60]):
                self.assertNotEqual(egress.classify_denial(text), "unknown")


class AggregateCauseTest(unittest.TestCase):
    """A mixed attempt set must not report a minority reason (TODO.md §1)."""

    @staticmethod
    def _attempt(n: int, cause: str) -> "egress.Attempt":
        return egress.Attempt(n=n, target=f"t{n}", local_resolved=[], outcome="denied",
                              status=403, elapsed_ms=1.0, detail="", cause=cause)

    def test_uniform_attempts_report_that_cause(self) -> None:
        attempts = [self._attempt(i, "private-ip") for i in range(3)]
        self.assertEqual(egress.aggregate_cause("ignored", attempts), "private-ip")

    def test_mixed_attempts_report_every_cause(self) -> None:
        # The real dns-private-ipv4 shape: 3 private-IP + 1 metadata. Matching
        # the concatenated detail would have reported "metadata" alone.
        attempts = [self._attempt(i, "private-ip") for i in range(3)]
        attempts.append(self._attempt(3, "metadata"))
        self.assertEqual(egress.aggregate_cause("ignored", attempts),
                         "metadata+private-ip")

    def test_no_cause_when_attempts_exist_but_none_was_denied(self) -> None:
        established = egress.Attempt(n=0, target="t", local_resolved=[], outcome="established",
                                     status=200, elapsed_ms=1.0, detail="HTTP/1.1 200 OK")
        self.assertIsNone(egress.aggregate_cause(
            "the engine connected although 10.0.0.1 was in the answer set", [established]))

    def test_falls_back_to_detail_without_attempts(self) -> None:
        self.assertEqual(
            egress.aggregate_cause("denied by mock policy: hostname not on allowlist", []),
            "hostname-not-allowlisted")


class AnnotateTlsBytesTest(unittest.TestCase):
    """Decoding the exact alert bytes docs/comparison.md manually decoded."""

    def test_decodes_documented_alert_sequence(self) -> None:
        data = b"\x15\x03\x03\x00\x02\x02\x32" + b"\x15\x03\x03\x00\x02\x01\x00"
        result = egress.annotate_tls_bytes(data)
        self.assertIn("alert(21)", result)
        self.assertIn("fatal(2)", result)
        self.assertIn("decode_error(50)", result)
        self.assertIn("warning(1)", result)
        self.assertIn("close_notify(0)", result)

    def test_falls_back_for_non_tls_bytes(self) -> None:
        result = egress.annotate_tls_bytes(b"HTTP/1.1 400 Bad Request\r\n")
        self.assertIn("not a recognized TLS record", result)


class LogDeltaTest(unittest.TestCase):
    def test_returns_new_lines(self) -> None:
        self.assertEqual(egress._log_delta(["a", "b"], ["a", "b", "c", "d"]), ["c", "d"])

    def test_empty_before(self) -> None:
        self.assertEqual(egress._log_delta([], ["x"]), ["x"])

    def test_falls_back_on_rotation(self) -> None:
        self.assertEqual(egress._log_delta(["a"], ["b", "c"]), ["b", "c"])


class LogCaptureTest(unittest.TestCase):
    """`--backend-bin`/`--container` end to end, via a tiny fake backend
    that returns a growing log on every `logs` call — no real container
    runtime available in this environment (TODO.md §1's log-capture item)."""

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
        port = free_port()
        server = mock_proxy.start_in_thread(port, mode="strict")
        self.addCleanup(server.shutdown)
        results = egress.run_suite(f"http://127.0.0.1:{port}", "pipelock", full=False,
                                   backend_bin=self.backend_bin, container="fake")
        self.assertTrue(results)
        for r in results:
            self.assertEqual(len(r.engine_logs), 1, f"{r.name}: {r.engine_logs}")
        lines = [r.engine_logs[0] for r in results]
        self.assertEqual(len(lines), len(set(lines)), "each test's window should be distinct")

    def test_no_capture_without_backend_args(self) -> None:
        port = free_port()
        server = mock_proxy.start_in_thread(port, mode="strict")
        self.addCleanup(server.shutdown)
        results = egress.run_suite(f"http://127.0.0.1:{port}", "pipelock", full=False)
        self.assertTrue(all(r.engine_logs == [] for r in results))


class DnsRebindEvidenceTest(unittest.TestCase):
    """`test_dns_rebind`'s per-attempt evidence (TODO.md §1). The outcome
    stays `record` — each rbndr.us query is an independent random draw, so
    the checker's own resolution cannot grade the engine's — but the detail
    must say whether the fixture varied or a cache flattened it. Driven
    through monkeypatched `resolve_locally` since real DNS is unavailable
    here."""

    def setUp(self) -> None:
        self._orig_resolve = egress.resolve_locally
        self.addCleanup(lambda: setattr(egress, "resolve_locally", self._orig_resolve))

    @staticmethod
    def _hostnames() -> set[str]:
        return {egress._rebind_target(i)[0] for i in range(6)}

    def test_every_attempt_uses_a_fresh_hostname(self) -> None:
        self.assertEqual(len(self._hostnames()), 6)

    def test_established_attempts_are_recorded_not_failed(self) -> None:
        port = free_port()
        allowed = set(mock_proxy.DEFAULT_ALLOWED) | self._hostnames()
        server = mock_proxy.start_in_thread(port, allowed=allowed, mode="strict")
        self.addCleanup(server.shutdown)
        egress.resolve_locally = lambda host: ["127.0.0.9"]
        client = egress.ProxyClient("127.0.0.1", port)

        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "record")
        self.assertEqual(len(raw.attempts), 6)
        self.assertTrue(all(a.outcome == "established" for a in raw.attempts))
        self.assertIn("6 established", raw.detail)
        self.assertIn("caching resolver", raw.detail)

    def test_denied_attempts_are_recorded_not_passed(self) -> None:
        port = free_port()
        server = mock_proxy.start_in_thread(port, mode="strict")  # default allowlist: hostnames denied
        self.addCleanup(server.shutdown)
        egress.resolve_locally = lambda host: ["127.0.0.9"]
        client = egress.ProxyClient("127.0.0.1", port)

        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "record")
        self.assertTrue(all(a.outcome == "denied" for a in raw.attempts))
        self.assertIn("6 denied", raw.detail)

    def test_varying_resolution_is_reported_as_such(self) -> None:
        port = free_port()
        server = mock_proxy.start_in_thread(port, mode="strict")
        self.addCleanup(server.shutdown)
        answers = iter(["1.1.1.1", "127.0.0.2"] * 3)
        egress.resolve_locally = lambda host: [next(answers)]
        client = egress.ProxyClient("127.0.0.1", port)

        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "record")
        self.assertIn("did vary", raw.detail)

    def test_unresolvable_fixture_is_called_unattributable(self) -> None:
        port = free_port()
        server = mock_proxy.start_in_thread(port, mode="strict")
        self.addCleanup(server.shutdown)
        egress.resolve_locally = lambda host: []
        client = egress.ProxyClient("127.0.0.1", port)

        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "record")
        self.assertIn("unattributable", raw.detail)
        self.assertTrue(all(a.local_resolved == [] for a in raw.attempts))


class DiffModeTest(unittest.TestCase):
    def test_flags_only_divergent_checks(self) -> None:
        a = {"schema_version": 1, "engine": "pipelock", "results": [
            {"name": "connect-sni-mismatch", "outcome": "pass", "cause": None, "detail": "denied"},
            {"name": "allowed-http", "outcome": "pass", "cause": None, "detail": "200"},
        ]}
        b = {"schema_version": 1, "engine": "smokescreen", "results": [
            {"name": "connect-sni-mismatch", "outcome": "record", "cause": None, "detail": "allowed"},
            {"name": "allowed-http", "outcome": "pass", "cause": None, "detail": "301"},
        ]}
        lines = egress.diff_results(a, b)
        self.assertEqual(len(lines), 1)
        self.assertIn("connect-sni-mismatch", lines[0])

    def test_no_divergence_when_identical(self) -> None:
        a = {"results": [{"name": "x", "outcome": "pass", "cause": None, "detail": "d"}]}
        self.assertEqual(egress.diff_results(a, a), [])

    def test_flags_checks_present_in_only_one_file(self) -> None:
        a = {"results": [{"name": "x", "outcome": "pass", "cause": None, "detail": "d"}]}
        b = {"results": []}
        lines = egress.diff_results(a, b)
        self.assertEqual(len(lines), 1)
        self.assertIn("only in A", lines[0])


if __name__ == "__main__":
    unittest.main()
