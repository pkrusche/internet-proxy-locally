"""Tests for checks/egress.py against the policy-enforcing mock proxy.

No network egress: the mock proxy answers everything locally, terminating
TLS with a throwaway self-signed certificate generated at setup time.
"""

from __future__ import annotations

import json
import shutil
import socket
import struct
import subprocess
import threading
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Run from the repository root, so everything imports by name. See the
# comment in scripts/harness.py.
from checks import egress  # noqa: E402
from tests import mock_proxy, quiet  # noqa: E402

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
        # graded (docs/findings.md).
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
        resolution behavior is measured in docs/findings.md.
        """
        port = free_port()
        allowed = set(mock_proxy.DEFAULT_ALLOWED) | {"1.1.1.1.nip.io"} | allowed_names
        server = mock_proxy.start_in_thread(
            port, allowed=allowed, mode="strict",
            certfile=self.certfile, keyfile=self.keyfile)
        self.addCleanup(server.shutdown)
        return port

    def test_mixed_answers_denies_when_only_the_control_is_reachable(self) -> None:
        port = self._mixed_fixture_server({egress.MIXED_FIXTURE_CONTROL})
        client = egress.ProxyClient("127.0.0.1", port)
        raw = egress.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "denied", raw.detail)
        self.assertEqual(len(raw.attempts), 1 + len(egress.MIXED_FIXTURE_TARGETS))

    def test_mixed_answers_reports_allowed_when_a_mixed_name_is_reachable(self) -> None:
        port = self._mixed_fixture_server(
            {egress.MIXED_FIXTURE_CONTROL, *egress.MIXED_FIXTURE_TARGETS})
        client = egress.ProxyClient("127.0.0.1", port)
        raw = egress.test_dns_mixed(client)
        self.assertEqual(raw.outcome, "allowed", raw.detail)
        for name in egress.MIXED_FIXTURE_TARGETS:
            self.assertIn(name, raw.detail)

    def test_mixed_answers_is_graded_per_engine(self) -> None:
        """The same behavior is a failure on the engines that are expected
        to refuse it and a recorded deviation on Smokescreen, which is not
        (ENGINE_EXPECTATIONS)."""
        port = self._mixed_fixture_server(
            {egress.MIXED_FIXTURE_CONTROL, *egress.MIXED_FIXTURE_TARGETS})
        graded = {}
        for engine in ("pipelock", "squid", "smokescreen"):
            results = {r.name: r for r in
                       egress.run_suite(f"http://127.0.0.1:{port}", engine, full=True)}
            graded[engine] = results["dns-mixed-answers"].outcome
        self.assertEqual(graded["pipelock"], "fail")
        self.assertEqual(graded["squid"], "fail")
        self.assertEqual(graded["smokescreen"], "record")

    def test_smokescreens_recorded_deviation_does_not_set_the_exit_code(self) -> None:
        # The point of the grade: a known, bounded deviation must not make
        # `check --full` indistinguishable from a broken engine.
        port = self._mixed_fixture_server(
            {egress.MIXED_FIXTURE_CONTROL, *egress.MIXED_FIXTURE_TARGETS})
        results = egress.run_suite(f"http://127.0.0.1:{port}", "smokescreen", full=True)
        row = {r.name: r for r in results}["dns-mixed-answers"]
        self.assertEqual(row.outcome, "record")
        self.assertIn("established", row.detail)
        self.assertIsNone(row.cause, "nothing was denied, so there is no cause")

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

    def test_a_failed_connect_does_not_orphan_its_socket(self) -> None:
        """`connect()` opens the socket itself, so it owns it on the error
        path too.

        A server that accepts and then resets makes `sendall`/`recv` raise
        after `_sock()` has already succeeded. The descriptor used to be
        dropped on the floor there, which a long run of timing-out probes
        turns into a file-descriptor leak.
        """
        import gc
        import warnings

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)
        port = server.getsockname()[1]

        def accept_and_reset() -> None:
            conn, _ = server.accept()
            # Linger 0 => RST rather than a clean FIN, so the client's
            # recv raises instead of returning b"".
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
            conn.close()

        thread = threading.Thread(target=accept_and_reset, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2.0)

        client = egress.ProxyClient("127.0.0.1", port, timeout=2.0)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            sock, status, detail = client.connect("example.com:443")
            self.assertIsNone(sock)
            gc.collect()
        leaked = [w for w in caught if issubclass(w.category, ResourceWarning)
                  and "socket" in str(w.message)]
        self.assertEqual(leaked, [], f"connect() leaked a socket: {detail}")

    def test_exit_code_reflects_failures(self) -> None:
        _, port = self.start("strict")
        with quiet() as printed:
            rc_ok = egress.main(["--proxy", f"http://127.0.0.1:{port}",
                                 "--engine", "pipelock", "--quick", "--json"])
        self.assertEqual(rc_ok, 0)
        # --json means the envelope is the whole of stdout, so assert that
        # rather than letting it scroll past.
        self.assertEqual(json.loads(printed.out)["engine"], "pipelock")


class ClassifyDenialTest(unittest.TestCase):
    """Best-effort denial-cause taxonomy (docs/security.md)."""

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
    """Verbatim engine wording captured on 2026-08-19 (docs/findings.md).

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
        ("HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
         "the destination is a bare IP address, and this proxy allowlists destinations by "
         "hostname only.", "ip-literal-destination"),
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
    """A mixed attempt set must not report a minority reason (docs/security.md)."""

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
    """Decoding the exact alert bytes docs/findings.md manually decoded."""

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


class ParseFixtureLogTest(unittest.TestCase):
    """The fixture's own transcript is what grades dns-rebinding, so
    reading it has to be exact."""

    LINES = [
        "IPL-FIXTURE starting address=192.168.64.60 public=9.9.9.9",
        "IPL-FIXTURE dns name=a0-ab12cd.rebind.fixture.test query=1 answer=9.9.9.9",
        "dnsmasq: query[A] something.else from 192.168.64.1",
        "IPL-FIXTURE dns name=a0-ab12cd.rebind.fixture.test query=2 answer=192.168.64.60",
        "IPL-FIXTURE trap connect from=192.168.64.47:51102",
    ]

    def test_collects_answers_in_order_and_trap_hits(self) -> None:
        answers, trap = egress.parse_fixture_log(self.LINES)
        self.assertEqual(answers["a0-ab12cd.rebind.fixture.test"],
                         ["9.9.9.9", "192.168.64.60"])
        self.assertEqual(trap, ["192.168.64.47:51102"])

    def test_ignores_unrelated_lines(self) -> None:
        answers, trap = egress.parse_fixture_log(
            ["dnsmasq: started", "random noise", ""])
        self.assertEqual((answers, trap), ({}, []))


class PtrAllowlistTest(unittest.TestCase):
    """`ptr-allowlist` guards a bypass the rest of the suite cannot see:
    Squid retries a `dstdomain` miss as a reverse lookup, so an address
    whose PTR names an allowlisted host is allowed through. Measured before
    the fix (docs/findings.md), and `direct-ip-connect` passed throughout
    — it uses an address with no PTR claim."""

    def setUp(self) -> None:
        self._source = egress.FIXTURE_LOG_SOURCE
        self.addCleanup(lambda: setattr(egress, "FIXTURE_LOG_SOURCE", self._source))
        self.asked = False
        egress.FIXTURE_LOG_SOURCE = lambda: ["IPL-FIXTURE trap listening on 10.0.0.2:443"]

    def client(self, allow: bool) -> "egress.ProxyClient":
        port = free_port()
        server = mock_proxy.start_in_thread(port, mode="strict")

        def host_allowed(host: str) -> bool:
            self.asked = True
            return allow

        server.host_allowed = host_allowed  # type: ignore[method-assign]
        self.addCleanup(server.shutdown)
        return egress.ProxyClient("127.0.0.1", port)

    def test_fails_when_the_address_is_reachable(self) -> None:
        raw = egress.test_ptr_allowlist(self.client(allow=True))
        self.assertEqual(raw.outcome, "fail", raw.detail)
        self.assertIn(egress.PTR_FIXTURE_ADDRESS, raw.detail)
        self.assertIn("reverse record", raw.detail)

    def test_passes_when_denied(self) -> None:
        raw = egress.test_ptr_allowlist(self.client(allow=False))
        self.assertEqual(raw.outcome, "pass", raw.detail)

    def test_reports_whether_a_reverse_lookup_happened(self) -> None:
        """An engine that never reverse-resolves passes without the
        fallback having been offered. The detail must not imply otherwise."""
        raw = egress.test_ptr_allowlist(self.client(allow=False))
        self.assertIn("no reverse lookup", raw.detail)

        # The query line appears only once the probe has been made, as it
        # would in a live fixture — the check subtracts what was already
        # there so an earlier run's lookups are not counted as this one's.
        reversed_name = ".".join(reversed(egress.PTR_FIXTURE_ADDRESS.split("."))) + ".in-addr.arpa"
        self.asked = False
        egress.FIXTURE_LOG_SOURCE = lambda: (
            ["IPL-FIXTURE trap listening on 10.0.0.2:443"]
            + ([f"dnsmasq: query[PTR] {reversed_name} from 192.168.64.1"] if self.asked else []))
        raw = egress.test_ptr_allowlist(self.client(allow=False))
        self.assertIn("1 reverse lookup(s)", raw.detail)

    def test_a_previous_runs_lookup_is_not_counted(self) -> None:
        reversed_name = ".".join(reversed(egress.PTR_FIXTURE_ADDRESS.split("."))) + ".in-addr.arpa"
        egress.FIXTURE_LOG_SOURCE = lambda: [
            "IPL-FIXTURE trap listening on 10.0.0.2:443",
            f"dnsmasq: query[PTR] {reversed_name} from 192.168.64.1",
        ]
        raw = egress.test_ptr_allowlist(self.client(allow=False))
        self.assertIn("no reverse lookup", raw.detail)

    def test_skips_without_an_observable_fixture(self) -> None:
        # Without the fixture the PTR claim is not live, and the address
        # would be denied for the ordinary reason — a pass proving nothing.
        egress.FIXTURE_LOG_SOURCE = lambda: []
        raw = egress.test_ptr_allowlist(self.client(allow=False))
        self.assertEqual(raw.outcome, "skip", raw.detail)

    def test_the_fixture_address_is_public_and_unused_elsewhere(self) -> None:
        import ipaddress
        address = ipaddress.ip_address(egress.PTR_FIXTURE_ADDRESS)
        self.assertFalse(address.is_private or address.is_loopback or address.is_link_local,
                         "a private address would trip the SSRF floors instead of the allowlist")
        source = (REPO_ROOT / "checks" / "egress.py").read_text()
        # It must not collide with an address another check connects to, or
        # the fixture's PTR claim would leak into that check's result.
        self.assertNotIn(f'"{egress.PTR_FIXTURE_ADDRESS}:', source)


class DnsRebindTest(unittest.TestCase):
    """`dns-rebinding` grades on one thing: whether the fixture saw a
    connection. The mock proxy stands in for the engine's verdict on each
    CONNECT; the fixture transcript is supplied directly, since the real
    one is read from a container's log stream (docs/findings.md
    "DNS rebinding")."""

    def setUp(self) -> None:
        self._source = egress.FIXTURE_LOG_SOURCE
        self.addCleanup(lambda: setattr(egress, "FIXTURE_LOG_SOURCE", self._source))
        # The gap exists to defeat second-granularity resolver caches. No
        # real resolver is involved here, so don't pay for it.
        self._gap = egress.REBIND_TTL_GAP
        egress.REBIND_TTL_GAP = 0.0
        self.addCleanup(lambda: setattr(egress, "REBIND_TTL_GAP", self._gap))
        self.asked: list[str] = []

    def client(self, allow: bool) -> "egress.ProxyClient":
        """A mock that records every host it is asked about, so a
        transcript can be built for exactly the names the check invented."""
        port = free_port()
        server = mock_proxy.start_in_thread(port, mode="strict")
        asked = self.asked

        def host_allowed(host: str) -> bool:
            asked.append(host)
            return allow

        server.host_allowed = host_allowed  # type: ignore[method-assign]
        self.addCleanup(server.shutdown)
        return egress.ProxyClient("127.0.0.1", port)

    def transcript(self, lookups_per_name: int, trap: "list[str]" = ()) -> "list[str]":
        lines = []
        for name in sorted(set(self.asked)):
            answers = ["9.9.9.9", "192.168.64.60"][:lookups_per_name]
            for i, answer in enumerate(answers, start=1):
                lines.append(f"IPL-FIXTURE dns name={name} query={i} answer={answer}")
        return lines + [f"IPL-FIXTURE trap connect from={peer}" for peer in trap]

    def test_trap_hit_fails_even_when_every_probe_was_denied(self) -> None:
        """The decisive signal is the fixture's, not the proxy's: a denial
        of the CONNECT the checker made says nothing about a connection the
        engine opened for itself."""
        client = self.client(allow=False)
        # The hit appears only once probing has started, as it would in a
        # live fixture — the check subtracts whatever was already there.
        egress.FIXTURE_LOG_SOURCE = lambda: self.transcript(
            2, ["192.168.64.47:51102"] if self.asked else [])
        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "fail", raw.detail)
        self.assertIn("192.168.64.47", raw.detail)

    def test_a_pre_existing_trap_hit_is_not_blamed_on_this_run(self) -> None:
        """The fixture container outlives a single check, so trap hits
        accumulate. Only the ones this run produced may fail it."""
        client = self.client(allow=False)
        egress.FIXTURE_LOG_SOURCE = lambda: self.transcript(2, ["10.9.9.9:4242"])
        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)

    def test_passes_when_the_rebind_was_offered_and_refused(self) -> None:
        client = self.client(allow=False)
        egress.FIXTURE_LOG_SOURCE = lambda: self.transcript(2)
        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertIn(f"{egress.REBIND_NAMES}/{egress.REBIND_NAMES} names", raw.detail)
        self.assertNotIn("did not exercise", raw.detail)

    def test_pass_says_so_when_no_rebind_was_offered(self) -> None:
        """One lookup per name means the engine pinned the first answer and
        was never handed the private one. Still a pass — nothing reached
        the trap — but the detail must not imply a rebind was survived."""
        client = self.client(allow=True)
        egress.FIXTURE_LOG_SOURCE = lambda: self.transcript(1)
        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertIn("did not exercise", raw.detail)

    def test_skips_when_the_fixture_saw_nothing(self) -> None:
        client = self.client(allow=False)
        egress.FIXTURE_LOG_SOURCE = lambda: []
        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "skip", raw.detail)
        self.assertIn("no lookups", raw.detail)

    def test_each_name_is_probed_twice(self) -> None:
        client = self.client(allow=True)
        egress.FIXTURE_LOG_SOURCE = lambda: self.transcript(1)
        raw = egress.test_dns_rebind(client)
        self.assertEqual(len(raw.attempts), 2 * egress.REBIND_NAMES)
        targets = [a.target for a in raw.attempts]
        first_pass, second_pass = targets[:egress.REBIND_NAMES], targets[egress.REBIND_NAMES:]
        self.assertEqual(first_pass, second_pass)
        self.assertEqual(len(set(first_pass)), egress.REBIND_NAMES)

    def test_names_are_unique_per_run(self) -> None:
        """The fixture counts lookups per name and rebinds from the second
        onward, so a name reused by a later run would begin already
        rebound — and the fixture container outlives individual runs."""
        client = self.client(allow=True)
        egress.FIXTURE_LOG_SOURCE = lambda: self.transcript(1)
        first = {a.target for a in egress.test_dns_rebind(client).attempts}
        self.asked.clear()
        second = {a.target for a in egress.test_dns_rebind(client).attempts}
        self.assertFalse(first & second, "names must not repeat between runs")

    def test_only_the_trap_decides_the_grade(self) -> None:
        """A repeat probe that establishes, with the trap silent, means the
        engine reused the address it had already validated. That is a
        defense, not a failure."""
        client = self.client(allow=True)
        egress.FIXTURE_LOG_SOURCE = lambda: self.transcript(2)
        raw = egress.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertTrue(all(a.outcome == "established" for a in raw.attempts))
        self.assertIn("reused the address", raw.detail)


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
