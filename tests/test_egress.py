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

    def test_lenient_behavior_would_fail_pipelock_expectations(self) -> None:
        # If Pipelock behaved leniently, the suite must flag it.
        results = self.run_suite("pipelock", "lenient", full=True)
        self.assertEqual(results["connect-sni-mismatch"].outcome, "fail",
                         results["connect-sni-mismatch"].detail)
        self.assertEqual(results["connect-raw-tunnel"].outcome, "fail",
                         results["connect-raw-tunnel"].detail)

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


if __name__ == "__main__":
    unittest.main()
