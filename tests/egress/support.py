"""Shared mock-proxy scaffolding for tests/egress/test_*.py.

No network egress: the mock proxy answers everything locally, terminating
TLS with a throwaway self-signed certificate generated once per test run.
Not itself a test module (no `test_` prefix), so `unittest discover`
skips it — the same convention `tests/mock_proxy.py` already uses.
"""

from __future__ import annotations

import atexit
import functools
import shutil
import socket
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from typing import Protocol

from internet_proxy_locally.checks.egress.transport import ProxyClient
from tests import mock_proxy

OPENSSL = shutil.which("openssl")
requires_openssl = unittest.skipUnless(
    OPENSSL, "openssl needed to generate the mock TLS certificate"
)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@functools.lru_cache(maxsize=1)
def _cert_and_key() -> tuple[str, str]:
    """One throwaway self-signed cert, generated once and shared by every
    test file in this run rather than once per file."""
    tmp = tempfile.mkdtemp(prefix="ipl-egress-test-")
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)
    certfile, keyfile = f"{tmp}/cert.pem", f"{tmp}/key.pem"
    assert OPENSSL, "guarded by requires_openssl on the caller"
    subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            keyfile,
            "-out",
            certfile,
            "-days",
            "1",
            "-subj",
            "/CN=mock-proxy.test",
        ],
        check=True,
        capture_output=True,
    )
    return certfile, keyfile


def start_mock(
    test_case: unittest.TestCase,
    *,
    mode: str = "strict",
    allowed: set[str] | None = None,
    host_allowed: Callable[[str], bool] | None = None,
) -> tuple[mock_proxy.MockProxyServer, int]:
    """Start a MockProxyServer on a free port with the shared cert,
    registering its shutdown as cleanup on `test_case`.

    `host_allowed`, when given, replaces the server's allow decision
    entirely — used by tests that need per-request logic instead of a
    fixed set of allowed hostnames.
    """
    certfile, keyfile = _cert_and_key()
    port = free_port()
    server = mock_proxy.start_in_thread(
        port, mode=mode, allowed=allowed, certfile=certfile, keyfile=keyfile
    )
    if host_allowed is not None:
        server.host_allowed = host_allowed  # ty: ignore[invalid-assignment]
    test_case.addCleanup(server.stop)
    return server, port


class Outcome(Protocol):
    outcome: str


def assert_each_target_matters(
    test_case: unittest.TestCase,
    check: Callable[[ProxyClient], tuple[str, str] | Outcome],
    targets: tuple[str, ...],
) -> None:
    """Prove a multi-target denial check fails when each target alone is allowed."""
    for allowed_target in targets:
        allowed_host = allowed_target.rsplit(":", 1)[0]
        with test_case.subTest(allowed_target=allowed_target):
            _, port = start_mock(
                test_case,
                mode="strict",
                host_allowed=lambda host, expected=allowed_host: host == expected,
            )
            result = check(ProxyClient("127.0.0.1", port))
            outcome = result[0] if isinstance(result, tuple) else result.outcome
            test_case.assertEqual(outcome, "fail")
