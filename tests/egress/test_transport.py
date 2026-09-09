"""ProxyClient's socket handling, and summarize_body()."""

from __future__ import annotations

import socket
import struct
import threading
import unittest
import warnings

from internet_proxy_locally.checks.egress import denial, transport
from tests.egress import support


class SummarizeBodyTest(unittest.TestCase):
    """Squid answers denials with an HTML error page rather than a
    sentence. `summarize_body` has to flatten it without losing the reason
    classify_denial() reads out of `detail`."""

    def test_strips_tags_and_collapses_whitespace(self) -> None:
        body = (
            "<html><head><title>403 Forbidden</title></head><body>\n"
            "<p>internet-proxy-locally denied this   request:\n"
            "the destination is not in the allowlist.</p>\n</body></html>"
        )
        summary = transport.summarize_body(body)
        self.assertNotIn("<", summary)
        self.assertIn("the destination is not in the allowlist.", summary)
        self.assertEqual(summary, " ".join(summary.split()))

    def test_reason_survives_for_classification(self) -> None:
        body = "<html><body><p>SSRF blocked, the destination resolves to a private address.</p></body></html>"
        self.assertEqual(
            denial.classify_denial(transport.summarize_body(body)), "private-ip"
        )

    def test_truncates_overlong_bodies(self) -> None:
        summary = transport.summarize_body("x " * 4000, limit=100)
        self.assertLessEqual(len(summary), 102)
        self.assertTrue(summary.endswith("…"))

    def test_short_body_is_unchanged(self) -> None:
        self.assertEqual(
            transport.summarize_body("  denied by policy  "), "denied by policy"
        )


class TunnelCarriedTest(unittest.TestCase):
    """Idle sockets and un-attributable closures prove neither access nor denial."""

    def _pair(self, close: str) -> transport.ProxyClient:
        """A server that accepts and then either holds the connection open,
        closes it cleanly (FIN), or resets it (RST). Returns a client whose
        timeout is short enough not to slow the suite down."""
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)
        held: list[socket.socket] = []

        def accept() -> None:
            conn, _ = server.accept()
            if close == "reset":
                conn.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
                conn.close()
            elif close == "fin":
                conn.close()
            else:
                held.append(conn)  # keep the tunnel open past the timeout

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2.0)
        self.addCleanup(lambda: [c.close() for c in held])
        return transport.ProxyClient("127.0.0.1", server.getsockname()[1], timeout=0.2)

    def _carried(self, close: str) -> tuple[bool | None, str]:
        client = self._pair(close)
        sock = socket.create_connection((client.host, client.port), timeout=2.0)
        self.addCleanup(sock.close)
        return client.tunnel_carried(sock, "example.com:443")

    def test_an_idle_tunnel_is_inconclusive(self) -> None:
        carried, detail = self._carried("hold")
        self.assertIsNone(carried, detail)

    def test_a_clean_close_is_inconclusive(self) -> None:
        carried, detail = self._carried("fin")
        self.assertIsNone(carried, detail)

    def test_a_reset_is_inconclusive(self) -> None:
        carried, detail = self._carried("reset")
        self.assertIsNone(carried, detail)


@support.requires_openssl
class ActiveTunnelTest(unittest.TestCase):
    def test_denial_waits_for_clienthello_and_http(self) -> None:
        _, port = support.start_mock(self, mode="bumping")
        client = transport.ProxyClient("127.0.0.1", port, timeout=1)
        sock, status, _ = client.connect("example.com:443")
        assert sock is not None
        self.addCleanup(sock.close)
        self.assertEqual(status, 200)
        sock.settimeout(0.05)
        with self.assertRaises(TimeoutError):
            sock.recv(1)
        carried, detail = client.tunnel_carried(sock, "example.com:443")
        self.assertFalse(carried, detail)
        self.assertIn("ERR_ACCESS_DENIED", detail)

    def test_handshake_alone_and_ambiguous_errors_are_inconclusive(self) -> None:
        server, port = support.start_mock(self, mode="bumping")
        client = transport.ProxyClient("127.0.0.1", port, timeout=1)
        for response in (
            b"",
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 502 Bad Gateway\r\nX-Squid-Error: ERR_CONNECT_FAIL 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
        ):
            with self.subTest(response=response):
                server.tunnel_response = response
                sock, _, _ = client.connect("pypi.org:443")
                assert sock is not None
                carried, detail = client.tunnel_carried(sock, "pypi.org:443")
                self.assertIsNone(carried, detail)

    def test_allowed_tls_http_exchange(self) -> None:
        _, port = support.start_mock(self, mode="bumping")
        client = transport.ProxyClient("127.0.0.1", port, timeout=1)
        sock, _, _ = client.connect("pypi.org:443")
        assert sock is not None
        self.addCleanup(sock.close)
        carried, detail = client.tunnel_carried(sock, "pypi.org:443")
        self.assertTrue(carried, detail)
        self.assertIn("HTTP response received after TLS", detail)


class ProxyClientConnectTest(unittest.TestCase):
    def test_a_failed_connect_does_not_orphan_its_socket(self) -> None:
        """`connect()` opens the socket itself, so it owns it on the error
        path too.

        A server that accepts and then resets makes `sendall`/`recv` raise
        after `_sock()` has already succeeded. The descriptor used to be
        dropped on the floor there, which a long run of timing-out probes
        turns into a file-descriptor leak.
        """
        import gc

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
            conn.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            conn.close()

        thread = threading.Thread(target=accept_and_reset, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2.0)

        client = transport.ProxyClient("127.0.0.1", port, timeout=2.0)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            sock, _status, detail = client.connect("example.com:443")
            self.assertIsNone(sock)
            gc.collect()
        leaked = [
            w
            for w in caught
            if issubclass(w.category, ResourceWarning) and "socket" in str(w.message)
        ]
        self.assertEqual(leaked, [], f"connect() leaked a socket: {detail}")


if __name__ == "__main__":
    unittest.main()
