#!/usr/bin/env python3
"""Policy-enforcing mock forward proxy for the local test suite.

Simulates the externally observable behavior of the real engines without
any network egress:

- absolute-form GET: 200 for allowlisted hostnames, 403 otherwise;
- CONNECT: 200 + tunnel for allowlisted hostnames, 403 otherwise
  (IP-literal and non-allowlisted targets are always denied);
- inside an established tunnel:
  - strict mode (Pipelock-like): non-TLS bytes cause an immediate close,
    and a TLS ClientHello whose SNI differs from the CONNECT target
    aborts the handshake (unrecognized_name alert);
  - lenient mode (Smokescreen-like): non-TLS bytes get a fake origin
    response, and any SNI is accepted;
  - bumping mode (Squid-with-ssl_bump-like): every CONNECT is answered
    `200` before policy runs, because the ClientHello the proxy means to
    inspect only arrives once the client believes it has a tunnel. A
    denial reached afterwards can no longer send a page and aborts the
    tunnel instead. Enforcement is identical to strict mode; only the
    shape of the refusal differs.

TLS termination requires a self-signed cert (see tests/egress/).
Used two ways: imported and started in-process by tests, and spawned as
a process by the fake container backend shim to emulate a published port.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import socketserver
import ssl
import sys
import threading

DEFAULT_ALLOWED = {"pypi.org", "files.pythonhosted.org", "github.com"}


class MockProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        addr,
        *,
        allowed: set[str],
        mode: str,
        certfile: str | None,
        keyfile: str | None,
    ):
        self.allowed = allowed
        self.mode = mode
        self.tls_ctx: ssl.SSLContext | None = None
        if certfile and keyfile:
            self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_ctx.load_cert_chain(certfile, keyfile)
        super().__init__(addr, Handler)

    def stop(self) -> None:
        """Stop serving *and* close the listening socket.

        `shutdown()` alone only breaks out of `serve_forever`; the bound
        socket stays open until the object is collected, which is one
        leaked descriptor per test that starts a proxy. Registering this
        as the single cleanup is what keeps the two from drifting apart.
        """
        self.shutdown()
        self.server_close()

    def host_allowed(self, host: str) -> bool:
        host = host.strip("[]").lower()
        try:
            ipaddress.ip_address(host)
            return False  # IP literals always denied by the mock policy
        except ValueError:
            pass
        return host in self.allowed

    def deny_reason(self, host: str) -> str:
        """A cause-differentiated deny body, mirroring the kind of detail a
        real engine's response is expected to carry (docs/security.md's
        denial-taxonomy gap) — not a claim about actual engine wording."""
        bare = host.strip("[]").lower()
        try:
            addr = ipaddress.ip_address(bare)
        except ValueError:
            return "denied by mock policy: hostname not on allowlist"
        if bare == "169.254.169.254":
            return "denied by mock policy: destination is the cloud metadata endpoint"
        if addr.is_loopback:
            return "denied by mock policy: destination resolves to a loopback address"
        if addr.is_link_local:
            return "denied by mock policy: destination resolves to a link-local address"
        if addr.is_private or addr.is_reserved:
            return "denied by mock policy: destination resolves to a private address"
        return "denied by mock policy: IP-literal CONNECT targets are not allowlisted"


class Handler(socketserver.BaseRequestHandler):
    server: MockProxyServer

    def handle(self) -> None:
        try:
            self._handle()
        except OSError:
            pass

    def _read_head(self) -> bytes:
        data = b""
        self.request.settimeout(5)
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def _send(self, status: int, reason: str, body: str = "") -> None:
        payload = body.encode()
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        )
        self.request.sendall(head.encode() + payload)

    def _handle(self) -> None:
        head = self._read_head()
        if not head:
            return
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")

        connect = re.match(r"CONNECT\s+(\S+)\s+HTTP/", line)
        if connect:
            self._handle_connect(connect.group(1))
            return

        absolute = re.match(r"[A-Z]+\s+\w+://([^/\s:]+)", line)
        if absolute:
            host = absolute.group(1)
            if self.server.host_allowed(host):
                self._send(200, "OK", f"mock response from {host}\n")
            else:
                self._send(403, "Forbidden", self.server.deny_reason(host) + "\n")
            return
        self._send(400, "Bad Request", "expected absolute-form or CONNECT\n")

    def _handle_connect(self, target: str) -> None:
        host, _, _port = target.rpartition(":")
        allowed = self.server.host_allowed(host)
        # A bumping proxy commits to the tunnel before it decides, so its
        # refusal arrives too late to carry a reason.
        if not allowed and self.server.mode != "bumping":
            self._send(403, "Forbidden", self.server.deny_reason(host) + "\n")
            return
        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        if not allowed:
            return  # the 200 is already sent; aborting is the only refusal left

        first = self.request.recv(1, socket.MSG_PEEK)
        if not first:
            return
        if first != b"\x16":  # not a TLS handshake record
            if self.server.mode != "lenient":
                # Close immediately: Pipelock sni_require_tls-style, and
                # equally what a bumping Squid does with bytes it cannot
                # parse as TLS.
                return
            self._read_head()
            self._send(400, "Bad Request", "plain HTTP request sent to HTTPS port\n")
            return

        if self.server.tls_ctx is None:
            return  # cannot terminate TLS without a cert; close
        expected = host.lower()
        strict = self.server.mode == "strict"

        def sni_cb(sock: ssl.SSLObject, name: str | None, ctx: ssl.SSLContext):
            if strict and (name or "").lower() != expected:
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            return None

        self.server.tls_ctx.sni_callback = sni_cb
        try:
            tls = self.server.tls_ctx.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            tls.settimeout(2)
            try:
                tls.recv(4096)
            except (ssl.SSLError, OSError):
                pass
        finally:
            try:
                tls.close()
            except OSError:
                pass


def start_in_thread(
    port: int,
    *,
    allowed: set[str] | None = None,
    mode: str = "strict",
    certfile: str | None = None,
    keyfile: str | None = None,
) -> MockProxyServer:
    server = MockProxyServer(
        ("127.0.0.1", port),
        allowed=allowed or set(DEFAULT_ALLOWED),
        mode=mode,
        certfile=certfile,
        keyfile=keyfile,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument(
        "--mode", choices=("strict", "lenient", "bumping"), default="strict"
    )
    parser.add_argument("--allow", default=",".join(sorted(DEFAULT_ALLOWED)))
    parser.add_argument("--cert")
    parser.add_argument("--key")
    opts = parser.parse_args()
    allowed = {h.strip() for h in opts.allow.split(",") if h.strip()}
    server = MockProxyServer(
        ("127.0.0.1", opts.port),
        allowed=allowed,
        mode=opts.mode,
        certfile=opts.cert,
        keyfile=opts.key,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
