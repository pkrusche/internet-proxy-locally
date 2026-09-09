"""The raw-socket HTTP/CONNECT/TLS client every check probes through.

Stdlib only (`socket`, `ssl`), so a check never depends on anything the
proxy itself might also depend on.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass

from .tls import annotate_tls_bytes

TIMEOUT = 8.0
MAX_HEADER_BYTES = 64 * 1024


@dataclass
class HttpResponse:
    status: int | None
    headers: dict[str, str]
    body: str
    first_line: str


def _parse_headers(data: bytes) -> dict[str, str]:
    head, _, _ = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")[1:]
    headers: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def _parse_body(data: bytes) -> str:
    _, _, body = data.partition(b"\r\n\r\n")
    return body.decode("latin-1", "replace")


def summarize_body(body: str, limit: int = 600) -> str:
    """Collapse a response body to a single readable line.

    Pipelock and Smokescreen answer a denial with one sentence; Squid
    answers with an HTML error page. Stripping tags and runs of whitespace
    keeps all three comparable in the text table and in `--json`, and
    leaves the engine's own wording intact for classify_denial() — which
    reads `detail`, so the reason has to survive this.
    """
    text = re.sub(r"<[^>]*>", " ", body)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit].rstrip() + " …"


class ProxyClient:
    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = TIMEOUT,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _sock(self) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        return sock

    @staticmethod
    def _status_of(data: bytes) -> int | None:
        line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", line)
        return int(match.group(1)) if match else None

    def http_get(self, url: str) -> HttpResponse:
        """Absolute-form GET through the proxy."""
        host = re.sub(r"^\w+://", "", url).split("/", 1)[0]
        request = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: internet-proxy-locally-egress-check\r\n"
            "Connection: close\r\n\r\n"
        )
        try:
            with self._sock() as sock:
                sock.sendall(request.encode())
                data = self._recv_some(sock)
        except OSError as exc:
            return HttpResponse(None, {}, "", f"connection error: {exc}")
        status = self._status_of(data)
        first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return HttpResponse(
            status,
            _parse_headers(data),
            _parse_body(data),
            first or "(connection closed, no data)",
        )

    def connect(self, target: str) -> tuple[socket.socket | None, int | None, str]:
        """CONNECT to `host:port`. On 200, returns the open tunnel socket.
        On denial, `detail` includes a short response body when the engine
        sent one, for cause classification."""
        request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        sock = None
        try:
            sock = self._sock()
            sock.sendall(request.encode())
            data = self._recv_headers(sock)
        except OSError as exc:
            # Close even when sending or reading fails after a successful connection.
            if sock is not None:
                sock.close()
            return None, None, f"connection error: {exc}"
        status = self._status_of(data)
        first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if status == 200:
            return sock, status, first
        _, _, extra = data.partition(b"\r\n\r\n")
        if not extra:
            # Body not yet in hand — engines that send one usually do so
            # immediately, so wait only briefly rather than the full timeout.
            try:
                sock.settimeout(1.0)
                extra = sock.recv(2048)
            except OSError:
                pass
        sock.close()
        body = summarize_body(extra.decode("latin-1", "replace"))
        detail = (
            f"{first} — {body}" if body else (first or "(connection closed, no data)")
        )
        return None, status, detail

    def tunnel_carried(
        self, sock: socket.socket, target: str
    ) -> tuple[bool | None, str]:
        """Actively exercise CONNECT, including an intercepting TLS endpoint.

        True means an HTTP response was received through TLS; False means
        Squid explicitly reported an access denial. A bare CONNECT 200,
        TLS handshake alone, timeout, EOF, or TLS alert cannot establish
        origin reachability or attribute a refusal, so those return None.
        Certificate verification is disabled for this behavioral probe,
        as in tls_in_tunnel(); this is not a trust-chain test.
        """
        host = target.rsplit(":", 1)[0].strip("[]")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            sock.settimeout(self.timeout)
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(
                    (
                        f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                    ).encode()
                )
                data = self._recv_headers(tls)
                status = self._status_of(data)
                headers = {k.lower(): v for k, v in _parse_headers(data).items()}
                if status is None or b"\r\n\r\n" not in data:
                    return None, "inconclusive: no complete HTTP response after TLS"
                first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                if not 200 <= status < 400:
                    body = summarize_body(self._recv_error_body(tls, data, headers))
                    detail = f"{first} — {body}" if body else first
                    # Our deny_info pages need not include X-Squid-Error.
                    # Match the project's explicit statement, not a generic
                    # origin 403 or incidental words such as "private IP".
                    marker = "internet-proxy-locally denied this request: "
                    if status == 403 and body.startswith(
                        (marker, f"403 Forbidden {marker}")
                    ):
                        return False, f"denied after CONNECT: {detail}"
                    error = headers.get("x-squid-error", "")
                    if status == 403 and error.split()[:1] == ["ERR_ACCESS_DENIED"]:
                        return (
                            False,
                            f"denied after CONNECT: Squid ERR_ACCESS_DENIED — {detail}",
                        )
                    if error:
                        detail += f" (X-Squid-Error: {error})"
                    return None, f"inconclusive HTTP response after TLS: {detail}"
                return True, f"HTTP response received after TLS: {first}"
        except (OSError, ssl.SSLError) as exc:
            return None, f"inconclusive TLS/HTTP exchange after CONNECT: {exc}"
        finally:
            sock.close()

    def _recv_error_body(
        self,
        sock: socket.socket,
        data: bytes,
        headers: dict[str, str],
        limit: int = 8192,
    ) -> str:
        """Read a bounded error-page excerpt, including separately sent bodies.

        Honor Content-Length so a keep-alive peer need not close. Without
        a length, the request's Connection: close supplies the boundary.
        Reading failures retain any excerpt already received for diagnosis.
        """
        _, _, body = data.partition(b"\r\n\r\n")
        try:
            limit = min(limit, max(0, int(headers.get("content-length", str(limit)))))
        except ValueError:
            pass
        body = body[:limit]
        deadline = time.monotonic() + self.timeout
        while len(body) < limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                sock.settimeout(remaining)
                chunk = sock.recv(limit - len(body))
            except OSError:
                break
            if not chunk:
                break
            body += chunk
        return body.decode("latin-1", "replace")

    def _recv_headers(self, sock: socket.socket) -> bytes:
        data = b""
        deadline = time.monotonic() + self.timeout
        while b"\r\n\r\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out reading proxy response headers")
            sock.settimeout(remaining)
            chunk = sock.recv(min(4096, MAX_HEADER_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_HEADER_BYTES:
                raise OSError(f"proxy response headers exceed {MAX_HEADER_BYTES} bytes")
        return data

    def verified_https_get(
        self, target: str, path: str = "/", *, ca_file: str | None = None
    ) -> HttpResponse:
        """CONNECT, verify peer identity/trust, then perform an HTTPS GET."""
        sock, _status, first = self.connect(target)
        if sock is None:
            return HttpResponse(None, {}, "", f"CONNECT denied: {first}")
        host = target.rsplit(":", 1)[0].strip("[]")
        ctx = ssl.create_default_context(cafile=ca_file)
        try:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )
                data = self._recv_some(tls)
        except (ssl.SSLError, OSError) as exc:
            return HttpResponse(None, {}, "", f"verified TLS/GET failed: {exc}")
        status = self._status_of(data)
        first_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return HttpResponse(status, _parse_headers(data), _parse_body(data), first_line)

    def _recv_some(self, sock: socket.socket, limit: int = 8192) -> bytes:
        data = b""
        try:
            while len(data) < limit:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        return data

    def tls_in_tunnel(self, target: str, sni: str) -> tuple[bool, str]:
        """CONNECT then perform a TLS handshake with the given SNI.

        Certificate verification is deliberately off: this tests whether
        the proxy lets the handshake through, not upstream authenticity.
        """
        sock, _status, first = self.connect(target)
        if sock is None:
            return False, f"CONNECT denied: {first}"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                version = tls.version() or "TLS"
                return True, f"tunnel established, {version} handshake OK (SNI={sni})"
        except (ssl.SSLError, OSError) as exc:
            return (
                False,
                f"tunnel established but TLS handshake failed (SNI={sni}): {exc}",
            )
        finally:
            sock.close()

    def raw_in_tunnel(self, target: str, payload: bytes) -> tuple[bytes, str]:
        """CONNECT then send non-TLS bytes; returns (response, detail)."""
        sock, _status, first = self.connect(target)
        if sock is None:
            return b"", f"CONNECT denied: {first}"
        try:
            sock.sendall(payload)
            data = self._recv_some(sock, limit=2048)
        except OSError as exc:
            sock.close()
            return b"", f"tunnel reset while sending raw bytes: {exc}"
        sock.close()
        if not data:
            return b"", (
                "tunnel established; connection closed with no response to raw "
                "(non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check"
            )
        annotated = annotate_tls_bytes(data)
        return data, f"raw bytes traversed the tunnel; response: {annotated}"
