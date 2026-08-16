#!/usr/bin/env python3
"""Common adversarial egress test suite for internet-proxy-locally.

Runs the same checks against either engine (Pipelock or Smokescreen)
through the stable proxy endpoint, and produces comparable results.

Stdlib only; Python 3.11+.

Groups:
  quick — ordinary allow/deny behavior (README §8 "Basic policy")
  full  — quick + SSRF/DNS fixtures and CONNECT-abuse tests

The DNS fixture tests (nip.io / sslip.io / rbndr.us) only make sense when
the *test* policy is mounted (`./run.py up --test-policy`): the fixture
hostnames must be allowlisted so that a rejection can only come from the
IP-layer SSRF protections, not from ordinary hostname policy. The suite
auto-detects whether the test policy is active and skips those tests
otherwise.

Outcomes:
  pass   — behavior matched the expectation
  fail   — behavior violated the expectation
  record — engine behavior documented, no pass/fail defined (README §8)
  skip   — prerequisites missing (with reason)
  error  — the test itself could not run
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, asdict

DEFAULT_PROXY = "http://127.0.0.1:18080"
TIMEOUT = 8.0

ALLOWED_HTTP_HOST = "pypi.org"          # must be on the allowlist
ALLOWED_HTTPS_HOST = "pypi.org"         # must be on the allowlist
ALLOWED_ALT_HOST = "files.pythonhosted.org"  # allowlisted, used as mismatching SNI
BLOCKED_HOST = "example.com"            # must NOT be on the allowlist

# Engine-specific expectations for the CONNECT-abuse tests (README §8):
# Pipelock is expected to reject; Smokescreen behavior is recorded.
ENGINE_EXPECTATIONS = {
    "pipelock": {"connect-sni-mismatch": "deny", "connect-raw-tunnel": "deny"},
    "smokescreen": {"connect-sni-mismatch": "record", "connect-raw-tunnel": "record"},
}


@dataclass
class Result:
    name: str
    group: str          # "quick" | "full"
    expectation: str    # "allow" | "deny" | "record"
    outcome: str        # "pass" | "fail" | "record" | "skip" | "error"
    detail: str


class ProxyClient:
    def __init__(self, host: str, port: int, timeout: float = TIMEOUT):
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

    def http_get(self, url: str) -> tuple[int | None, str]:
        """Absolute-form GET through the proxy. Returns (status, detail)."""
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
            return None, f"connection error: {exc}"
        status = self._status_of(data)
        first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return status, first or "(connection closed, no data)"

    def connect(self, target: str) -> tuple[socket.socket | None, int | None, str]:
        """CONNECT to `host:port`. On 200, returns the open tunnel socket."""
        request = (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n\r\n"
        )
        try:
            sock = self._sock()
            sock.sendall(request.encode())
            data = self._recv_headers(sock)
        except OSError as exc:
            return None, None, f"connection error: {exc}"
        status = self._status_of(data)
        first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if status == 200:
            return sock, status, first
        sock.close()
        return None, status, first or "(connection closed, no data)"

    def _recv_headers(self, sock: socket.socket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

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
        sock, status, first = self.connect(target)
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
            return False, f"tunnel established but TLS handshake failed (SNI={sni}): {exc}"
        finally:
            sock.close()

    def raw_in_tunnel(self, target: str, payload: bytes) -> tuple[bytes, str]:
        """CONNECT then send non-TLS bytes; returns (response, detail)."""
        sock, status, first = self.connect(target)
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
            return b"", "tunnel established; connection closed with no response to raw bytes"
        first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return data, f"raw bytes traversed the tunnel; response: {first!r}"


# ---------------------------------------------------------------------------
# Individual tests. Each returns (outcome, detail) given a client.
# ---------------------------------------------------------------------------


def _classify_deny_connect(client: ProxyClient, target: str) -> tuple[str, str]:
    sock, status, detail = client.connect(target)
    if sock is not None:
        sock.close()
        return "fail", f"tunnel to {target} was ESTABLISHED: {detail}"
    return "pass", f"denied: {detail}"


def _classify_deny_http(client: ProxyClient, url: str) -> tuple[str, str]:
    status, detail = client.http_get(url)
    if status is not None and status < 400:
        return "fail", f"request succeeded ({detail})"
    return "pass", f"denied: {detail}"


def test_allowed_http(client: ProxyClient) -> tuple[str, str]:
    status, detail = client.http_get(f"http://{ALLOWED_HTTP_HOST}/")
    if status is not None and status < 400:
        return "pass", f"reached {ALLOWED_HTTP_HOST} ({detail})"
    return "fail", f"expected success, got: {detail}"


def test_allowed_https(client: ProxyClient) -> tuple[str, str]:
    ok, detail = client.tls_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", ALLOWED_HTTPS_HOST)
    return ("pass" if ok else "fail"), detail


def test_blocked_host_connect(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, f"{BLOCKED_HOST}:443")


def test_blocked_host_http(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_http(client, f"http://{BLOCKED_HOST}/")


def test_direct_ip_connect(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "1.1.1.1:443")


def test_loopback(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "127.0.0.1:80")


def test_rfc1918(client: ProxyClient) -> tuple[str, str]:
    outcomes = [_classify_deny_connect(client, t) for t in ("10.0.0.1:80", "192.168.1.1:80", "172.16.0.1:80")]
    bad = [d for o, d in outcomes if o == "fail"]
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "10.0.0.1, 192.168.1.1, 172.16.0.1 all denied"


def test_link_local(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "169.254.1.1:80")


def test_metadata(client: ProxyClient) -> tuple[str, str]:
    o1, d1 = _classify_deny_connect(client, "169.254.169.254:80")
    o2, d2 = _classify_deny_http(client, "http://169.254.169.254/latest/meta-data/")
    if "fail" in (o1, o2):
        return "fail", f"CONNECT: {d1}; GET: {d2}"
    return "pass", "metadata endpoint denied for CONNECT and GET"


def test_ipv6_loopback(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "[::1]:80")


def test_ipv6_private(client: ProxyClient) -> tuple[str, str]:
    outcomes = [_classify_deny_connect(client, t) for t in ("[fd00::1]:80", "[fe80::1]:80")]
    bad = [d for o, d in outcomes if o == "fail"]
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "fd00::1 and fe80::1 denied"


# -- DNS fixtures (need the test policy active) -----------------------------


def fixtures_active(client: ProxyClient) -> bool:
    """True when *.nip.io is allowlisted (test policy) — a public-IP nip.io
    name should then tunnel; under the normal policy it is hostname-denied."""
    sock, status, _ = client.connect("1.1.1.1.nip.io:443")
    if sock is not None:
        sock.close()
        return True
    return False


FIXTURE_SKIP = ("test policy not active — run `./run.py up --test-policy` "
                "to exercise DNS/SSRF fixtures, then re-run")


def test_dns_private_v4(client: ProxyClient) -> tuple[str, str]:
    targets = ("10.0.0.1.nip.io:80", "192.168.1.1.nip.io:80",
               "127.0.0.1.nip.io:80", "169.254.169.254.nip.io:80")
    outcomes = [_classify_deny_connect(client, t) for t in targets]
    bad = [d for o, d in outcomes if o == "fail"]
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied"


def test_dns_private_v6(client: ProxyClient) -> tuple[str, str]:
    # sslip.io: dashes become colons, so "--1" => ::1, "fe80--1" => fe80::1
    targets = ("--1.sslip.io:80", "fe80--1.sslip.io:80", "fd00--1.sslip.io:80")
    outcomes = [_classify_deny_connect(client, t) for t in targets]
    bad = [d for o, d in outcomes if o == "fail"]
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "allowlisted hostnames resolving to private/loopback IPv6 all denied"


def test_dns_rebind(client: ProxyClient) -> tuple[str, str]:
    """rbndr.us alternates answers between 1.1.1.1 and 127.0.0.1.

    A proxy with rebinding protection validates the resolved IP it actually
    connects to, every time; loopback must never be reachable. The result is
    recorded (timing-dependent), with a hard fail only if a tunnel is
    established AND the fixture currently resolves to loopback is undetectable
    from here — so established tunnels are reported for manual review.
    """
    target = "7f000001.01010101.rbndr.us:443"
    denied = established = errors = 0
    for _ in range(6):
        sock, status, _ = client.connect(target)
        if sock is not None:
            established += 1
            sock.close()
        elif status is None:
            errors += 1
        else:
            denied += 1
    return "record", (f"{target}: denied={denied} established={established} errors={errors} "
                      "(established tunnels can be legitimate when the answer was public; "
                      "verify engine logs show per-connection resolved-IP validation)")


def test_dns_mixed(client: ProxyClient) -> tuple[str, str]:
    return "skip", ("mixed public/private DNS answers need a local DNS fixture; "
                    "see docs/security.md for the dnsmasq recipe")


# -- CONNECT abuse ----------------------------------------------------------


def test_sni_mismatch(client: ProxyClient) -> tuple[str, str]:
    """CONNECT to one allowlisted host with the SNI of another."""
    ok, detail = client.tls_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", ALLOWED_ALT_HOST)
    if ok:
        return "allowed", f"mismatched SNI accepted: {detail}"
    return "denied", detail


def test_raw_tunnel(client: ProxyClient) -> tuple[str, str]:
    payload = (f"GET / HTTP/1.1\r\nHost: {ALLOWED_HTTPS_HOST}\r\nConnection: close\r\n\r\n").encode()
    data, detail = client.raw_in_tunnel(f"{ALLOWED_HTTPS_HOST}:443", payload)
    if not data:
        return "denied", detail
    return "allowed", detail


def test_concurrency(client: ProxyClient) -> tuple[str, str]:
    def one(_: int) -> bool:
        sock, status, _ = client.connect(f"{ALLOWED_HTTPS_HOST}:443")
        if sock is not None:
            sock.close()
            return True
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(one, range(10)))
    ok = sum(results)
    return "record", f"10 concurrent CONNECTs to an allowed host: {ok} established, {10 - ok} denied/failed"


# ---------------------------------------------------------------------------
# Suite driver
# ---------------------------------------------------------------------------

# (name, group, default expectation, callable, needs_fixtures)
TESTS = [
    ("allowed-http",         "quick", "allow",  test_allowed_http,         False),
    ("allowed-https",        "quick", "allow",  test_allowed_https,        False),
    ("blocked-host-connect", "quick", "deny",   test_blocked_host_connect, False),
    ("blocked-host-http",    "quick", "deny",   test_blocked_host_http,    False),
    ("direct-ip-connect",    "quick", "deny",   test_direct_ip_connect,    False),
    ("loopback-ipv4",        "quick", "deny",   test_loopback,             False),
    ("rfc1918-ipv4",         "quick", "deny",   test_rfc1918,              False),
    ("link-local-ipv4",      "quick", "deny",   test_link_local,           False),
    ("metadata-endpoint",    "quick", "deny",   test_metadata,             False),
    ("loopback-ipv6",        "quick", "deny",   test_ipv6_loopback,        False),
    ("private-ipv6",         "quick", "deny",   test_ipv6_private,         False),
    ("dns-private-ipv4",     "full",  "deny",   test_dns_private_v4,       True),
    ("dns-private-ipv6",     "full",  "deny",   test_dns_private_v6,       True),
    ("dns-rebinding",        "full",  "record", test_dns_rebind,           True),
    ("dns-mixed-answers",    "full",  "record", test_dns_mixed,            True),
    ("connect-sni-mismatch", "full",  "record", test_sni_mismatch,         False),
    ("connect-raw-tunnel",   "full",  "record", test_raw_tunnel,           False),
    ("concurrency-sanity",   "full",  "record", test_concurrency,          False),
]


def _finalize(name: str, expectation: str, raw: tuple[str, str]) -> tuple[str, str]:
    """Map a test's raw outcome onto its (possibly engine-specific) expectation."""
    outcome, detail = raw
    if outcome in ("pass", "fail", "record", "skip", "error"):
        # deny/allow-style tests already classified themselves against the
        # default expectation; re-interpret only behavioral outcomes below.
        return outcome, detail
    # Behavioral outcomes from the CONNECT-abuse tests: "denied" / "allowed".
    if expectation == "deny":
        return ("pass" if outcome == "denied" else "fail"), detail
    if expectation == "allow":
        return ("pass" if outcome == "allowed" else "fail"), detail
    return "record", f"observed: {outcome} — {detail}"


def run_suite(proxy: str, engine: str, full: bool) -> list[Result]:
    match = re.match(r"(?:http://)?([^:/]+):(\d+)/?$", proxy)
    if not match:
        raise SystemExit(f"cannot parse proxy endpoint: {proxy}")
    client = ProxyClient(match.group(1), int(match.group(2)))

    try:
        with socket.create_connection((client.host, client.port), timeout=3):
            pass
    except OSError as exc:
        raise SystemExit(f"proxy endpoint {proxy} is not reachable: {exc}")

    overrides = ENGINE_EXPECTATIONS.get(engine, {})
    have_fixtures = None
    results: list[Result] = []
    for name, group, default_expect, fn, needs_fixtures in TESTS:
        if group == "full" and not full:
            continue
        expectation = overrides.get(name, default_expect)
        if needs_fixtures:
            if have_fixtures is None:
                have_fixtures = fixtures_active(client)
            if not have_fixtures:
                results.append(Result(name, group, expectation, "skip", FIXTURE_SKIP))
                continue
        try:
            outcome, detail = _finalize(name, expectation, fn(client))
        except Exception as exc:  # a test must never take down the suite
            outcome, detail = "error", f"{type(exc).__name__}: {exc}"
        results.append(Result(name, group, expectation, outcome, detail))
    return results


def print_text(results: list[Result], engine: str) -> None:
    width = max(len(r.name) for r in results)
    print(f"egress checks — engine: {engine}")
    for r in results:
        print(f"  {r.name:<{width}}  [{r.expectation:^6}]  {r.outcome.upper():<6}  {r.detail}")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    print(f"summary: {summary}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--proxy", default=DEFAULT_PROXY)
    parser.add_argument("--engine", choices=("pipelock", "smokescreen"), required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true")
    mode.add_argument("--full", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    opts = parser.parse_args(argv)

    results = run_suite(opts.proxy, opts.engine, full=opts.full)
    if opts.as_json:
        print(json.dumps({"engine": opts.engine, "proxy": opts.proxy,
                          "results": [asdict(r) for r in results]}, indent=2))
    else:
        print_text(results, opts.engine)
    return 1 if any(r.outcome in ("fail", "error") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
