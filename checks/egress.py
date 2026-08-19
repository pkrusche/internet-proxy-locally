#!/usr/bin/env python3
"""Common adversarial egress test suite for internet-proxy-locally.

Runs the same checks against either engine (Pipelock or Smokescreen)
through the stable proxy endpoint, and produces comparable results.

Stdlib only; Python 3.11+.

Groups:
  quick — ordinary allow/deny behavior (docs/policy.md)
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
  record — engine behavior documented, no pass/fail defined (docs/comparison.md)
  skip   — prerequisites missing (with reason)
  error  — the test itself could not run

Each result may carry: a best-effort denial `cause` classification, a
wall-clock `elapsed_ms`, per-attempt evidence (`attempts` — used by the
DNS fixtures), full response `headers` (allow-path checks), and the
engine's own log lines for that test's window (`--backend-bin`/
`--container`; `run.py check` wires this automatically).

`--diff A.json B.json` compares two prior `--json` runs and prints only
the rows that diverge, instead of running the suite.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict

DEFAULT_PROXY = "http://127.0.0.1:18080"
TIMEOUT = 8.0
SCHEMA_VERSION = 1

ALLOWED_HTTP_HOST = "pypi.org"          # must be on the allowlist
ALLOWED_HTTPS_HOST = "pypi.org"         # must be on the allowlist
ALLOWED_ALT_HOST = "files.pythonhosted.org"  # allowlisted, used as mismatching SNI
BLOCKED_HOST = "example.com"            # must NOT be on the allowlist

# Engine-specific expectations for the CONNECT-abuse tests: Pipelock is
# expected to reject; Smokescreen behavior is recorded (docs/comparison.md
# has the measured outcome — Smokescreen allows both).
ENGINE_EXPECTATIONS = {
    "pipelock": {"connect-sni-mismatch": "deny", "connect-raw-tunnel": "deny"},
    "smokescreen": {"connect-sni-mismatch": "record", "connect-raw-tunnel": "record"},
}


@dataclass
class Attempt:
    """One probe within a multi-target check (e.g. dns-rebinding)."""
    n: int
    target: str
    local_resolved: list[str]   # IPs the checker itself resolved, if any
    outcome: str                # "established" | "denied" | "error"
    status: int | None
    elapsed_ms: float
    detail: str
    cause: str | None = None    # filled in by the runner for denied attempts


@dataclass
class Result:
    name: str
    group: str          # "quick" | "full"
    expectation: str    # "allow" | "deny" | "record"
    outcome: str        # "pass" | "fail" | "record" | "skip" | "error"
    detail: str
    cause: str | None = None            # best-effort denial classification
    elapsed_ms: float | None = None
    attempts: list[Attempt] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    engine_logs: list[str] = field(default_factory=list)


@dataclass
class RawOutcome:
    """What a test function returns when it has more than (outcome, detail)."""
    outcome: str
    detail: str
    attempts: list[Attempt] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class HttpResponse:
    status: int | None
    headers: dict[str, str]
    body: str
    first_line: str


def _normalize(raw: "tuple[str, str] | RawOutcome") -> RawOutcome:
    if isinstance(raw, RawOutcome):
        return raw
    outcome, detail = raw
    return RawOutcome(outcome, detail)


# ---------------------------------------------------------------------------
# Local DNS resolution and IP classification
# ---------------------------------------------------------------------------


def resolve_locally(host: str) -> list[str]:
    """What *this* process resolves `host` to, right now. Best-effort:
    empty on any resolution failure (offline, NXDOMAIN, fixture down)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


# ---------------------------------------------------------------------------
# Denial-cause classification
# ---------------------------------------------------------------------------

# Ordered: more specific buckets first. Best-effort text match over
# whatever detail the checker already assembled (its own framing plus, when
# available, the engine's response body).
#
# Patterns match the engine's *stated reason*, never the destination it
# echoes back. Verified against real Pipelock wording on 2026-08-19: it
# reports "domain not in allowlist: 127.0.0.1" for a direct-IP CONNECT, so
# an earlier revision that keyed on bare addresses (127.0.0.1, fd00, fe80,
# 169.254.169.254) read the *target* and mislabelled plain allowlist
# denials as "private-ip"/"metadata". Likewise "forbidden" is a status-line
# artifact present in every 403, not a reason — matching it made the
# allowlist bucket a catch-all. Both are deliberately absent below; keep
# them out. "unknown" is expected and honest when nothing matches.
_TAXONOMY: list[tuple[str, re.Pattern]] = [
    # An engine that resolved the name and rejected the answer states so.
    ("metadata", re.compile(r"metadata", re.I)),
    ("sni-mismatch", re.compile(r"\bsni\b|unrecognized_name|domain.?fronting", re.I)),
    ("non-tls-in-tunnel", re.compile(r"non-tls|non.?tls.?in.?tunnel|decode_error|"
                                      r"plain (http|bytes)|raw (protocol|bytes)", re.I)),
    # Pipelock: "SSRF blocked: X resolves to internal IP".
    # Smokescreen: "no valid IP found among resolved addresses - 10.0.0.1
    # denied by rule 'Deny: Private Range'".
    ("private-ip", re.compile(r"\bssrf\b|private range|"
                               r"no valid ip found among resolved|"
                               r"resolves? to (a |an )?(non.?overridable )?"
                               r"(internal|private|loopback|link.?local|reserved)|"
                               r"(private|loopback|link.?local|rfc.?1918|reserved|internal)"
                               r" (ip|address)", re.I)),
    # Resolution never produced an answer: not a policy verdict at all.
    # Pipelock: "DNS lookup for X returned no such host".
    # Smokescreen: "502 Failed to resolve remote hostname: lookup X ...".
    ("dns-failure", re.compile(r"no such host|nxdomain|name or service not known|"
                                r"dns lookup .*(failed|returned)|"
                                r"(failed|unable) to resolve", re.I)),
    # Smokescreen rejects bracketed IPv6 literals before any policy applies
    # ("Destination host cannot be determined"), so its pass on the
    # private-IPv6 checks says nothing about private-IP defence. Kept as its
    # own bucket precisely so that row cannot be read as one.
    ("unparseable-destination", re.compile(r"destination host cannot be determined|"
                                            r"invalid domain|invalid label|\bidna\b|"
                                            r"could not parse (the )?(destination|host)", re.I)),
    ("timeout", re.compile(r"timed out|timeout", re.I)),
    # Smokescreen's default-deny ACL verdict is "default rule policy used".
    ("hostname-not-allowlisted", re.compile(r"not (on|in)( the)? allowlist|not.?allowlisted|"
                                             r"not.?whitelist|denied by (mock )?policy|"
                                             r"default rule policy|"
                                             r"no matching allow|blacklist", re.I)),
]


def classify_denial(text: str) -> str:
    for cause, pattern in _TAXONOMY:
        if pattern.search(text):
            return cause
    return "unknown"


def aggregate_cause(detail: str, attempts: "list[Attempt]") -> str:
    """One cause for a whole check.

    With per-attempt evidence, classify each attempt and combine, rather
    than matching the concatenated detail: a single text match returns
    whichever bucket appears first in the taxonomy, which on a mixed set
    silently reports a minority reason (dns-private-ipv4 read as
    "metadata" when three of its four attempts were plain private-IP
    rejections). Distinct causes are joined with "+" so a mixed row stays
    truthful and still diffs cleanly.
    """
    denied = [a for a in attempts if a.cause]
    if not denied:
        return classify_denial(detail)
    causes = sorted({a.cause for a in denied if a.cause})
    return "+".join(causes)


# ---------------------------------------------------------------------------
# TLS record decoding
# ---------------------------------------------------------------------------

_TLS_CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
_TLS_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
_TLS_ALERT_LEVELS = {1: "warning", 2: "fatal"}
_TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 90: "user_canceled",
    109: "missing_extension", 110: "unsupported_extension",
    112: "unrecognized_name", 116: "certificate_required",
}


def annotate_tls_bytes(data: bytes) -> str:
    """Decode TLS records (esp. alerts) instead of dumping repr(). Falls
    back to a hex/repr summary when the bytes are not TLS records at all
    (e.g. plaintext HTTP forwarded into a tunnel)."""
    records: list[str] = []
    offset = 0
    while offset + 5 <= len(data) and len(records) < 8:
        ctype = data[offset]
        version = int.from_bytes(data[offset + 1:offset + 3], "big")
        length = int.from_bytes(data[offset + 3:offset + 5], "big")
        if ctype not in _TLS_CONTENT_TYPES:
            break
        body = data[offset + 5:offset + 5 + length]
        ctype_name = _TLS_CONTENT_TYPES.get(ctype, f"unknown({ctype})")
        version_name = _TLS_VERSIONS.get(version, f"0x{version:04x}")
        line = f"type={ctype_name}({ctype}) version={version_name} length={length}"
        if ctype == 21 and len(body) >= 2:
            level = _TLS_ALERT_LEVELS.get(body[0], f"unknown({body[0]})")
            desc = _TLS_ALERT_DESCRIPTIONS.get(body[1], f"unknown({body[1]})")
            line += f" -> alert level={level}({body[0]}) description={desc}({body[1]})"
        records.append(line)
        offset += 5 + length
    if records:
        summary = "; ".join(records)
        remaining = data[offset:]
        if remaining:
            summary += f"; +{len(remaining)} trailing bytes: {remaining[:32].hex()}"
        return summary
    return f"not a recognized TLS record; first bytes: {data[:32].hex()} ({data[:32]!r})"


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
        return HttpResponse(status, _parse_headers(data), _parse_body(data),
                            first or "(connection closed, no data)")

    def connect(self, target: str) -> tuple[socket.socket | None, int | None, str]:
        """CONNECT to `host:port`. On 200, returns the open tunnel socket.
        On denial, `detail` includes a short response body when the engine
        sent one, for cause classification."""
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
        body = extra.decode("latin-1", "replace").strip()
        detail = f"{first} — {body}" if body else (first or "(connection closed, no data)")
        return None, status, detail

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
            return b"", ("tunnel established; connection closed with no response to raw "
                        "(non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check")
        annotated = annotate_tls_bytes(data)
        return data, f"raw bytes traversed the tunnel; response: {annotated}"


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


# ---------------------------------------------------------------------------
# Individual tests. Each returns (outcome, detail) or a RawOutcome.
# ---------------------------------------------------------------------------


def _classify_deny_connect(client: ProxyClient, target: str) -> tuple[str, str]:
    sock, status, detail = client.connect(target)
    if sock is not None:
        sock.close()
        return "fail", f"tunnel to {target} was ESTABLISHED: {detail}"
    return "pass", f"denied: {detail}"


def _classify_deny_http(client: ProxyClient, url: str) -> tuple[str, str]:
    resp = client.http_get(url)
    if resp.status is not None and resp.status < 400:
        return "fail", f"request succeeded ({resp.first_line})"
    body = resp.body.strip()
    text = f"{resp.first_line} — {body}" if body else resp.first_line
    return "pass", f"denied: {text}"


def test_allowed_http(client: ProxyClient) -> RawOutcome:
    resp = client.http_get(f"http://{ALLOWED_HTTP_HOST}/")
    if resp.status is not None and resp.status < 400:
        return RawOutcome("pass", f"reached {ALLOWED_HTTP_HOST} ({resp.first_line})", headers=resp.headers)
    return RawOutcome("fail", f"expected success, got: {resp.first_line}")


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
    return "pass", "; ".join(d for _, d in outcomes)


def test_link_local(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "169.254.1.1:80")


def test_metadata(client: ProxyClient) -> tuple[str, str]:
    o1, d1 = _classify_deny_connect(client, "169.254.169.254:80")
    o2, d2 = _classify_deny_http(client, "http://169.254.169.254/latest/meta-data/")
    if "fail" in (o1, o2):
        return "fail", f"CONNECT: {d1}; GET: {d2}"
    # Deliberately does not say "metadata": the cause is classified from
    # this text, and a reason word injected by the checker would be read
    # back as the engine's own. Pipelock in fact rejects the bare address
    # at the allowlist, exactly as it does 127.0.0.1 — the genuine
    # metadata verdict shows up in dns-private-ipv4, where an allowlisted
    # hostname resolves to 169.254.169.254.
    return "pass", f"denied for CONNECT and GET (CONNECT: {d1}; GET: {d2})"


def test_ipv6_loopback(client: ProxyClient) -> tuple[str, str]:
    return _classify_deny_connect(client, "[::1]:80")


def test_ipv6_private(client: ProxyClient) -> tuple[str, str]:
    outcomes = [_classify_deny_connect(client, t) for t in ("[fd00::1]:80", "[fe80::1]:80")]
    bad = [d for o, d in outcomes if o == "fail"]
    if bad:
        return "fail", "; ".join(bad)
    return "pass", "; ".join(d for _, d in outcomes)


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


def _connect_attempt(client: ProxyClient, n: int, target: str, host_for_resolution: str) -> Attempt:
    local = resolve_locally(host_for_resolution)
    t0 = time.monotonic()
    sock, status, detail = client.connect(target)
    elapsed = round((time.monotonic() - t0) * 1000, 1)
    established = sock is not None
    if established:
        sock.close()
    outcome = "established" if established else ("error" if status is None else "denied")
    return Attempt(n, target, local, outcome, status, elapsed, detail)


def test_dns_private_v4(client: ProxyClient) -> RawOutcome:
    targets = ("10.0.0.1.nip.io:80", "192.168.1.1.nip.io:80",
               "127.0.0.1.nip.io:80", "169.254.169.254.nip.io:80")
    attempts = [_connect_attempt(client, i, t, t.rsplit(":", 1)[0]) for i, t in enumerate(targets)]
    bad = [a for a in attempts if a.outcome == "established"]
    if bad:
        detail = "; ".join(f"{a.target} established (resolved {a.local_resolved})" for a in bad)
        return RawOutcome("fail", detail, attempts=attempts)
    return RawOutcome("pass", "allowlisted hostnames resolving to private/loopback/metadata IPv4 "
                              "all denied; resolved IPs recorded per attempt", attempts=attempts)


def test_dns_private_v6(client: ProxyClient) -> RawOutcome:
    # sslip.io: dashes become colons, so "0--1" => 0::1 (== ::1),
    # "fe80--1" => fe80::1. The bare "--1.sslip.io" spelling also resolves
    # to ::1 but is an invalid IDNA label (a label may not start with two
    # hyphens): Smokescreen rejects it as `invalid domain ... idna: invalid
    # label` and Pipelock as `no such host`, so neither engine ever reached
    # the SSRF check and the row scored a pass for the wrong reason
    # (measured 2026-08-19). "0--1" is the equivalent, valid spelling.
    targets = ("0--1.sslip.io:80", "fe80--1.sslip.io:80", "fd00--1.sslip.io:80")
    attempts = [_connect_attempt(client, i, t, t.rsplit(":", 1)[0]) for i, t in enumerate(targets)]
    bad = [a for a in attempts if a.outcome == "established"]
    if bad:
        detail = "; ".join(f"{a.target} established (resolved {a.local_resolved})" for a in bad)
        return RawOutcome("fail", detail, attempts=attempts)
    return RawOutcome("pass", "allowlisted hostnames resolving to private/loopback IPv6 all "
                              "denied; resolved IPs recorded per attempt", attempts=attempts)


# rbndr.us fixture pool for cache-busted rebinding attempts: pair a public
# resolver IP with a varying loopback octet so every attempt is a hostname
# neither the checker nor the engine has resolved before (see TODO.md §1 —
# a repeated hostname makes a stale/cached DNS answer indistinguishable
# from a real per-connection rebind defence).
_REBIND_PUBLIC_IPS = ("1.1.1.1", "1.0.0.1", "9.9.9.9", "8.8.8.8", "8.8.4.4", "149.112.112.112")


def _hex_ip(ip: str) -> str:
    return "".join(f"{int(octet):02x}" for octet in ip.split("."))


def _rebind_target(attempt: int) -> tuple[str, str, str]:
    """Return (hostname, public_ip, private_ip) for one cache-busted attempt."""
    public_ip = _REBIND_PUBLIC_IPS[attempt % len(_REBIND_PUBLIC_IPS)]
    private_ip = f"127.0.0.{2 + (attempt % 250)}"
    hostname = f"{_hex_ip(public_ip)}.{_hex_ip(private_ip)}.rbndr.us"
    return hostname, public_ip, private_ip


def test_dns_rebind(client: ProxyClient) -> RawOutcome:
    """Each attempt uses a fresh rbndr.us hostname (see `_rebind_target`), so
    no attempt can be served from a cache warmed by an earlier one, and
    records what the checker itself resolved that hostname to at attempt
    time.

    Stays `record`: rbndr.us answers *every query* with one of its two
    encoded IPs at random, so the checker's resolution and the engine's are
    independent draws. An established tunnel does not prove the engine saw
    the loopback answer, and a denial does not prove it saw the public one —
    grading a single attempt against the checker's own lookup would fail a
    correct engine most runs. What the per-attempt evidence *does* settle is
    the question docs/comparison.md's 2026-08-17 run could not (`denied=0
    established=6` on one engine, `denied=6 established=0` on the other):
    whether the fixture varied at all. Uniform local resolutions across six
    fresh hostnames mean a caching resolver, and a uniform engine result is
    then evidence of nothing. The graded proof that a hostname cannot reach
    a private address is `dns-private-ipv4`/`ipv6`; a conclusive rebinding
    grade needs the local DNS fixture (docs/security.md), not rbndr.us."""
    attempts = []
    for i in range(6):
        hostname, _, _ = _rebind_target(i)
        attempts.append(_connect_attempt(client, i, f"{hostname}:443", hostname))

    counts = {outcome: sum(1 for a in attempts if a.outcome == outcome)
              for outcome in ("established", "denied", "error")}
    resolved = sorted({ip for a in attempts for ip in a.local_resolved})
    if not resolved:
        fixture = ("the checker resolved none of them (no network / fixture unreachable), "
                   "so the engine-side result is unattributable")
    elif any(_is_private(ip) for ip in resolved) and not all(_is_private(ip) for ip in resolved):
        fixture = f"the fixture did vary for the checker (saw {resolved})"
    else:
        fixture = (f"the checker saw only {resolved} across all six — a caching resolver, "
                   "so a uniform engine result proves nothing")
    detail = (f"{counts['established']} established, {counts['denied']} denied, "
              f"{counts['error']} error across 6 cache-busted hostnames; {fixture}; "
              "per-attempt resolutions recorded")
    return RawOutcome("record", detail, attempts=attempts)


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


def _log_delta(before: list[str], after: list[str]) -> list[str]:
    """New lines since `before`. Falls back to the full `after` snapshot
    if the log stream rotated/truncated between the two reads."""
    if after[:len(before)] == before:
        return after[len(before):]
    return after


def _fetch_logs(backend_bin: str | None, container: str | None) -> list[str]:
    if not backend_bin or not container:
        return []
    try:
        proc = subprocess.run([backend_bin, "logs", container],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return ((proc.stdout or "") + (proc.stderr or "")).splitlines()


def run_suite(proxy: str, engine: str, full: bool,
             backend_bin: str | None = None, container: str | None = None) -> list[Result]:
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
        before_logs = _fetch_logs(backend_bin, container)
        t0 = time.monotonic()
        try:
            raw = _normalize(fn(client))
            outcome, detail = _finalize(name, expectation, (raw.outcome, raw.detail))
        except Exception as exc:  # a test must never take down the suite
            outcome, detail = "error", f"{type(exc).__name__}: {exc}"
            raw = RawOutcome(outcome, detail)
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        after_logs = _fetch_logs(backend_bin, container)
        for attempt in raw.attempts:
            if attempt.outcome == "denied" and attempt.cause is None:
                attempt.cause = classify_denial(attempt.detail)
        cause = (aggregate_cause(detail, raw.attempts)
                 if expectation == "deny" and outcome in ("pass", "fail") else None)
        results.append(Result(name, group, expectation, outcome, detail,
                              cause=cause, elapsed_ms=elapsed_ms,
                              attempts=raw.attempts, headers=raw.headers,
                              engine_logs=_log_delta(before_logs, after_logs)))
    return results


def print_text(results: list[Result], engine: str) -> None:
    width = max(len(r.name) for r in results)
    print(f"egress checks — engine: {engine}")
    for r in results:
        extra = f" [{r.cause}]" if r.cause else ""
        timing = f" ({r.elapsed_ms:.0f}ms)" if r.elapsed_ms is not None else ""
        attempts = f" [{len(r.attempts)} attempts]" if r.attempts else ""
        print(f"  {r.name:<{width}}  [{r.expectation:^6}]  {r.outcome.upper():<6}{extra}{timing}{attempts}  {r.detail}")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    print(f"summary: {summary}")


# ---------------------------------------------------------------------------
# --diff mode
# ---------------------------------------------------------------------------


def _load_results(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def diff_results(a: dict, b: dict) -> list[str]:
    a_by_name = {r["name"]: r for r in a.get("results", [])}
    b_by_name = {r["name"]: r for r in b.get("results", [])}
    lines: list[str] = []
    for name in sorted(set(a_by_name) | set(b_by_name)):
        ra, rb = a_by_name.get(name), b_by_name.get(name)
        if ra is None:
            lines.append(f"{name}: only in B — {rb['outcome']} ({rb['detail']})")
            continue
        if rb is None:
            lines.append(f"{name}: only in A — {ra['outcome']} ({ra['detail']})")
            continue
        if ra["outcome"] != rb["outcome"] or ra.get("cause") != rb.get("cause"):
            a_tag = f"{ra['outcome']}" + (f" [{ra['cause']}]" if ra.get("cause") else "")
            b_tag = f"{rb['outcome']}" + (f" [{rb['cause']}]" if rb.get("cause") else "")
            lines.append(f"{name}: A={a_tag} vs B={b_tag}\n    A: {ra['detail']}\n    B: {rb['detail']}")
    return lines


def cmd_diff(path_a: str, path_b: str) -> int:
    a, b = _load_results(path_a), _load_results(path_b)
    if a.get("schema_version") != b.get("schema_version"):
        print(f"warning: schema_version mismatch ({a.get('schema_version')} vs "
              f"{b.get('schema_version')}); fields may not align", file=sys.stderr)
    lines = diff_results(a, b)
    label_a, label_b = a.get("engine", path_a), b.get("engine", path_b)
    if not lines:
        print(f"no divergence between {label_a} ({path_a}) and {label_b} ({path_b}): "
              f"all {len(a.get('results', []))} checks agree")
        return 0
    print(f"divergences between {label_a} ({path_a}) and {label_b} ({path_b}):")
    for line in lines:
        print(f"  {line}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--proxy", default=DEFAULT_PROXY)
    parser.add_argument("--engine", choices=("pipelock", "smokescreen"), default=None)
    parser.add_argument("--backend-bin", default=None,
                        help="container backend binary (docker/container), for engine log capture")
    parser.add_argument("--container", default=None,
                        help="container name, paired with --backend-bin, for engine log capture")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true")
    mode.add_argument("--full", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--diff", nargs=2, metavar=("RESULTS_A", "RESULTS_B"),
                        help="compare two prior --json result files instead of running the suite")
    opts = parser.parse_args(argv)

    if opts.diff:
        return cmd_diff(opts.diff[0], opts.diff[1])
    if not opts.engine:
        parser.error("--engine is required unless --diff is given")

    results = run_suite(opts.proxy, opts.engine, full=opts.full,
                        backend_bin=opts.backend_bin, container=opts.container)
    if opts.as_json:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "engine": opts.engine, "proxy": opts.proxy,
                          "results": [asdict(r) for r in results]}, indent=2))
    else:
        print_text(results, opts.engine)
    return 1 if any(r.outcome in ("fail", "error") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
