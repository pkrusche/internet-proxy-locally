#!/usr/bin/env python3
"""Common adversarial egress test suite for internet-proxy-locally.

Runs the same checks against any engine (Pipelock, Smokescreen or Squid)
through the stable proxy endpoint, and produces comparable results.

Stdlib only; Python 3.11+.

Groups:
  quick — ordinary allow/deny behavior (docs/policy.md)
  full  — quick + SSRF/DNS fixtures and CONNECT-abuse tests

The DNS fixture tests (nip.io / sslip.io, plus the local mixed-answer and
rebinding fixtures) only make sense when the *test* policy is mounted, which
is what `./lab.py up` does: the fixture hostnames must be allowlisted so
that a rejection can only come from the IP-layer SSRF protections, not from
ordinary hostname policy. The suite auto-detects whether the test policy is
active and skips those tests otherwise. `dns-mixed-answers` and
`dns-rebinding` additionally need the local DNS fixture container, which the
same command starts and points the engine's resolver at; each proves the
fixture is live — a control probe, and the fixture's own lookup log —
before grading anything.

Outcomes:
  pass   — behavior matched the expectation
  fail   — behavior violated the expectation
  record — engine behavior documented, no pass/fail defined (docs/findings.md)
  skip   — prerequisites missing (with reason)
  error  — the test itself could not run

Each result may carry: a best-effort denial `cause` classification, a
wall-clock `elapsed_ms`, per-attempt evidence (`attempts` — used by the
DNS fixtures), full response `headers` (allow-path checks), and the
engine's own log lines for that test's window (`--backend-bin`/
`--container`; `run.py check` and `lab.py check` wire this automatically).

`--diff A.json B.json` compares two prior `--json` runs and prints only
the rows that diverge, instead of running the suite.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict

DEFAULT_PROXY = "http://127.0.0.1:18080"
TIMEOUT = 8.0
# 2: the envelope carries the run's conditions (engine image, backend,
# which policy was mounted, host, timestamp) so that scripts/report.py can
# generate docs/findings.md from the result files alone, rather than from
# a table somebody remembered to update. v1 files still diff against v2
# ones — `--diff` only reads `results` — with a warning.
SCHEMA_VERSION = 2

ALLOWED_HTTP_HOST = "pypi.org"          # must be on the allowlist
ALLOWED_HTTPS_HOST = "pypi.org"         # must be on the allowlist
ALLOWED_ALT_HOST = "files.pythonhosted.org"  # allowlisted, used as mismatching SNI
BLOCKED_HOST = "example.com"            # must NOT be on the allowlist

# Mixed-answer fixture, served from lab/config/dns-fixture.hosts which
# `run.py ./lab.py up` mounts at /etc/hosts inside the engine
# container. The control resolves to one public address; the other two
# resolve to the same public address *and* a private one, in both
# orderings, so an engine that validates only the first answer fails one of
# them. Keep these names in sync with that file and with the test policies.
MIXED_FIXTURE_CONTROL = "public-only.fixture.test"
MIXED_FIXTURE_TARGETS = ("mixed-public-first.fixture.test",
                         "mixed-private-first.fixture.test")

# Rebinding fixture, served by the same container (lab/dnsfixture).
# The first A query for one of these names is answered with a public
# address and every later query with the fixture's own private address,
# where it listens as a trap. Each name is fresh, so no name can be served
# from a cache an earlier one warmed, and each is probed twice so that the
# second answer is actually handed out.
REBIND_ZONE = "rebind.fixture.test"
REBIND_NAMES = 3          # probed twice each, either side of REBIND_TTL_GAP
# The fixture answers with TTL 0, but a resolver cache keyed on a
# whole-second clock — Squid's ipcache is one — will still serve two
# probes issued in the same second from a single lookup, and the rebind
# never gets handed out. One pass over every name, a pause, then a second
# pass costs one gap for the whole check rather than one per name.
REBIND_TTL_GAP = 1.5

# Reverse-DNS fixture: the local resolver answers PTR for this address with
# an allowlisted hostname. Keep in sync with PTR_ADDRESS / PTR_CLAIMS in
# lab/dnsfixture/rebind.py. The address is public — so the SSRF floors
# stay out of it and the hostname allowlist really is the rule under test —
# and no other check connects to it.
PTR_FIXTURE_ADDRESS = "1.0.0.1"
PTR_FIXTURE_CLAIMS = "pypi.org"

# The fixture's log stream, set by run_suite when `run.py check` passes
# --fixture-container. Kept as a module-level hook so the rebinding test
# can read it without every test function growing a parameter, and so the
# unit tests can substitute a canned transcript.
FIXTURE_LOG_SOURCE: "callable" = lambda: []

# Engine-specific expectations for the CONNECT-abuse tests: Pipelock is
# expected to reject; Smokescreen and Squid behavior is recorded
# (docs/findings.md has the measured outcome — both allow both).
#
# Squid *can* inspect a tunnel, via `ssl_bump peek` + `splice`, but that
# configuration was built, measured and rejected: it crashes the daemon
# when a peeked connection must be terminated without a signing CA, and it
# answers every CONNECT with 200 before evaluating policy. See the header
# of config/squid.conf and docs/findings.md.
#
# `dns-mixed-answers` on Smokescreen is the third override and the one that
# is a policy call rather than a capability gap. Handed a name that
# resolves to one public and one private address, Smokescreen connects to
# the public one; docs/policy.md says such a name is rejected, so it
# deviates. It is graded `record` rather than `fail` because the row is
# still the same measurement either way and the grade was doing a job it
# cannot do: `./lab.py check` exited 1 on every Smokescreen run, so the exit
# code stopped distinguishing "this engine has a known, bounded deviation"
# from "something broke". Recording keeps the behavior in the report — the
# row says `RECORD established` with both answer orderings — and leaves the
# exit code meaning what it says. What it costs, and why the deviation is
# bounded, is docs/security.md, "Choosing an engine"; the measurement is
# docs/findings.md §2.
ENGINE_EXPECTATIONS = {
    "pipelock": {"connect-sni-mismatch": "deny", "connect-raw-tunnel": "deny"},
    "smokescreen": {"connect-sni-mismatch": "record", "connect-raw-tunnel": "record",
                    "dns-mixed-answers": "record"},
    "squid": {"connect-sni-mismatch": "record", "connect-raw-tunnel": "record"},
}

ENGINES = tuple(ENGINE_EXPECTATIONS)


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
    # What the engine actually did, for checks that report behavior rather
    # than grading themselves: "allowed" or "denied". A `record` grade says
    # only that no verdict is defined, so without this the result file would
    # not say which way the engine went — which is the entire content of a
    # recorded row.
    observed: str | None = None
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
    # Squid: ERR_DNS_FAIL — "Unable to determine IP address from host name
    # X / The DNS server returned: Server Failure".
    ("dns-failure", re.compile(r"no such host|nxdomain|name or service not known|"
                                r"dns lookup .*(failed|returned)|"
                                r"(failed|unable) to resolve|"
                                r"unable to determine ip address from host name|"
                                r"the dns server returned", re.I)),
    # Smokescreen rejects bracketed IPv6 literals before any policy applies
    # ("Destination host cannot be determined"), so its pass on the
    # private-IPv6 checks says nothing about private-IP defence. Kept as its
    # own bucket precisely so that row cannot be read as one.
    ("unparseable-destination", re.compile(r"destination host cannot be determined|"
                                            r"invalid domain|invalid label|\bidna\b|"
                                            r"could not parse (the )?(destination|host)", re.I)),
    # Squid: "the destination is a bare IP address" (config/squid.conf
    # refuses address-form destinations so that `dstdomain` can never fall
    # back to a PTR lookup). Distinct from a plain allowlist miss, because
    # the point is that the name was never consulted.
    ("ip-literal-destination", re.compile(r"bare ip address|"
                                           r"allowlists? destinations by hostname", re.I)),
    # Squid: "CONNECT to this port is not allowed" (config/squid.conf
    # restricts tunnels to 443). Not a hostname verdict — the destination
    # may well be allowlisted — so it gets its own bucket.
    ("port-not-allowed", re.compile(r"connect to this port|port .{0,20}not (allowed|permitted)|"
                                     r"unsafe port|disallowed port", re.I)),
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
        if attempts:
            # Per-attempt evidence exists and nothing was denied, so there
            # is no denial to attribute. Falling through to the text would
            # classify the checker's *own* summary — which is how a failing
            # dns-mixed-answers row came to be labelled `private-ip` for
            # saying the words "a private address" (docs/security.md: never
            # classify a reason word the checker wrote).
            return None
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
        body = summarize_body(extra.decode("latin-1", "replace"))
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
    body = summarize_body(resp.body)
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


FIXTURE_SKIP = ("test policy not active — run `./lab.py up` "
                "to exercise DNS/SSRF fixtures, then re-run")


def _connect_attempt(client: ProxyClient, n: int, target: str, host_for_resolution: str,
                     resolve: bool = True) -> Attempt:
    """One CONNECT probe. `resolve=False` skips the checker's own lookup —
    used for fixture names that exist only inside the engine's container,
    where the lookup can only ever NXDOMAIN after a timeout."""
    local = resolve_locally(host_for_resolution) if resolve else []
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


def _rebind_name(index: int, token: str) -> str:
    """A name unique to this run.

    The fixture counts lookups per name and hands out the private address
    from the second onward, so a name reused by a later `check` would start
    its life already rebound and the first probe would be graded against
    the wrong answer. The fixture container outlives individual check runs,
    so the token cannot be dropped.
    """
    return f"a{index}-{token}.{REBIND_ZONE}"


def parse_fixture_log(lines: "list[str]") -> "tuple[dict[str, list[str]], list[str]]":
    """Split the fixture's `IPL-FIXTURE` lines into (answers, trap hits).

    `answers` maps each queried name to the addresses handed out, in order,
    so the number of entries is the number of times the engine resolved
    that name. `trap` holds one entry per connection that reached the
    fixture's private address — each of which is a rebind followed through.
    """
    answers: dict[str, list[str]] = {}
    trap: list[str] = []
    for line in lines:
        if "IPL-FIXTURE" not in line:
            continue
        body = line.split("IPL-FIXTURE", 1)[1].strip()
        fields = dict(part.split("=", 1) for part in body.split() if "=" in part)
        if body.startswith("dns ") and "name" in fields and "answer" in fields:
            answers.setdefault(fields["name"], []).append(fields["answer"])
        elif body.startswith("trap connect"):
            trap.append(fields.get("from", "?"))
    return answers, trap


def test_dns_rebind(client: ProxyClient) -> RawOutcome:
    """The engine must never connect to an address it was handed *after*
    validating a different one.

    Each name is probed twice. The fixture answers the first lookup with a
    public address and every later lookup with its own private address, on
    which it listens. So the second probe is a genuine rebind: whatever the
    engine does there, it does knowing only what its resolver just told it.
    An engine that re-resolves and re-validates refuses. An engine that
    re-resolves and forgets to re-validate arrives at the trap, and the
    fixture reports it.

    Probing twice, with a pause between the passes, is the point. A single
    probe per name never causes the private answer to be handed out at all,
    so the trap could not fire even against a vulnerable engine and the row
    would pass while testing nothing — the failure mode that made
    `dns-private-ipv6` vacuous for two measurement rounds
    (docs/findings.md, "Corrections to earlier runs"). Two probes in the
    same second are no
    better against a resolver cache with second granularity, which is why
    the passes are separated rather than interleaved.

    **Only the trap decides the grade.** A second probe that establishes
    with the trap silent is not a failure: it means the engine connected to
    the public address it had already validated, which is the safe way to
    resist rebinding. Both behaviors are recorded in the detail, because
    they are different designs and the difference is worth seeing.

    This replaced `rbndr.us`, which stopped resolving in 2026-08 and had
    always been ungradable: it answered each query with one of its two
    addresses at random, so nothing the checker observed could attribute
    what the engine did (docs/findings.md, "DNS rebinding").
    """
    _, before_trap = parse_fixture_log(FIXTURE_LOG_SOURCE())
    token = os.urandom(3).hex()
    names = [_rebind_name(i, token) for i in range(REBIND_NAMES)]

    attempts: list[Attempt] = []
    for name in names:
        attempts.append(_connect_attempt(client, len(attempts), f"{name}:443",
                                         name, resolve=False))
    time.sleep(REBIND_TTL_GAP)
    for name in names:
        attempts.append(_connect_attempt(client, len(attempts), f"{name}:443",
                                         name, resolve=False))

    answers, trap = parse_fixture_log(FIXTURE_LOG_SOURCE())
    # The names are unique to this run, so their answers need no delta;
    # trap hits accumulate in a long-lived container and do.
    trap = trap[len(before_trap):]
    ours = {name: answers.get(name, []) for name in names}
    lookups = sum(len(seen) for seen in ours.values())
    if not lookups:
        return RawOutcome("skip", (
            f"the DNS fixture reported no lookups for *.{REBIND_ZONE} — it is not "
            "running, the engine is not resolving through it, or its log stream is not "
            "readable from here. Run `./lab.py up` and `./run.py check "
            "--full`, which wires the fixture's container through automatically"),
            attempts=attempts)

    for attempt in attempts:
        attempt.local_resolved = list(ours.get(attempt.target.rsplit(":", 1)[0], []))

    if trap:
        return RawOutcome("fail", (
            f"{len(trap)} connection(s) reached the fixture's private address "
            f"(from {', '.join(sorted(set(trap)))}) after a repeat lookup handed it "
            "over — the engine followed a rebind instead of re-validating"),
            attempts=attempts)

    # No trap hits: say why, because "never offered the rebind" and
    # "offered it and refused" are very different amounts of evidence.
    rebound = [name for name, seen in ours.items() if len(seen) > 1]
    second_probes = attempts[REBIND_NAMES:]
    established = sum(1 for a in second_probes if a.outcome == "established")
    detail = (f"no connection reached the trap. {len(rebound)}/{REBIND_NAMES} names were "
              f"resolved more than once and so were handed the private address "
              f"({lookups} lookups total); of the {len(second_probes)} repeat probes, "
              f"{len(second_probes) - established} were denied and {established} "
              "established")
    if not rebound:
        detail += (" — but the engine resolved each name only once, so it was never "
                   "offered the rebind and this run did not exercise one")
    elif established:
        detail += (" — an established repeat probe with a silent trap means the engine "
                   "reused the address it had already validated rather than following "
                   "the new answer")
    return RawOutcome("pass", detail, attempts=attempts)


def test_ptr_allowlist(client: ProxyClient) -> RawOutcome:
    """A bare address must not inherit an allowlisted name through its PTR
    record.

    Squid resolves `dstdomain` with a documented fallback: "a reverse
    lookup is tried if a IP based URL is used and no match is found". PTR
    records belong to whoever holds the address block and Squid does not
    forward-confirm them, so an agent exfiltrating to a host its operator
    controls only has to point that host's PTR at an allowlisted name.
    Measured before the fix: `CONNECT 1.1.1.1:443` was allowed under the
    real policy while `CONNECT 9.9.9.9:443` was refused, the PTR record
    being the only difference (docs/findings.md).

    The local fixture answers PTR for `PTR_FIXTURE_ADDRESS` with
    `PTR_FIXTURE_CLAIMS`, which is on the allowlist. The destination is an
    address, so no forward lookup is involved and the only way to reach it
    is through that fallback.

    Whether the engine actually asked is recorded but not graded. Pipelock
    and Smokescreen never reverse-resolve, and a correctly configured Squid
    refuses address-form destinations before any `dstdomain` rule is
    reached — so on a healthy engine no PTR query is expected, and the
    detail says as much rather than implying a fallback was survived.
    """
    fixture_lines = FIXTURE_LOG_SOURCE()
    if not any("IPL-FIXTURE" in line for line in fixture_lines):
        return RawOutcome("skip", (
            "the local DNS fixture is not observable from here, so the PTR claim "
            f"for {PTR_FIXTURE_ADDRESS} cannot be known to be live. Run "
            "`./lab.py up` and `./lab.py check`, which wires "
            "the fixture's container through automatically"))

    target = f"{PTR_FIXTURE_ADDRESS}:443"
    attempt = _connect_attempt(client, 0, target, PTR_FIXTURE_ADDRESS, resolve=False)
    asked = _ptr_queries(FIXTURE_LOG_SOURCE(), PTR_FIXTURE_ADDRESS) - \
        _ptr_queries(fixture_lines, PTR_FIXTURE_ADDRESS)

    if attempt.outcome == "established":
        return RawOutcome("fail", (
            f"{target} was reached even though only {PTR_FIXTURE_CLAIMS} is "
            f"allowlisted — the address inherited an allowlisted name from its "
            f"reverse record"), attempts=[attempt])

    detail = f"denied: {attempt.detail}"
    detail += (f"; the engine made {asked} reverse lookup(s) for it and refused anyway"
               if asked else
               "; the engine performed no reverse lookup, so the allowlist was never "
               "offered the PTR name")
    return RawOutcome("pass", detail, attempts=[attempt])


def _ptr_queries(lines: "list[str]", address: str) -> int:
    """How many PTR lookups for `address` the fixture logged. dnsmasq's
    `--log-queries` writes `query[PTR] <reversed>.in-addr.arpa from ...`."""
    reversed_name = ".".join(reversed(address.split("."))) + ".in-addr.arpa"
    return sum(1 for line in lines if "query[PTR]" in line and reversed_name in line)


def test_dns_mixed(client: ProxyClient) -> RawOutcome:
    """An allowlisted name resolving to a public *and* a private address
    must be refused, in both answer orderings.

    This is the one check whose fixture cannot come from public DNS, so it
    is manufactured in lab/config/dns-fixture.hosts, served by the dnsmasq
    container `./lab.py up` starts. The control probe is what makes the result
    attributable: it resolves to the same public address as the mixed names
    and nothing else, so if it does not establish, the fixture is missing,
    unallowlisted or unreachable and a denial below would prove nothing.
    The row skips in that case rather than banking an unearned pass.

    Local resolution is deliberately not attempted — the names exist only
    inside the engine's container — so `local_resolved` is empty on every
    attempt here by design, not by failure.
    """
    control = _connect_attempt(client, 0, f"{MIXED_FIXTURE_CONTROL}:443",
                               MIXED_FIXTURE_CONTROL, resolve=False)
    if control.outcome != "established":
        return RawOutcome("skip", (
            f"control probe to {MIXED_FIXTURE_CONTROL} did not establish "
            f"({control.detail}) — the mixed-answer fixture is not mounted, not "
            "allowlisted, or its public address is unreachable from here. Run "
            "`./lab.py up`, which serves lab/config/dns-fixture.hosts, "
            "and re-run"), attempts=[control])

    attempts = [control]
    attempts += [_connect_attempt(client, i, f"{name}:443", name, resolve=False)
                 for i, name in enumerate(MIXED_FIXTURE_TARGETS, start=1)]
    established = [a for a in attempts[1:] if a.outcome == "established"]
    if established:
        # Behavioral, not graded: `_finalize` maps it through the engine's
        # expectation, because Smokescreen's deviation here is recorded
        # rather than failed (ENGINE_EXPECTATIONS).
        #
        # Deliberately phrased without a taxonomy reason word: this detail
        # is fed to classify_denial(), and nothing here was denied.
        return RawOutcome("allowed", "; ".join(
            f"{a.target} established — the engine connected although a private address "
            "was in the answer set" for a in established), attempts=attempts)
    return RawOutcome("denied", (
        f"control {MIXED_FIXTURE_CONTROL} established, and both mixed-answer names "
        "(public-first and private-first) were denied — every address in the answer set "
        "is validated, not only the first one or the routable one"), attempts=attempts)


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
    ("dns-rebinding",        "full",  "deny",   test_dns_rebind,           True),
    ("dns-mixed-answers",    "full",  "deny",   test_dns_mixed,            True),
    ("ptr-allowlist",        "full",  "deny",   test_ptr_allowlist,        True),
    ("connect-sni-mismatch", "full",  "record", test_sni_mismatch,         False),
    ("connect-raw-tunnel",   "full",  "record", test_raw_tunnel,           False),
    ("concurrency-sanity",   "full",  "record", test_concurrency,          False),
]

# What each check asks, in one sentence — the question, not the verdict.
#
# It lives here rather than in the report generator because the question is
# a property of the check: whoever changes what a check does is the person
# who has to restate what it asks. scripts/report.py prints these above the
# measured outcomes so that docs/findings.md can be generated whole,
# instead of pairing generated rows with a hand-written key that drifts.
# A test asserts every check has one and that nothing here is orphaned.
CHECK_PURPOSE = {
    "allowed-http": "A plain-HTTP GET to an allowlisted host reaches it.",
    "allowed-https": "A CONNECT tunnel to an allowlisted host completes a real TLS "
                     "handshake, so ordinary HTTPS works through the proxy.",
    "blocked-host-connect": "CONNECT to a host that is not on the allowlist is refused "
                            "— the default-deny rule, on the tunnel path.",
    "blocked-host-http": "A plain-HTTP GET to a host that is not on the allowlist is "
                         "refused — the same rule on the request path.",
    "direct-ip-connect": "A destination written as a bare address is refused. Under a "
                         "hostname allowlist it can only ever be denied; which rule "
                         "denies it is what the cause column shows.",
    "loopback-ipv4": "CONNECT to 127.0.0.1 is refused.",
    "rfc1918-ipv4": "CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is refused.",
    "link-local-ipv4": "CONNECT to 169.254.0.0/16 is refused.",
    "metadata-endpoint": "The cloud metadata address is refused over both CONNECT and "
                         "plain HTTP.",
    "loopback-ipv6": "CONNECT to [::1] is refused.",
    "private-ipv6": "CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is refused.",
    "dns-private-ipv4": "An *allowlisted* name that resolves to a private IPv4 address "
                        "is refused, so the denial can only have come from validating "
                        "the resolved address (nip.io).",
    "dns-private-ipv6": "The same, for IPv6 (sslip.io).",
    "dns-rebinding": "A name whose answer changes between the first lookup and the "
                     "next does not get the engine to a private address. Graded on "
                     "whether the fixture's trap was reached, not on counts.",
    "dns-mixed-answers": "A name resolving to a public *and* a private address is "
                         "refused, in both answer orderings — every address in the "
                         "answer set is validated, not just the first or the routable "
                         "one.",
    "ptr-allowlist": "An address whose PTR record claims an allowlisted hostname is "
                     "still refused, so a reverse lookup cannot satisfy the allowlist.",
    "connect-sni-mismatch": "What the engine does when a tunnel to one allowlisted host "
                            "carries a ClientHello for another: enforcement inside the "
                            "tunnel, or none.",
    "connect-raw-tunnel": "What the engine does when a tunnel to an allowlisted host on "
                          "443 carries plaintext rather than TLS.",
    "concurrency-sanity": "Ten simultaneous CONNECTs to an allowed host all succeed — "
                          "the proxy is not serializing or dropping under trivial load.",
}


def check_purpose(name: str) -> str:
    return CHECK_PURPOSE.get(name, "")


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
             backend_bin: str | None = None, container: str | None = None,
             fixture_container: str | None = None) -> list[Result]:
    match = re.match(r"(?:http://)?([^:/]+):(\d+)/?$", proxy)
    if not match:
        raise SystemExit(f"cannot parse proxy endpoint: {proxy}")
    client = ProxyClient(match.group(1), int(match.group(2)))

    try:
        with socket.create_connection((client.host, client.port), timeout=3):
            pass
    except OSError as exc:
        raise SystemExit(f"proxy endpoint {proxy} is not reachable: {exc}")

    global FIXTURE_LOG_SOURCE
    if backend_bin and fixture_container:
        FIXTURE_LOG_SOURCE = lambda: _fetch_logs(backend_bin, fixture_container)

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
        observed = None
        try:
            raw = _normalize(fn(client))
            observed = raw.outcome if raw.outcome in ("allowed", "denied") else None
            outcome, detail = _finalize(name, expectation, (raw.outcome, raw.detail))
        except Exception as exc:  # a test must never take down the suite
            outcome, detail = "error", f"{type(exc).__name__}: {exc}"
            raw = RawOutcome(outcome, detail)
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        after_logs = _fetch_logs(backend_bin, container)
        for attempt in raw.attempts:
            if attempt.outcome == "denied" and attempt.cause is None:
                attempt.cause = classify_denial(attempt.detail)
        # A recorded row still deserves its reason when there is one to
        # attribute — that is the whole content of a `record` grade. Only
        # per-attempt evidence qualifies there: without it `aggregate_cause`
        # falls back to matching the checker's own summary, which on a row
        # nothing denied would invent a cause (docs/security.md).
        gradable = outcome in ("pass", "fail", "record")
        cause = (aggregate_cause(detail, raw.attempts)
                 if gradable and (expectation == "deny" or raw.attempts) else None)
        results.append(Result(name, group, expectation, outcome, detail,
                              cause=cause, observed=observed, elapsed_ms=elapsed_ms,
                              attempts=raw.attempts, headers=raw.headers,
                              engine_logs=_log_delta(before_logs, after_logs)))
    return results


def policy_in_use(results: list[Result]) -> str:
    """Which policy the engine was started with, read back off the results.

    The checker is not told; it can see it. Every fixture-dependent check
    skips with `FIXTURE_SKIP` under the real policy and runs under the test
    one, so the rows themselves say which was mounted. A `--quick` run has
    no such rows and reports `unknown` rather than guessing.
    """
    fixture_rows = [r for r in results
                    if r.name in {name for name, _, _, _, needs in TESTS if needs}]
    if not fixture_rows:
        return "unknown"
    if all(r.outcome == "skip" and r.detail == FIXTURE_SKIP for r in fixture_rows):
        return "real"
    return "test"


def envelope(results: list[Result], engine: str, proxy: str, full: bool,
             backend: str | None = None, image: str | None = None) -> dict:
    """The `--json` document: the results plus the conditions they were
    measured under, which is what scripts/report.py generates
    docs/findings.md from."""
    return {
        "schema_version": SCHEMA_VERSION,
        "engine": engine,
        "proxy": proxy,
        "mode": "full" if full else "quick",
        "backend": backend or None,
        "image": image or None,
        "policy": policy_in_use(results),
        "host": f"{platform.system()} {platform.release()} {platform.machine()}",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "exit_code": 1 if any(r.outcome in ("fail", "error") for r in results) else 0,
        "results": [asdict(r) for r in results],
    }


def print_text(results: list[Result], engine: str) -> None:
    width = max(len(r.name) for r in results)
    print(f"egress checks — engine: {engine}")
    for r in results:
        extra = f" [{r.cause}]" if r.cause else ""
        if r.outcome == "record" and r.observed:
            extra = f" ({r.observed})" + extra
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
    parser.add_argument("--engine", choices=ENGINES, default=None)
    parser.add_argument("--backend-bin", default=None,
                        help="container backend binary (docker/container), for engine log capture")
    parser.add_argument("--container", default=None,
                        help="container name, paired with --backend-bin, for engine log capture")
    parser.add_argument("--fixture-container", default=None,
                        help="DNS fixture container name, paired with --backend-bin; "
                             "dns-rebinding grades on what the fixture observed")
    parser.add_argument("--image", default=None,
                        help="the engine image reference, recorded in --json output so "
                             "a result file says what it measured (run.py check passes it)")
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
                        backend_bin=opts.backend_bin, container=opts.container,
                        fixture_container=opts.fixture_container)
    if opts.as_json:
        print(json.dumps(envelope(results, opts.engine, opts.proxy, full=opts.full,
                                  backend=opts.backend_bin, image=opts.image), indent=2))
    else:
        print_text(results, opts.engine)
    return 1 if any(r.outcome in ("fail", "error") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
