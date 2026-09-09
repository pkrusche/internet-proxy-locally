"""classify_denial() and aggregate_cause() — the denial-cause taxonomy
(docs/security.md)."""

from __future__ import annotations

import unittest
from typing import ClassVar

from internet_proxy_locally.checks.egress import denial
from internet_proxy_locally.checks.egress.models import Attempt


class ClassifyDenialTest(unittest.TestCase):
    def test_metadata(self) -> None:
        text = "denied by mock policy: destination is the cloud metadata endpoint"
        self.assertEqual(denial.classify_denial(text), "metadata")

    def test_sni_mismatch(self) -> None:
        text = "tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): mismatch"
        self.assertEqual(denial.classify_denial(text), "sni-mismatch")

    def test_non_tls_in_tunnel(self) -> None:
        text = (
            "tunnel established; connection closed with no response to raw (non-TLS) "
            "bytes — consistent with a non-TLS-in-tunnel policy check"
        )
        self.assertEqual(denial.classify_denial(text), "non-tls-in-tunnel")

    def test_private_ip(self) -> None:
        text = "denied by mock policy: destination resolves to a loopback address"
        self.assertEqual(denial.classify_denial(text), "private-ip")

    def test_aborted_after_connect(self) -> None:
        text = "denied after CONNECT: tunnel closed immediately after CONNECT, nothing carried"
        self.assertEqual(denial.classify_denial(text), "aborted-after-connect")

    def test_a_stated_reason_outranks_an_aborted_tunnel(self) -> None:
        """metadata-endpoint probes CONNECT *and* GET. On a bumping Squid
        only the GET half gets a page, and that half is the informative
        one — so the abort must never displace it."""
        text = (
            "CONNECT: denied after CONNECT: tunnel closed immediately after CONNECT, "
            "nothing carried; GET: denied: HTTP/1.1 403 Forbidden — SSRF blocked, the "
            "destination resolves to a cloud metadata endpoint."
        )
        self.assertEqual(denial.classify_denial(text), "metadata")

    def test_timeout(self) -> None:
        self.assertEqual(
            denial.classify_denial("connection error: timed out"), "timeout"
        )

    def test_hostname_not_allowlisted(self) -> None:
        text = (
            "HTTP/1.1 403 Forbidden — denied by mock policy: hostname not on allowlist"
        )
        self.assertEqual(denial.classify_denial(text), "hostname-not-allowlisted")

    def test_unknown_fallback(self) -> None:
        self.assertEqual(denial.classify_denial("connection reset by peer"), "unknown")


class ClassifyDenialRealWordingTest(unittest.TestCase):
    """Verbatim engine wording captured on 2026-08-19 (docs/findings.md).

    The invented strings in ClassifyDenialTest all classified correctly
    while the taxonomy was still keying on bare addresses and on the word
    "forbidden" — which is in every 403 line. These are the strings that
    caught it, so they are the ones worth pinning.
    """

    PIPELOCK: ClassVar[list[tuple[str, str]]] = [
        # A destination echoed back is not a reason: all of these are
        # allowlist denials even though the text contains a private address.
        (
            "HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 127.0.0.1",
            "hostname-not-allowlisted",
        ),
        (
            "HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1",
            "hostname-not-allowlisted",
        ),
        (
            "HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254",
            "hostname-not-allowlisted",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — CONNECT blocked: SSRF blocked: 10.0.0.1.nip.io "
                "resolves to internal IP 10.0.0.1"
            ),
            "private-ip",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — CONNECT blocked: SSRF blocked: fe80--1.sslip.io "
                "resolves to non-overridable internal IP fe80::1"
            ),
            "private-ip",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — CONNECT blocked: SSRF blocked: 169.254.169.254.nip.io "
                "resolves to cloud metadata endpoint 169.254.169.254"
            ),
            "metadata",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — CONNECT blocked: DNS lookup for "
                "01010101.7f000002.rbndr.us returned no such host"
            ),
            "dns-failure",
        ),
    ]

    SMOKESCREEN: ClassVar[list[tuple[str, str]]] = [
        (
            (
                "HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
                "'example.com:443': default rule policy used."
            ),
            "hostname-not-allowlisted",
        ),
        (
            (
                "HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
                "'127.0.0.1:80': default rule policy used."
            ),
            "hostname-not-allowlisted",
        ),
        (
            (
                "HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
                "'[fd00::1]:80': Destination host cannot be determined."
            ),
            "unparseable-destination",
        ),
        (
            (
                "HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
                "'10.0.0.1.nip.io:80': no valid IP found among resolved addresses - 10.0.0.1 "
                "denied by rule 'Deny: Private Range'. ."
            ),
            "private-ip",
        ),
        (
            (
                "HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
                "'fe80--1.sslip.io:80': no valid IP found among resolved addresses - fe80::1 "
                "denied by rule 'Deny: Not Global Unicast'. ."
            ),
            "private-ip",
        ),
        (
            (
                "HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host "
                '\'--1.sslip.io:80\': invalid domain "--1.sslip.io": idna: invalid label "--1".'
            ),
            "unparseable-destination",
        ),
        (
            (
                "HTTP/1.1 502 Bad gateway — Failed to resolve remote hostname: lookup "
                "01010101.7f000002.rbndr.us: no such host"
            ),
            "dns-failure",
        ),
    ]

    # Measured against real Squid 6.12 on 2026-08-25. The first four are
    # the custom `deny_info` pages in data/images/squid/errors, which exist so a
    # Squid denial states its cause the way the other two engines' do; the
    # last is Squid's own ERR_DNS_FAIL, which is not a policy verdict.
    SQUID: ClassVar[list[tuple[str, str]]] = [
        (
            (
                "HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
                "the destination is not in the allowlist."
            ),
            "hostname-not-allowlisted",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
                "SSRF blocked, the destination resolves to a private, loopback, link-local or "
                "otherwise non-public address."
            ),
            "private-ip",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
                "SSRF blocked, the destination resolves to a cloud metadata endpoint."
            ),
            "metadata",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
                "CONNECT to this port is not allowed, tunnels are permitted to port 443 only."
            ),
            "port-not-allowed",
        ),
        (
            (
                "HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: "
                "the destination is a bare IP address, and this proxy allowlists destinations by "
                "hostname only."
            ),
            "ip-literal-destination",
        ),
        (
            (
                "HTTP/1.1 503 Service Unavailable — ERROR: The requested URL could not be retrieved "
                "The following error was encountered while trying to retrieve the URL: "
                "https://01010101.7f000002.rbndr.us/* Unable to determine IP address from host name "
                "01010101.7f000002.rbndr.us The DNS server returned: Server Failure: The name server "
                "was unable to process this query."
            ),
            "dns-failure",
        ),
    ]

    def test_squid_wording(self) -> None:
        for text, expected in self.SQUID:
            with self.subTest(text=text[:60]):
                self.assertEqual(denial.classify_denial(text), expected)

    def test_pipelock_wording(self) -> None:
        for text, expected in self.PIPELOCK:
            with self.subTest(text=text[:60]):
                self.assertEqual(denial.classify_denial(text), expected)

    def test_smokescreen_wording(self) -> None:
        for text, expected in self.SMOKESCREEN:
            with self.subTest(text=text[:60]):
                self.assertEqual(denial.classify_denial(text), expected)

    def test_no_real_denial_is_unknown(self) -> None:
        for text, _ in self.PIPELOCK + self.SMOKESCREEN + self.SQUID:
            with self.subTest(text=text[:60]):
                self.assertNotEqual(denial.classify_denial(text), "unknown")


class AggregateCauseTest(unittest.TestCase):
    """A mixed attempt set must not report a minority reason (docs/security.md)."""

    @staticmethod
    def _attempt(n: int, cause: str) -> Attempt:
        return Attempt(
            n=n,
            target=f"t{n}",
            local_resolved=[],
            outcome="denied",
            status=403,
            elapsed_ms=1.0,
            detail="",
            cause=cause,
        )

    def test_uniform_attempts_report_that_cause(self) -> None:
        attempts = [self._attempt(i, "private-ip") for i in range(3)]
        self.assertEqual(denial.aggregate_cause("ignored", attempts), "private-ip")

    def test_mixed_attempts_report_every_cause(self) -> None:
        # The real dns-private-ipv4 shape: 3 private-IP + 1 metadata. Matching
        # the concatenated detail would have reported "metadata" alone.
        attempts = [self._attempt(i, "private-ip") for i in range(3)]
        attempts.append(self._attempt(3, "metadata"))
        self.assertEqual(
            denial.aggregate_cause("ignored", attempts), "metadata+private-ip"
        )

    def test_no_cause_when_attempts_exist_but_none_was_denied(self) -> None:
        established = Attempt(
            n=0,
            target="t",
            local_resolved=[],
            outcome="established",
            status=200,
            elapsed_ms=1.0,
            detail="HTTP/1.1 200 OK",
        )
        self.assertIsNone(
            denial.aggregate_cause(
                "the engine connected although 10.0.0.1 was in the answer set",
                [established],
            )
        )

    def test_falls_back_to_detail_without_attempts(self) -> None:
        self.assertEqual(
            denial.aggregate_cause(
                "denied by mock policy: hostname not on allowlist", []
            ),
            "hostname-not-allowlisted",
        )


if __name__ == "__main__":
    unittest.main()
