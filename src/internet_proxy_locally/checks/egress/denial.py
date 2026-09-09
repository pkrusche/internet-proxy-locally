"""Classify stated denial reasons, never echoed targets or generic HTTP status text."""

from __future__ import annotations

import re

from .models import Attempt

# Ordered: more specific buckets first.
_TAXONOMY: list[tuple[str, re.Pattern]] = [
    # An engine that resolved the name and rejected the answer states so.
    ("metadata", re.compile(r"metadata", re.IGNORECASE)),
    (
        "sni-mismatch",
        re.compile(r"\bsni\b|unrecognized_name|domain.?fronting", re.IGNORECASE),
    ),
    (
        "non-tls-in-tunnel",
        re.compile(
            r"non-tls|non.?tls.?in.?tunnel|decode_error|"
            r"plain (http|bytes)|raw (protocol|bytes)",
            re.IGNORECASE,
        ),
    ),
    # Pipelock: "SSRF blocked: X resolves to internal IP".
    # Smokescreen: "no valid IP found among resolved addresses - 10.0.0.1
    # denied by rule 'Deny: Private Range'".
    (
        "private-ip",
        re.compile(
            r"\bssrf\b|private range|"
            r"no valid ip found among resolved|"
            r"resolves? to (a |an )?(non.?overridable )?"
            r"(internal|private|loopback|link.?local|reserved)|"
            r"(private|loopback|link.?local|rfc.?1918|reserved|internal)"
            r" (ip|address)",
            re.IGNORECASE,
        ),
    ),
    # Resolution never produced an answer: not a policy verdict at all.
    # Pipelock: "DNS lookup for X returned no such host".
    # Smokescreen: "502 Failed to resolve remote hostname: lookup X ...".
    # Squid: ERR_DNS_FAIL — "Unable to determine IP address from host name
    # X / The DNS server returned: Server Failure".
    (
        "dns-failure",
        re.compile(
            r"no such host|nxdomain|name or service not known|"
            r"dns lookup .*(failed|returned)|"
            r"(failed|unable) to resolve|"
            r"unable to determine ip address from host name|"
            r"the dns server returned",
            re.IGNORECASE,
        ),
    ),
    # Smokescreen rejects bracketed IPv6 literals before any policy applies
    # ("Destination host cannot be determined"), so its pass on the
    # private-IPv6 checks says nothing about private-IP defence. Kept as its
    # own bucket precisely so that row cannot be read as one.
    (
        "unparseable-destination",
        re.compile(
            r"destination host cannot be determined|"
            r"invalid domain|invalid label|\bidna\b|"
            r"could not parse (the )?(destination|host)",
            re.IGNORECASE,
        ),
    ),
    # Squid: "the destination is a bare IP address" (config/squid.conf
    # refuses address-form destinations so that `dstdomain` can never fall
    # back to a PTR lookup). Distinct from a plain allowlist miss, because
    # the point is that the name was never consulted.
    (
        "ip-literal-destination",
        re.compile(
            r"bare ip address|"
            r"allowlists? destinations by hostname",
            re.IGNORECASE,
        ),
    ),
    # Squid: "CONNECT to this port is not allowed" (config/squid.conf
    # restricts tunnels to 443). Not a hostname verdict — the destination
    # may well be allowlisted — so it gets its own bucket.
    (
        "port-not-allowed",
        re.compile(
            r"connect to this port|port .{0,20}not (allowed|permitted)|"
            r"unsafe port|disallowed port",
            re.IGNORECASE,
        ),
    ),
    ("timeout", re.compile(r"timed out|timeout", re.IGNORECASE)),
    # Smokescreen's default-deny ACL verdict is "default rule policy used".
    (
        "hostname-not-allowlisted",
        re.compile(
            r"not (on|in)( the)? allowlist|not.?allowlisted|"
            r"not.?whitelist|denied by (mock )?policy|"
            r"default rule policy|"
            r"no matching allow|blacklist",
            re.IGNORECASE,
        ),
    ),
    # Last, and the one bucket keyed on the checker's own words rather than
    # the engine's — because there are no engine words to read. A proxy
    # that refuses only after answering `200` cannot state a reason; it
    # aborts the tunnel, and "the tunnel carried nothing" is the whole of
    # the evidence (ProxyClient.tunnel_carried).
    #
    # Below every stated reason on purpose: whatever the engine did manage
    # to say is more informative than the abort. metadata-endpoint probes
    # CONNECT *and* GET, and on a bumping Squid only the GET half gets a
    # page — that half's `metadata` must still win the row.
    (
        "aborted-after-connect",
        re.compile(
            r"denied after connect|"
            r"tunnel (closed|reset) immediately after connect",
            re.IGNORECASE,
        ),
    ),
]


def classify_denial(text: str) -> str:
    for cause, pattern in _TAXONOMY:
        if pattern.search(text):
            return cause
    return "unknown"


def aggregate_cause(detail: str, attempts: list[Attempt]) -> str | None:
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
