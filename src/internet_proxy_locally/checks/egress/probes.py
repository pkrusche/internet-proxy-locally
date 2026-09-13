"""Small probe helpers shared by several checks."""

from __future__ import annotations

import re
import socket
import time
from urllib.parse import urlsplit

from .models import Attempt, RawOutcome
from .transport import HttpResponse, ProxyClient, summarize_body


def resolve_locally(host: str) -> list[str]:
    """What *this* process resolves `host` to, right now. Best-effort:
    empty on any resolution failure (offline, NXDOMAIN, fixture down)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


def _classify_deny_connect(client: ProxyClient, target: str) -> tuple[str, str]:
    """Require an active exchange rather than treating CONNECT 200 as access."""
    sock, status, detail = client.connect(target)
    if sock is None:
        if status is None or not 400 <= status < 500:
            return "error", f"inconclusive transport failure: {detail}"
        return "pass", f"denied: {detail}"
    carried, why = client.tunnel_carried(sock, target)
    sock.close()
    if carried is None:
        return "error", why
    if not carried:
        return "pass", why
    return "fail", f"tunnel to {target} carried traffic: {why}"


def _classify_deny_http(client: ProxyClient, url: str) -> tuple[str, str]:
    return _classify_http_response(client.http_get(url), url)


def _classify_http_response(resp: HttpResponse, url: str) -> tuple[str, str]:
    if resp.status is None:
        return "error", f"inconclusive transport failure: {resp.first_line}"
    if 200 <= resp.status < 400:
        return "fail", f"request succeeded ({resp.first_line})"
    body = summarize_body(resp.body)
    text = f"{resp.first_line} — {body}" if body else resp.first_line
    headers = {k.lower(): v for k, v in resp.headers.items()}
    host = urlsplit(url).hostname or ""
    marker = "internet-proxy-locally denied this request: "
    squid = body.startswith((marker, f"403 Forbidden {marker}")) or (
        headers.get("x-squid-error", "").split()[:1] == ["ERR_ACCESS_DENIED"]
    )
    pipelock = body == f"blocked: domain not in allowlist: {host}"
    smokescreen = re.fullmatch(
        rf"Egress proxying is denied to host '{re.escape(host)}(?::80)?': "
        r"default rule policy used\.",
        headers.get("x-smokescreen-error", ""),
    )
    if (resp.status == 403 and (squid or pipelock)) or (
        resp.status == 407 and smokescreen
    ):
        return "pass", f"denied: {text}"
    return "error", f"inconclusive HTTP response: {text}"


def _http_attempt(client: ProxyClient, url: str, *, n: int = 0) -> Attempt:
    started = time.monotonic()
    response = client.http_get(url)
    outcome, detail = _classify_http_response(response, url)
    return Attempt(
        n,
        url,
        [],
        {"pass": "denied", "fail": "established", "error": "error"}[outcome],
        response.status,
        round((time.monotonic() - started) * 1000, 1),
        detail,
    )


def _deny_attempts(attempts: list[Attempt]) -> RawOutcome:
    if any(a.outcome == "established" for a in attempts):
        outcome = "fail"
    elif all(a.outcome == "denied" for a in attempts):
        outcome = "pass"
    else:
        outcome = "error"
    return RawOutcome(
        outcome, "; ".join(f"{a.target}: {a.detail}" for a in attempts), attempts
    )


def _deny_all(client: ProxyClient, *targets: str) -> tuple[str, str]:
    """Every one of `targets` must be refused; report the ones that were not.

    A whole address family is one check, not one per address, so a partial
    floor — 10/8 denied but 172.16/12 allowed — reads as a failure rather
    than as two results that have to be compared by eye.
    """
    outcomes = [_classify_deny_connect(client, target) for target in targets]
    bad = [detail for outcome, detail in outcomes if outcome == "fail"]
    if bad:
        return "fail", "; ".join(bad)
    errors = [detail for outcome, detail in outcomes if outcome == "error"]
    if errors:
        return "error", "; ".join(errors)
    return "pass", "; ".join(detail for _, detail in outcomes)


def _connect_attempt(
    client: ProxyClient,
    n: int,
    target: str,
    host_for_resolution: str,
    resolve: bool = True,
) -> Attempt:
    """One CONNECT probe. `resolve=False` skips the checker's own lookup —
    used for fixture names that exist only inside the engine's container,
    where the lookup can only ever NXDOMAIN after a timeout."""
    local = resolve_locally(host_for_resolution) if resolve else []
    t0 = time.monotonic()
    sock, status, detail = client.connect(target)
    if sock is None:
        outcome = "error" if status is None or not 400 <= status < 500 else "denied"
    else:
        carried, why = client.tunnel_carried(sock, target)
        sock.close()
        outcome = "error" if carried is None else "established" if carried else "denied"
        detail = f"{detail} — {why}"
    elapsed = round((time.monotonic() - t0) * 1000, 1)
    return Attempt(n, target, local, outcome, status, elapsed, detail)
