"""Small probe helpers shared by several checks."""

from __future__ import annotations

import socket
import time

from .models import Attempt
from .transport import ProxyClient, summarize_body


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
    resp = client.http_get(url)
    if resp.status is None:
        return "error", f"inconclusive transport failure: {resp.first_line}"
    if resp.status < 400:
        return "fail", f"request succeeded ({resp.first_line})"
    body = summarize_body(resp.body)
    text = f"{resp.first_line} — {body}" if body else resp.first_line
    return "pass", f"denied: {text}"


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
