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
    """Was the destination reached? — not "what status came back?".

    A refusal states itself two ways. A proxy that decides before
    acknowledging the tunnel answers 4xx, and the body says why. A proxy
    that decides afterwards has already sent `200` and can only abort
    (ProxyClient.tunnel_carried). Both refuse; only the first is legible.
    Grading the second a failure would report an enforcing proxy as a hole,
    so the tunnel itself is the evidence and the status line is not.
    """
    sock, status, detail = client.connect(target)
    if sock is None:
        if status is None:
            return "error", f"inconclusive transport failure: {detail}"
        return "pass", f"denied: {detail}"
    carried, why = client.tunnel_carried(sock)
    sock.close()
    if not carried:
        return "pass", f"denied after CONNECT: {why}"
    return "fail", f"tunnel to {target} was ESTABLISHED: {detail}"


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
    errors = [detail for outcome, detail in outcomes if outcome == "error"]
    if errors:
        return "error", "; ".join(errors)
    bad = [detail for outcome, detail in outcomes if outcome == "fail"]
    if bad:
        return "fail", "; ".join(bad)
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
    # Timed to the CONNECT response, so the grace period tunnel_carried()
    # spends on a live tunnel never lands in the recorded latency.
    elapsed = round((time.monotonic() - t0) * 1000, 1)
    if sock is None:
        outcome = "error" if status is None else "denied"
    else:
        carried, why = client.tunnel_carried(sock)
        sock.close()
        outcome = "established" if carried else "aborted"
        if not carried:
            detail = f"{detail} — {why}"
    # An aborted tunnel is a denial the engine stated no reason for, so the
    # cause is set here rather than left to the runner's text classifier.
    cause = "aborted-after-connect" if outcome == "aborted" else None
    return Attempt(n, target, local, outcome, status, elapsed, detail, cause)
