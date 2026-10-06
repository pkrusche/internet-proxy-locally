"""Talking to the endpoint: where it is, whether it is up, whether it works."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import time
from collections.abc import Callable
from http.client import HTTPException, HTTPResponse

from internet_proxy_locally.constants import DEFAULT_ENDPOINT


def validate_endpoint(
    host: str, port: int, *, loopback_only: bool = False
) -> tuple[str, int]:
    address = ipaddress.ip_address(host)
    if getattr(address, "scope_id", None):
        raise ValueError("scoped IPv6 addresses are not supported")
    if loopback_only and not address.is_loopback:
        raise ValueError("address must be loopback")
    if not 1 <= port <= 65535:
        raise ValueError("port must be 1..65535")
    return str(address), port


def endpoint(
    ip: str | None = None, port: int | None = None, *, loopback_only: bool = True
) -> tuple[str, int]:
    """Resolve CLI components over IPL_ENDPOINT over the shipped default.

    Lab callers retain loopback-only validation; operational callers explicitly
    allow other interfaces.
    """
    raw = os.environ.get("IPL_ENDPOINT", DEFAULT_ENDPOINT)
    host, sep, port_text = raw.rpartition(":")
    try:
        if (ip is None or port is None) and (not sep or not host or not port_text):
            raise ValueError("expected IP-address:port")
        return validate_endpoint(
            ip if ip is not None else host.removeprefix("[").removesuffix("]"),
            port if port is not None else int(port_text),
            loopback_only=loopback_only,
        )
    except ValueError as exc:
        raise ValueError(f"invalid endpoint (IPL_ENDPOINT {raw!r}): {exc}") from exc


def endpoint_text(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def probe_address(host: str) -> str:
    address = ipaddress.ip_address(host)
    if address.is_unspecified:
        return "::1" if address.version == 6 else "127.0.0.1"
    return host


def port_listening(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_proxy(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str, bool]:
    """Ask the proxy for a guaranteed-non-allowlisted host.

    Healthy means a 403 policy denial, or Smokescreen's 407 with an explicit
    default-policy denial for the probe. Authentication and resolution
    failures do not prove that the allowlist is enforced.

    Returns (healthy, detail, retryable). `retryable` marks a failure that
    only says the engine is not serving *yet* — no answer, or an answer that
    is not HTTP. Docker publishes the host port as soon as the container is
    created, so a connection can be accepted seconds before the engine
    listens behind it; those probes must be retried, not treated as verdicts.
    A proxy that answers and allows the probe is never retryable: it is
    enforcing nothing, and waiting longer cannot fix that.
    """
    request = (
        "GET http://ipl-health-probe.invalid/ HTTP/1.1\r\n"
        "Host: ipl-health-probe.invalid\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request.encode())
            with HTTPResponse(sock) as response:
                response.begin()
                status = response.status
                line = (
                    f"HTTP/{response.version // 10}.{response.version % 10} "
                    f"{status} {response.reason}"
                )
                smokescreen_denial = re.fullmatch(
                    r"Egress proxying is denied to host "
                    r"'ipl-health-probe\.invalid(?::80)?': default rule policy used\.",
                    response.getheader("X-Smokescreen-Error", ""),
                )
    except HTTPException as exc:
        return False, f"non-HTTP response: {exc}", True
    except OSError as exc:
        return False, f"no response from proxy: {exc}", True
    # Smokescreen uses 407 for ACL denials; the status alone could also be
    # an authentication challenge. Require its explicit policy reason.
    if status == 403 or (status == 407 and smokescreen_denial):
        return True, f"policy denies unknown destinations ({line.strip()})", False
    if status >= 400:
        return (
            False,
            f"non-policy error for unknown destination ({line.strip()})",
            False,
        )
    return (
        False,
        f"proxy allowed a non-allowlisted host ({line.strip()}) — NOT healthy",
        False,
    )


def wait_until(probe: Callable[[], object], timeout: float, interval: float = 0.5):
    """Poll `probe` until it returns something other than None, or time out.

    `None` is what "not yet" means, so a probe that wants to stop early —
    a container that has exited, a proxy that answered definitively — says
    so by returning its verdict, and gets the loop to end without waiting
    out a budget it already knows the answer to. On timeout the return is
    `None`, which is how the caller tells "gave up" from "decided".

    The engine health check and DNS fixture address poll share this so
    their timeout behavior stays consistent.
    """
    deadline = time.monotonic() + timeout
    while True:
        result = probe()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)
