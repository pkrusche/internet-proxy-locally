"""Talking to the endpoint: where it is, whether it is up, whether it works.

`probe_proxy` is the interesting one. It does not ask whether something is
listening — it asks whether what is listening is a proxy enforcing a
default-deny policy, by requesting a host that cannot be allowlisted. A 2xx
is a failure, not a success.
"""

from __future__ import annotations

import os
import re
import socket
import time

from internet_proxy_locally.constants import DEFAULT_ENDPOINT


def endpoint() -> tuple[str, int]:
    """Host endpoint; IPL_ENDPOINT override exists for the test suite only."""
    raw = os.environ.get("IPL_ENDPOINT", DEFAULT_ENDPOINT)
    host, _, port = raw.rpartition(":")
    return host, int(port)


def port_listening(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_proxy(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str, bool]:
    """Ask the proxy for a guaranteed-non-allowlisted host.

    Healthy means: the proxy answers with an HTTP error (policy denial or
    resolution failure). A 2xx/3xx would mean the proxy is not enforcing at
    all, which we refuse to call healthy (fail closed).

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
            data = sock.recv(4096)
    except OSError as exc:
        return False, f"no response from proxy: {exc}", True
    line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace") if data else ""
    match = re.match(r"HTTP/\d\.\d\s+(\d{3})", line)
    if not match:
        return False, f"non-HTTP response: {line!r}", True
    status = int(match.group(1))
    if status >= 400:
        return True, f"denies unknown destinations ({line.strip()})", False
    return (
        False,
        f"proxy allowed a non-allowlisted host ({line.strip()}) — NOT healthy",
        False,
    )


def wait_until(probe: callable, timeout: float, interval: float = 0.5):
    """Poll `probe` until it returns something other than None, or time out.

    `None` is what "not yet" means, so a probe that wants to stop early —
    a container that has exited, a proxy that answered definitively — says
    so by returning its verdict, and gets the loop to end without waiting
    out a budget it already knows the answer to. On timeout the return is
    `None`, which is how the caller tells "gave up" from "decided".

    This was three loops before: the engine health check, the DNS fixture's
    address poll, and the resilience script's settle wait. They had three
    different sleep intervals and no reason for any of them to differ.
    """
    deadline = time.monotonic() + timeout
    while True:
        result = probe()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)
