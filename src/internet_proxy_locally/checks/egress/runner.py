"""The suite driver: run every check against every engine, attribute denial
causes, and capture the engine's log window for each result."""

from __future__ import annotations

import re
import socket
import subprocess
import time

from internet_proxy_locally.backend import log_command

from . import fixture_log
from .catalogue import TESTS
from .denial import aggregate_cause, classify_denial
from .models import Result, _normalize
from .transport import ProxyClient


def fixtures_active(client: ProxyClient) -> bool:
    """True when *.nip.io is allowlisted (test policy) — a public-IP nip.io
    name should then tunnel; under the normal policy it is hostname-denied."""
    sock, _status, _ = client.connect("1.1.1.1.nip.io:443")
    if sock is not None:
        sock.close()
        return True
    return False


FIXTURE_SKIP = (
    "test policy not active — run `ipl-lab up` "
    "to exercise DNS/SSRF fixtures, then re-run"
)


def _finalize(name: str, expectation: str, raw: tuple[str, str]) -> tuple[str, str]:
    """Map a test's raw outcome onto its expectation."""
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
    if after[: len(before)] == before:
        return after[len(before) :]
    return after


def _fetch_logs(
    backend_bin: str | None, container: str | None, *, required: bool = False
) -> list[str]:
    if not backend_bin or not container:
        return []
    try:
        proc = subprocess.run(
            log_command(backend_bin, container, None if required else 200),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if required:
            raise RuntimeError(
                f"cannot read fixture logs for {container}: {exc}"
            ) from exc
        return []
    if proc.returncode:
        if required:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"cannot read fixture logs for {container}: {detail}")
        return []
    return ((proc.stdout or "") + (proc.stderr or "")).splitlines()


def run_suite(
    proxy: str,
    engine: str,
    full: bool,
    backend_bin: str | None = None,
    container: str | None = None,
    fixture_container: str | None = None,
) -> list[Result]:
    match = re.match(r"(?:http://)?([^:/]+):(\d+)/?$", proxy)
    if not match:
        raise SystemExit(f"cannot parse proxy endpoint: {proxy}")
    client = ProxyClient(match.group(1), int(match.group(2)))

    try:
        with socket.create_connection((client.host, client.port), timeout=3):
            pass
    except OSError as exc:
        raise SystemExit(f"proxy endpoint {proxy} is not reachable: {exc}")

    old_fixture_source = fixture_log.FIXTURE_LOG_SOURCE
    if backend_bin and fixture_container:
        fixture_log.FIXTURE_LOG_SOURCE = lambda: _fetch_logs(
            backend_bin, fixture_container, required=True
        )

    have_fixtures = None
    results: list[Result] = []
    for check in TESTS:
        name, group, fn = check.name, check.group, check.fn
        needs_fixtures = check.needs_fixtures
        if group == "full" and not full:
            continue
        expectation = check.expectation
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
        except Exception as exc:  # noqa: BLE001 - a test must never kill the suite
            outcome, detail = "error", f"{type(exc).__name__}: {exc}"
            raw = _normalize((outcome, detail))
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        after_logs = _fetch_logs(backend_bin, container)
        for attempt in raw.attempts:
            if attempt.outcome == "denied" and attempt.cause is None:
                attempt.cause = classify_denial(attempt.detail)
        # Require attempt evidence to avoid classifying our own summary as a denial.
        gradable = outcome in ("pass", "fail", "record")
        cause = (
            aggregate_cause(detail, raw.attempts)
            if gradable and (expectation == "deny" or raw.attempts)
            else None
        )
        results.append(
            Result(
                name,
                group,
                expectation,
                outcome,
                detail,
                cause=cause,
                observed=observed,
                elapsed_ms=elapsed_ms,
                attempts=raw.attempts,
                headers=raw.headers,
                engine_logs=_log_delta(before_logs, after_logs),
            )
        )
    fixture_log.FIXTURE_LOG_SOURCE = old_fixture_source
    return results


def policy_in_use(results: list[Result]) -> str:
    """Which policy the engine was started with, read back off the results.

    The checker is not told; it can see it. Every fixture-dependent check
    skips with `FIXTURE_SKIP` under the real policy and runs under the test
    one, so the rows themselves say which was mounted. A `--quick` run has
    no such rows and reports `unknown` rather than guessing.
    """
    fixture_rows = [
        r for r in results if r.name in {c.name for c in TESTS if c.needs_fixtures}
    ]
    if not fixture_rows:
        return "unknown"
    if all(r.outcome == "skip" and r.detail == FIXTURE_SKIP for r in fixture_rows):
        return "real"
    return "test"
