"""Rendering a suite run as JSON or text."""

from __future__ import annotations

import platform
import time
from dataclasses import asdict

from .models import Result
from .runner import policy_in_use

# 3: adds `tls_interception` to the run's conditions (was 2: the envelope
# carries the run's conditions — engine image, backend, which policy was
# mounted, host, timestamp — so that `report` can generate
# docs/findings.md from the result files alone, rather than from a table
# somebody remembered to update).
SCHEMA_VERSION = 3


def exit_code(results: list[Result], strict: bool = False) -> int:
    """Grades are findings; errors (and strict-mode skips) fail execution."""
    bad = {"error", "skip"} if strict else {"error"}
    return int(any(r.outcome in bad for r in results))


def envelope(
    results: list[Result],
    engine: str,
    proxy: str,
    full: bool,
    backend: str | None = None,
    image: str | None = None,
    tls_interception: bool = False,
    strict: bool = False,
) -> dict:
    """The `--json` document: the results plus the conditions they were
    measured under, which is what `report` generates
    docs/findings.md from."""
    return {
        "schema_version": SCHEMA_VERSION,
        "engine": engine,
        "proxy": proxy,
        "mode": "full" if full else "quick",
        "backend": backend or None,
        "image": image or None,
        "policy": policy_in_use(results),
        "tls_interception": tls_interception,
        "host": f"{platform.system()} {platform.release()} {platform.machine()}",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "exit_code": exit_code(results, strict=strict),
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
        print(
            f"  {r.name:<{width}}  [{r.expectation:^6}]  {r.outcome.upper():<6}{extra}{timing}{attempts}  {r.detail}"
        )
    counts: dict[str, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    print(f"summary: {summary}")
