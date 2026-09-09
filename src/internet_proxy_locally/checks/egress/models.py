"""The data model shared by every check: what a probe records, and what a
check reports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Attempt:
    """One probe within a multi-target check (e.g. dns-rebinding)."""

    n: int
    target: str
    local_resolved: list[str]  # IPs the checker itself resolved, if any
    # "established" | "denied" | "aborted" | "error". `aborted` is a
    # denial the engine only reached after answering `200`, so it could
    # not send a reason and tore the tunnel down instead — the deny checks
    # count it as a refusal, and it keeps its own name so a row cannot be
    # read as a legible 4xx (probes.py, ProxyClient.tunnel_carried).
    outcome: str
    status: int | None
    elapsed_ms: float
    detail: str
    cause: str | None = None  # filled in by the runner for denied attempts


@dataclass
class Result:
    name: str
    group: str  # "quick" | "full"
    expectation: str  # "allow" | "deny" | "record"
    outcome: str  # "pass" | "fail" | "record" | "skip" | "error"
    detail: str
    cause: str | None = None  # best-effort denial classification
    # Preserve allowed/denied behavior even when the grade is record.
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


def _normalize(raw: tuple[str, str] | RawOutcome) -> RawOutcome:
    if isinstance(raw, RawOutcome):
        return raw
    outcome, detail = raw
    return RawOutcome(outcome, detail)


@dataclass(frozen=True)
class Check:
    """One adversarial check: what it asks, and what counts as passing.

    One row per check, rather than a `TESTS` tuple and a `CHECK_PURPOSE`
    dict keyed by the same names. The purpose belongs here because it is a
    property of the check — whoever changes what a check does is the
    person who has to restate what it asks — and because two tables keyed
    alike will eventually disagree. They needed a test to catch orphans
    between them; a single row cannot have any.

    `report` prints `purpose` above the measured outcomes, so
    docs/findings.md is generated whole instead of pairing generated rows
    with a hand-written key that drifts.
    """

    name: str
    group: str  # "quick" or "full"
    expectation: str  # "allow", "deny" or "record"
    fn: Callable[..., RawOutcome | tuple[str, str]]
    needs_fixtures: bool
    purpose: str  # the question this check asks, in one sentence
