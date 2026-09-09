"""Probe DNS rebinding; only fixture trap connections count as failures."""

from __future__ import annotations

import os
import time

from . import fixture_log
from .models import Attempt, Check, RawOutcome
from .probes import _connect_attempt
from .transport import ProxyClient

# Fresh names avoid cached answers; probe each twice to trigger rebinding.
REBIND_ZONE = "rebind.fixture.test"
REBIND_NAMES = 3  # probed twice each, either side of REBIND_TTL_GAP
# Cross a whole-second cache boundary even though the fixture uses TTL 0.
REBIND_TTL_GAP = 1.5


def _rebind_name(index: int, token: str) -> str:
    """A name unique to this run.

    The fixture counts lookups per name and hands out the private address
    from the second onward, so a name reused by a later `check` would start
    its life already rebound and the first probe would be graded against
    the wrong answer. The fixture container outlives individual check runs,
    so the token cannot be dropped.
    """
    return f"a{index}-{token}.{REBIND_ZONE}"


def test_dns_rebind(client: ProxyClient) -> RawOutcome:
    _, before_trap = fixture_log.parse_fixture_log(fixture_log.FIXTURE_LOG_SOURCE())
    token = os.urandom(3).hex()
    names = [_rebind_name(i, token) for i in range(REBIND_NAMES)]

    attempts: list[Attempt] = []
    for name in names:
        attempts.append(
            _connect_attempt(client, len(attempts), f"{name}:443", name, resolve=False)
        )
    time.sleep(REBIND_TTL_GAP)
    for name in names:
        attempts.append(
            _connect_attempt(client, len(attempts), f"{name}:443", name, resolve=False)
        )

    answers, trap = fixture_log.parse_fixture_log(fixture_log.FIXTURE_LOG_SOURCE())
    # The names are unique to this run, so their answers need no delta;
    # trap hits accumulate in a long-lived container and do.
    trap = trap[len(before_trap) :]
    ours = {name: answers.get(name, []) for name in names}
    lookups = sum(len(seen) for seen in ours.values())
    if not lookups:
        return RawOutcome(
            "skip",
            (
                f"the DNS fixture reported no lookups for *.{REBIND_ZONE} — it is not "
                "running, the engine is not resolving through it, or its log stream is not "
                "readable from here. Run `ipl-lab up` and `ipl check "
                "--full`, which wires the fixture's container through automatically"
            ),
            attempts=attempts,
        )

    for attempt in attempts:
        attempt.local_resolved = list(ours.get(attempt.target.rsplit(":", 1)[0], []))

    if trap:
        return RawOutcome(
            "fail",
            (
                f"{len(trap)} connection(s) reached the fixture's private address "
                f"(from {', '.join(sorted(set(trap)))}) after a repeat lookup handed it "
                "over — the engine followed a rebind instead of re-validating"
            ),
            attempts=attempts,
        )

    # No trap hits: say why, because "never offered the rebind" and
    # "offered it and refused" are very different amounts of evidence.
    rebound = [name for name, seen in ours.items() if len(seen) > 1]
    second_probes = attempts[REBIND_NAMES:]
    established = sum(1 for a in second_probes if a.outcome == "established")
    detail = (
        f"no connection reached the trap. {len(rebound)}/{REBIND_NAMES} names were "
        f"resolved more than once and so were handed the private address "
        f"({lookups} lookups total); of the {len(second_probes)} repeat probes, "
        f"{len(second_probes) - established} were denied and {established} "
        "established"
    )
    if not rebound:
        detail += (
            " — but the engine resolved each name only once, so it was never "
            "offered the rebind and this run did not exercise one"
        )
    elif established:
        detail += (
            " — an established repeat probe with a silent trap means the engine "
            "reused the address it had already validated rather than following "
            "the new answer"
        )
    return RawOutcome("error" if not rebound else "pass", detail, attempts=attempts)


CHECK = Check(
    "dns-rebinding",
    "full",
    "deny",
    test_dns_rebind,
    True,
    "A name whose answer changes between the first lookup and the "
    "next does not get the engine to a private address. Graded on "
    "whether the fixture's trap was reached, not on counts.",
)
