"""dns-rebinding: a name whose answer changes between the first lookup and
the next does not get the engine to a private address.

The fixture answers the first lookup of a name with a public address and
every later one with its own private address, on which it listens as a
trap. Each name is probed twice, with a pause between passes, so the second
answer is actually handed out; two probes in the same second would be
served from one lookup by any resolver cache with second granularity, and
the rebind would never happen.

The engine must never connect to an address it was handed *after*
validating a different one. So the second probe is a genuine rebind:
whatever the engine does there, it does knowing only what its resolver just
told it. An engine that re-resolves and re-validates refuses. An engine
that re-resolves and forgets to re-validate arrives at the trap, and the
fixture reports it.

Probing twice, with a pause between the passes, is the point. A single
probe per name never causes the private answer to be handed out at all, so
the trap could not fire even against a vulnerable engine and the row would
pass while testing nothing — the same failure mode that once made
`dns-private-ipv6` vacuous: it asked only for a denial, and got one for the
wrong reason. Two probes in the same second are no better against a
resolver cache with second granularity, which is why the passes are
separated rather than interleaved.

**Only the trap decides the grade.** A second probe that establishes with
the trap silent is not a failure: it means the engine connected to the
public address it had already validated, which is the safe way to resist
rebinding. Both behaviors are recorded in the detail, because they are
different designs and the difference is worth seeing.

This replaced `rbndr.us`, which stopped resolving in 2026-08 and had always
been ungradable: it answered each query with one of its two addresses at
random, so nothing the checker observed could attribute what the engine did
(docs/findings.md, "DNS rebinding").
"""

from __future__ import annotations

import os
import time

from . import fixture_log
from .models import Attempt, Check, RawOutcome
from .probes import _connect_attempt
from .transport import ProxyClient

# Rebinding fixture, served by the local DNS fixture container. The first A
# query for one of these names is answered with a public address and every
# later query with the fixture's own private address, where it listens as
# a trap. Each name is fresh, so no name can be served from a cache an
# earlier one warmed, and each is probed twice so that the second answer is
# actually handed out.
REBIND_ZONE = "rebind.fixture.test"
REBIND_NAMES = 3  # probed twice each, either side of REBIND_TTL_GAP
# The fixture answers with TTL 0, but a resolver cache keyed on a
# whole-second clock — Squid's ipcache is one — will still serve two
# probes issued in the same second from a single lookup, and the rebind
# never gets handed out. One pass over every name, a pause, then a second
# pass costs one gap for the whole check rather than one per name.
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
