"""Reject mixed public/private DNS answers after a successful control probe."""

from __future__ import annotations

from .models import Check, RawOutcome
from .probes import _connect_attempt
from .transport import ProxyClient

# Served from lab/config/dns-fixture.hosts (config.toml). The
# control resolves to one public address; the others resolve to the same
# public address *and* a private one, in both orderings, so an engine that
# validates only the first answer fails one of them.
MIXED_FIXTURE_CONTROL = "public-only.fixture.test"
MIXED_FIXTURE_TARGETS = (
    "mixed-public-first.fixture.test",
    "mixed-private-first.fixture.test",
)


def test_dns_mixed(client: ProxyClient) -> RawOutcome:
    control = _connect_attempt(
        client, 0, f"{MIXED_FIXTURE_CONTROL}:443", MIXED_FIXTURE_CONTROL, resolve=False
    )
    if control.outcome != "established":
        return RawOutcome(
            "skip",
            (
                f"control probe to {MIXED_FIXTURE_CONTROL} did not establish "
                f"({control.detail}) — the mixed-answer fixture is not mounted, not "
                "allowlisted, or its public address is unreachable from here. Run "
                "`ipl-lab up`, which serves lab/config/dns-fixture.hosts, "
                "and re-run"
            ),
            attempts=[control],
        )

    attempts = [control]
    attempts += [
        _connect_attempt(client, i, f"{name}:443", name, resolve=False)
        for i, name in enumerate(MIXED_FIXTURE_TARGETS, start=1)
    ]
    established = [a for a in attempts[1:] if a.outcome == "established"]
    if established:
        # Behavioral, not graded here: the runner maps this through the
        # check's "deny" expectation (runner._finalize), so an engine that
        # connects fails the check.
        #
        # Deliberately phrased without a taxonomy reason word: this detail
        # is fed to classify_denial(), and nothing here was denied.
        return RawOutcome(
            "allowed",
            "; ".join(
                f"{a.target} established — the engine connected although a private address "
                "was in the answer set"
                for a in established
            ),
            attempts=attempts,
        )
    errors = [a.detail for a in attempts[1:] if a.outcome == "error"]
    if errors:
        return RawOutcome("error", "; ".join(errors), attempts=attempts)
    return RawOutcome(
        "denied",
        (
            f"control {MIXED_FIXTURE_CONTROL} established, and both mixed-answer names "
            "(public-first and private-first) were denied — every address in the answer set "
            "is validated, not only the first one or the routable one"
        ),
        attempts=attempts,
    )


CHECK = Check(
    "dns-mixed-answers",
    "full",
    "deny",
    test_dns_mixed,
    True,
    "A name resolving to a public *and* a private address is "
    "refused, in both answer orderings — every address in the "
    "answer set is validated, not just the first or the routable "
    "one.",
)
