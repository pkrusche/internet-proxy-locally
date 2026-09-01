"""Facts about the engines and backends, in one place.

The engine tuple used to be restated in three places — the CLI, the
report generator and the egress checker — with nothing making them
agree.
"""

from __future__ import annotations

DEFAULT_ENDPOINT = "127.0.0.1:18080"
ENGINES = ("pipelock", "smokescreen", "squid")
DEFAULT_ENGINE = "pipelock"
BACKENDS = ("docker", "container")

# How the engines are named in generated prose (docs/findings.md).
ENGINE_LABELS = {
    "pipelock": "Pipelock",
    "smokescreen": "Smokescreen",
    "squid": "Squid",
}

HEALTH_WAIT_SECONDS = 15.0

# The DNS fixture belongs to the lab lane and is defined in `spec.SERVICES`;
# this is the one thing about it the operational lane still has to know.
# A fixture left running answers allowlisted names
# with private addresses, so it must never outlive the engine it was
# started for — `up` and `down` remove it by name, whether or not the lab
# lane was ever used. A test asserts this string still matches the
# fixture's entry in `spec.SERVICES`.
FIXTURE_CONTAINER = "internet-proxy-dnsfixture"

# The lab lane's service name: its key in `spec.SERVICES`, and the
# directory holding its build context (data/images/dnsfixture/).
DNS_FIXTURE = "dnsfixture"
