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

# The lab lane's service name: its key in `spec.SERVICES`, and the
# directory holding its build context (data/images/dnsfixture/).
#
# The operational lane needs it too, but only to look the fixture's
# container name up in `spec.SERVICES` — a fixture left running answers
# allowlisted names with private addresses, so it must never outlive the
# engine it was started for, and `up`/`down` remove it whether or not the
# lab lane was ever used. `spec` is shared, so that lookup is not a lab
# import and the container name stays stated once.
DNS_FIXTURE = "dnsfixture"
