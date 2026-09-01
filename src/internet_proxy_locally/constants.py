"""Facts about the engines and backends, in one place.

The engine tuple used to be restated in three places — the CLI, the
report generator and the egress checker — with nothing making them
agree.
"""

from __future__ import annotations

DEFAULT_ENDPOINT = "127.0.0.1:18080"
ENGINES = ("pipelock", "smokescreen", "squid")
DEFAULT_ENGINE = "pipelock"
# Engines whose image this repository builds locally rather than pulling.
BUILT_ENGINES = ("smokescreen", "squid")
BACKENDS = ("docker", "container")

# How the engines are named in generated prose (docs/findings.md).
ENGINE_LABELS = {
    "pipelock": "Pipelock",
    "smokescreen": "Smokescreen",
    "squid": "Squid",
}

HEALTH_WAIT_SECONDS = 15.0

# The DNS fixture belongs to the lab lane and is defined in
# data/lab/dnsfixture.toml; this is the one thing about it the operational
# lane still has to know. A fixture left running answers allowlisted names
# with private addresses, so it must never outlive the engine it was
# started for — `up` and `down` remove it by name, whether or not the lab
# lane was ever used. A test asserts this string still matches
# data/lab/dnsfixture.toml.
FIXTURE_CONTAINER = "internet-proxy-dnsfixture"

# The lab lane's service name, and the stem of the two files that define
# it: data/lab/dnsfixture.toml and data/images/dnsfixture/Dockerfile.
DNS_FIXTURE = "dnsfixture"
