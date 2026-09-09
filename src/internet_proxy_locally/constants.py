"""Facts about the engines and backends, in one place."""

from __future__ import annotations

DEFAULT_ENDPOINT = "127.0.0.1:18080"
ENGINES = ("pipelock", "smokescreen", "squid")
DEFAULT_ENGINE = "pipelock"
BACKENDS = ("docker", "container")

ENGINE_LABELS = {
    "pipelock": "Pipelock",
    "smokescreen": "Smokescreen",
    "squid": "Squid",
}

HEALTH_WAIT_SECONDS = 15.0

# Shared so operational cleanup can remove the fixture without importing lab code.
DNS_FIXTURE = "dnsfixture"
