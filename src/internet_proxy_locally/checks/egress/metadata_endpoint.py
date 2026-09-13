"""metadata-endpoint: the cloud metadata address is refused over both
CONNECT and plain HTTP."""

from __future__ import annotations

from .models import Check, RawOutcome
from .probes import _connect_attempt, _deny_attempts, _http_attempt
from .transport import ProxyClient


def test_metadata(client: ProxyClient) -> RawOutcome:
    return _deny_attempts(
        [
            _connect_attempt(
                client, 0, "169.254.169.254:80", "169.254.169.254", resolve=False
            ),
            _http_attempt(client, "http://169.254.169.254/latest/meta-data/", n=1),
        ]
    )


CHECK = Check(
    "metadata-endpoint",
    "quick",
    "deny",
    test_metadata,
    False,
    "The cloud metadata address is refused over both CONNECT and plain HTTP.",
)
