"""concurrency-sanity: ten simultaneous CONNECTs to an allowed host all
succeed — the proxy is not serializing or dropping under trivial load."""

from __future__ import annotations

import concurrent.futures

from .models import Check
from .targets import ALLOWED_HTTPS_HOST
from .transport import ProxyClient


def test_concurrency(client: ProxyClient) -> tuple[str, str]:
    def one(_: int) -> bool:
        sock, _status, _detail = client.connect(f"{ALLOWED_HTTPS_HOST}:443")
        if sock is not None:
            sock.close()
            return True
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(one, range(10)))
    ok = sum(results)
    return (
        "record",
        f"10 concurrent CONNECTs to an allowed host: {ok} established, {10 - ok} denied/failed",
    )


CHECK = Check(
    "concurrency-sanity",
    "full",
    "record",
    test_concurrency,
    False,
    "Ten simultaneous CONNECTs to an allowed host all succeed — "
    "the proxy is not serializing or dropping under trivial load.",
)
