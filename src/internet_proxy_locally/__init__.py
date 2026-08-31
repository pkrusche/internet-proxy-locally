"""internet-proxy-locally — local containerized Internet filtering proxy.

One package, two lanes. The *operational* lane (`ipl`) runs one engine
behind a single stable endpoint on a default-deny hostname allowlist. The
*lab* lane (`ipl-lab`) measures all three engines against a DNS fixture and
a test allowlist, and is what `docs/findings.md` is generated from.

The split is load-bearing, not organizational: the operational lane must
not be able to reach the fixture machinery, because a fixture that outlives
its run answers allowlisted names with private addresses. Nothing under
`policy/`, `images`, `lifecycle` or `cli.run` may import
`internet_proxy_locally.lab`, and a test asserts it.

Run it through uv — `uv run ipl ...`. uv resolves the interpreter from
.python-version and the dependencies from pyproject.toml, so there is no
bare-interpreter path to keep working and nothing here is imported lazily
to preserve one.
"""

from __future__ import annotations

__all__ = ["Fail"]

from internet_proxy_locally.errors import Fail
