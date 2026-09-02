"""internet-proxy-locally — local containerized Internet filtering proxy.

One package, two lanes. The *operational* lane (`ipl`) runs one engine
behind a single stable endpoint on a default-deny hostname allowlist. The
*lab* lane (`ipl-lab`) measures all three engines against a DNS fixture and
a test allowlist, and is what `docs/findings.md` is generated from.

Run it through uv — `uv run ipl ...`. uv resolves the interpreter from
.python-version and the dependencies from pyproject.toml, so there is no
bare-interpreter path to keep working and nothing here is imported lazily
to preserve one.
"""

from __future__ import annotations

__all__ = ["Fail"]

from internet_proxy_locally.errors import Fail
