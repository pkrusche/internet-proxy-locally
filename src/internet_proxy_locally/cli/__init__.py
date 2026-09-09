"""The two command-line entry points, and what they share.

`run` is the operational lane (`ipl`) and `lab` the measurement one
(`ipl-lab`). `common` holds the parts that were byte-identical between
them — the error funnel, the global options, the `policy` and `check`
bodies — so the lanes differ only where they are meant to.
"""

from __future__ import annotations

# How to reach each lane as a module. Subprocess callers use these rather
# than console scripts, so a run does not depend on `ipl` being on PATH and
# uses the interpreter already running.
CLI_MODULE = {
    "ipl": "internet_proxy_locally.cli.run",
    "ipl-lab": "internet_proxy_locally.cli.lab",
}
