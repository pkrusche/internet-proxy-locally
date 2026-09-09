"""The two command-line entry points, and what they share."""

from __future__ import annotations

# Module entry points preserve the current interpreter in subprocesses.
CLI_MODULE = {
    "ipl": "internet_proxy_locally.cli.run",
    "ipl-lab": "internet_proxy_locally.cli.lab",
}
