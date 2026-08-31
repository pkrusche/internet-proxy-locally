"""End-to-end verification against a real container runtime.

These check what the unit suite cannot: that Docker or Apple `container`
actually does what this package assumes it does. They therefore drive the
real CLI, on a real backend, and report in one consistent shape — named
checks and an exit code — so a run can be pasted into docs/lab.md as
evidence rather than summarized from memory.

Reached as `ipl-verify <name>`; see `cli.py`.
"""

from __future__ import annotations
