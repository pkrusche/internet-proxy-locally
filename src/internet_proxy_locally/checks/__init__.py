"""Behavioral checks run against a live proxy.

`egress` is the whole suite: it speaks HTTP and CONNECT to the endpoint and
grades what comes back, which is the only way to find out what an engine
actually enforces rather than what its config says. It is deliberately
standalone — stdlib only, no engine knowledge beyond a table of
expectations — so a result file means the same thing whichever engine
produced it.
"""

from __future__ import annotations
