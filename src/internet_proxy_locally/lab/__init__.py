"""The measurement lane: the test policy, the DNS fixture, the comparison.

Never an operational proxy. Everything here exists to make the adversarial
checks in `checks.egress` mean something — a hostile resolver to answer
them, and a test allowlist that is the shipped one plus the fixture names.

Nothing in the operational lane may import this package; `cli.run` is
asserted not to, because a fixture reachable from a real run is a resolver
answering allowlisted names with private addresses.
"""

from __future__ import annotations
