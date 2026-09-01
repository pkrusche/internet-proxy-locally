"""parse_fixture_log() — the fixture's own transcript is what grades
dns-rebinding, so reading it has to be exact."""

from __future__ import annotations

import unittest
from typing import ClassVar

from internet_proxy_locally.checks.egress import fixture_log


class ParseFixtureLogTest(unittest.TestCase):
    LINES: ClassVar[list[str]] = [
        "IPL-FIXTURE starting address=192.168.64.60 public=9.9.9.9",
        "IPL-FIXTURE dns name=a0-ab12cd.rebind.fixture.test query=1 answer=9.9.9.9",
        "dnsmasq: query[A] something.else from 192.168.64.1",
        "IPL-FIXTURE dns name=a0-ab12cd.rebind.fixture.test query=2 answer=192.168.64.60",
        "IPL-FIXTURE trap connect from=192.168.64.47:51102",
    ]

    def test_collects_answers_in_order_and_trap_hits(self) -> None:
        answers, trap = fixture_log.parse_fixture_log(self.LINES)
        self.assertEqual(
            answers["a0-ab12cd.rebind.fixture.test"], ["9.9.9.9", "192.168.64.60"]
        )
        self.assertEqual(trap, ["192.168.64.47:51102"])

    def test_ignores_unrelated_lines(self) -> None:
        answers, trap = fixture_log.parse_fixture_log(
            ["dnsmasq: started", "random noise", ""]
        )
        self.assertEqual((answers, trap), ({}, []))


if __name__ == "__main__":
    unittest.main()
