"""dns-rebinding: grades on one thing — whether the fixture saw a
connection. The mock proxy stands in for the engine's verdict on each
CONNECT; the fixture transcript is supplied directly, since the real one is
read from a container's log stream (docs/findings.md "DNS rebinding")."""

from __future__ import annotations

import unittest
from collections.abc import Sequence

from internet_proxy_locally.checks.egress import dns_rebind, fixture_log, transport
from tests.egress import support


@support.requires_openssl
class DnsRebindTest(unittest.TestCase):
    def setUp(self) -> None:
        self._source = fixture_log.FIXTURE_LOG_SOURCE
        self.addCleanup(
            lambda: setattr(fixture_log, "FIXTURE_LOG_SOURCE", self._source)
        )
        # The gap exists to defeat second-granularity resolver caches. No
        # real resolver is involved here, so don't pay for it.
        self._gap = dns_rebind.REBIND_TTL_GAP
        dns_rebind.REBIND_TTL_GAP = 0.0
        self.addCleanup(lambda: setattr(dns_rebind, "REBIND_TTL_GAP", self._gap))
        self.asked: list[str] = []

    def client(self, allow: bool) -> transport.ProxyClient:
        """A mock that records every host it is asked about, so a
        transcript can be built for exactly the names the check invented."""
        asked = self.asked

        def host_allowed(host: str) -> bool:
            asked.append(host)
            return allow

        _, port = support.start_mock(self, mode="strict", host_allowed=host_allowed)
        return transport.ProxyClient("127.0.0.1", port)

    def transcript(self, lookups_per_name: int, trap: Sequence[str] = ()) -> list[str]:
        lines = []
        for name in sorted(set(self.asked)):
            answers = ["9.9.9.9", "192.168.64.60"][:lookups_per_name]
            for i, answer in enumerate(answers, start=1):
                lines.append(f"IPL-FIXTURE dns name={name} query={i} answer={answer}")
        return lines + [f"IPL-FIXTURE trap connect from={peer}" for peer in trap]

    def test_trap_hit_fails_even_when_every_probe_was_denied(self) -> None:
        """The decisive signal is the fixture's, not the proxy's: a denial
        of the CONNECT the checker made says nothing about a connection the
        engine opened for itself."""
        client = self.client(allow=False)
        # The hit appears only once probing has started, as it would in a
        # live fixture — the check subtracts whatever was already there.
        fixture_log.FIXTURE_LOG_SOURCE = lambda: self.transcript(
            2, ["192.168.64.47:51102"] if self.asked else []
        )
        raw = dns_rebind.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "fail", raw.detail)
        self.assertIn("192.168.64.47", raw.detail)

    def test_a_pre_existing_trap_hit_is_not_blamed_on_this_run(self) -> None:
        """The fixture container outlives a single check, so trap hits
        accumulate. Only the ones this run produced may fail it."""
        client = self.client(allow=False)
        fixture_log.FIXTURE_LOG_SOURCE = lambda: self.transcript(2, ["10.9.9.9:4242"])
        raw = dns_rebind.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)

    def test_passes_when_the_rebind_was_offered_and_refused(self) -> None:
        client = self.client(allow=False)
        fixture_log.FIXTURE_LOG_SOURCE = lambda: self.transcript(2)
        raw = dns_rebind.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertIn(
            f"{dns_rebind.REBIND_NAMES}/{dns_rebind.REBIND_NAMES} names", raw.detail
        )
        self.assertNotIn("did not exercise", raw.detail)

    def test_pass_says_so_when_no_rebind_was_offered(self) -> None:
        """One lookup per name means the engine pinned the first answer and
        was never handed the private one. Still a pass — nothing reached
        the trap — but the detail must not imply a rebind was survived."""
        client = self.client(allow=True)
        fixture_log.FIXTURE_LOG_SOURCE = lambda: self.transcript(1)
        raw = dns_rebind.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertIn("did not exercise", raw.detail)

    def test_skips_when_the_fixture_saw_nothing(self) -> None:
        client = self.client(allow=False)
        fixture_log.FIXTURE_LOG_SOURCE = list
        raw = dns_rebind.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "skip", raw.detail)
        self.assertIn("no lookups", raw.detail)

    def test_each_name_is_probed_twice(self) -> None:
        client = self.client(allow=True)
        fixture_log.FIXTURE_LOG_SOURCE = lambda: self.transcript(1)
        raw = dns_rebind.test_dns_rebind(client)
        self.assertEqual(len(raw.attempts), 2 * dns_rebind.REBIND_NAMES)
        targets = [a.target for a in raw.attempts]
        first_pass, second_pass = (
            targets[: dns_rebind.REBIND_NAMES],
            targets[dns_rebind.REBIND_NAMES :],
        )
        self.assertEqual(first_pass, second_pass)
        self.assertEqual(len(set(first_pass)), dns_rebind.REBIND_NAMES)

    def test_names_are_unique_per_run(self) -> None:
        """The fixture counts lookups per name and rebinds from the second
        onward, so a name reused by a later run would begin already
        rebound — and the fixture container outlives individual runs."""
        client = self.client(allow=True)
        fixture_log.FIXTURE_LOG_SOURCE = lambda: self.transcript(1)
        first = {a.target for a in dns_rebind.test_dns_rebind(client).attempts}
        self.asked.clear()
        second = {a.target for a in dns_rebind.test_dns_rebind(client).attempts}
        self.assertFalse(first & second, "names must not repeat between runs")

    def test_only_the_trap_decides_the_grade(self) -> None:
        """A repeat probe that establishes, with the trap silent, means the
        engine reused the address it had already validated. That is a
        defense, not a failure."""
        client = self.client(allow=True)
        fixture_log.FIXTURE_LOG_SOURCE = lambda: self.transcript(2)
        raw = dns_rebind.test_dns_rebind(client)
        self.assertEqual(raw.outcome, "pass", raw.detail)
        self.assertTrue(all(a.outcome == "established" for a in raw.attempts))
        self.assertIn("reused the address", raw.detail)


if __name__ == "__main__":
    unittest.main()
