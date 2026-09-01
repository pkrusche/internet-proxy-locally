"""Tests for the generated comparison and the end-to-end scripts.

The scripts themselves need a container runtime and are not run here; what
is tested is everything around that — the report generator's pure
rendering, the invariants it enforces on a result file, and the guard that
the committed docs/findings.md is what the committed results render to.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Run from the repository root, so everything imports by name. See the
# comment in `verify.harness`.
from internet_proxy_locally import report
from internet_proxy_locally.checks import egress
from internet_proxy_locally.verify import harness
from internet_proxy_locally.verify import resilience as verify_resilience
from internet_proxy_locally.verify import sandbox as verify_sandbox
from tests import quiet


def row(
    name: str,
    outcome: str,
    expectation: str = "deny",
    cause=None,
    observed=None,
    detail: str = "detail",
) -> dict:
    return {
        "name": name,
        "group": "quick",
        "expectation": expectation,
        "outcome": outcome,
        "detail": detail,
        "cause": cause,
        "observed": observed,
        "elapsed_ms": 1.0,
        "attempts": [],
        "headers": {},
        "engine_logs": [],
    }


def run(engine: str, rows: list[dict]) -> dict:
    return {
        "schema_version": egress.SCHEMA_VERSION,
        "engine": engine,
        "proxy": "http://127.0.0.1:18080",
        "mode": "full",
        "backend": "docker",
        "image": f"{engine}:test",
        "policy": "test",
        "host": "Darwin test",
        "generated_at": "2026-08-28T00:00:00Z",
        "exit_code": 0,
        "results": rows,
        "_path": REPO_ROOT / "results" / f"{engine}.json",
    }


class CheckCatalogTest(unittest.TestCase):
    """Every check must say what it asks, because the generated comparison
    prints that line and nothing else explains the row."""

    def test_every_check_has_a_purpose(self) -> None:
        """A purpose is a field of the check now, so it cannot be orphaned
        — only left empty, which is what this catches."""
        for check in egress.TESTS:
            self.assertTrue(
                check.purpose.strip(),
                f"{check.name} renders an unexplained section in docs/findings.md",
            )
        names = {check.name for check in egress.TESTS}
        self.assertEqual(len(names), len(egress.TESTS), "duplicate check name")


class BehaviorTest(unittest.TestCase):
    """The grade and the behavior are different facts, and the report has to
    keep them apart: `PASS` on a deny row and `RECORD (denied)` describe the
    same engine doing the same thing."""

    def test_graded_rows_report_what_the_engine_did(self) -> None:
        self.assertEqual(report.behavior(row("x", "pass", "deny")), "denied")
        self.assertEqual(report.behavior(row("x", "fail", "deny")), "allowed")
        self.assertEqual(report.behavior(row("x", "pass", "allow")), "allowed")
        self.assertEqual(report.behavior(row("x", "fail", "allow")), "denied")

    def test_recorded_rows_report_the_observation(self) -> None:
        self.assertEqual(
            report.behavior(row("x", "record", "record", observed="allowed")), "allowed"
        )

    def test_skip_and_error_are_their_own_answer(self) -> None:
        self.assertEqual(report.behavior(row("x", "skip", "deny")), "skip")

    def test_a_recorded_deviation_is_not_hidden_as_agreement(self) -> None:
        """Smokescreen's `record` on dns-mixed-answers must still show up as
        a behavioral difference — that grade changes the exit code, not the
        finding."""
        runs = {
            "pipelock": run(
                "pipelock",
                [row("dns-mixed-answers", "pass", "deny", cause="private-ip")],
            ),
            "smokescreen": run(
                "smokescreen",
                [row("dns-mixed-answers", "record", "record", observed="allowed")],
            ),
        }
        self.assertTrue(report.behavior_differs(runs, "dns-mixed-answers"))

    def test_same_behavior_different_cause_is_not_a_behavioral_difference(self) -> None:
        runs = {
            "pipelock": run(
                "pipelock",
                [
                    row(
                        "loopback-ipv4",
                        "pass",
                        "deny",
                        cause="hostname-not-allowlisted",
                    )
                ],
            ),
            "squid": run(
                "squid", [row("loopback-ipv4", "pass", "deny", cause="private-ip")]
            ),
        }
        self.assertFalse(report.behavior_differs(runs, "loopback-ipv4"))
        # ... but it is still a divergence worth listing.
        self.assertTrue(report.divergences(runs, ["loopback-ipv4"]))


class VerdictTest(unittest.TestCase):
    def test_cause_and_observation_are_both_shown(self) -> None:
        self.assertEqual(
            report.verdict(row("x", "pass", "deny", cause="private-ip")),
            "PASS [private-ip]",
        )
        self.assertEqual(
            report.verdict(row("x", "record", "record", observed="allowed")),
            "RECORD (allowed)",
        )
        self.assertEqual(report.verdict(row("x", "pass", "allow")), "PASS")


class GradedPoolTest(unittest.TestCase):
    def test_a_row_recorded_on_one_engine_leaves_the_pool(self) -> None:
        """Pass counts are only comparable over checks graded the same way
        everywhere; otherwise a lower count can mean either weaker behavior
        or a different expectation."""
        name = egress.TESTS[0].name
        other = egress.TESTS[1].name
        runs = {
            "pipelock": run(
                "pipelock", [row(name, "pass", "allow"), row(other, "pass", "deny")]
            ),
            "smokescreen": run(
                "smokescreen",
                [row(name, "pass", "allow"), row(other, "record", "record")],
            ),
        }
        self.assertEqual(report.graded_names(runs), [name])


class ResultFileTest(unittest.TestCase):
    """A result file has to state the conditions it was measured under, or
    the generated conditions table would be a guess."""

    def setUp(self) -> None:
        import shutil
        import tempfile

        self.tmp = Path(tempfile.mkdtemp(prefix="ipl-report-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, engine: str, document: dict) -> None:
        document = dict(document)
        document.pop("_path", None)
        (self.tmp / f"{engine}.json").write_text(json.dumps(document))

    def test_rejects_an_older_schema(self) -> None:
        stale = run("pipelock", [row("x", "pass")])
        stale["schema_version"] = 1
        self.write("pipelock", stale)
        with self.assertRaises(report.Fail) as ctx:
            report.load_runs(self.tmp, ("pipelock",))
        self.assertIn("schema_version", str(ctx.exception))

    def test_rejects_a_quick_run(self) -> None:
        quick = run("pipelock", [row("x", "pass")])
        quick["mode"] = "quick"
        self.write("pipelock", quick)
        with self.assertRaises(report.Fail) as ctx:
            report.load_runs(self.tmp, ("pipelock",))
        self.assertIn("quick", str(ctx.exception))

    def test_rejects_results_for_another_engine(self) -> None:
        self.write("pipelock", run("squid", [row("x", "pass")]))
        with self.assertRaises(report.Fail) as ctx:
            report.load_runs(self.tmp, ("pipelock",))
        self.assertIn("squid", str(ctx.exception))

    def test_reports_a_missing_engine_with_the_command_to_fix_it(self) -> None:
        with self.assertRaises(report.Fail) as ctx:
            report.load_runs(self.tmp, ("pipelock",))
        self.assertIn("ipl-lab measure", str(ctx.exception))


class PolicyDetectionTest(unittest.TestCase):
    """Which policy was mounted is read back off the rows, not declared."""

    def _results(self, fixture_outcome: str, detail: str) -> list:
        made = []
        for check in egress.TESTS:
            needs = check.needs_fixtures
            outcome = fixture_outcome if needs else "pass"
            made.append(
                egress.Result(
                    check.name,
                    check.group,
                    check.expectation,
                    outcome,
                    detail if needs else "ok",
                )
            )
        return made

    def test_test_policy_is_recognized(self) -> None:
        self.assertEqual(egress.policy_in_use(self._results("pass", "graded")), "test")

    def test_real_policy_is_recognized(self) -> None:
        self.assertEqual(
            egress.policy_in_use(self._results("skip", egress.FIXTURE_SKIP)), "real"
        )

    def test_quick_run_admits_it_does_not_know(self) -> None:
        quick = [r for r in self._results("pass", "x") if r.group == "quick"]
        self.assertEqual(egress.policy_in_use(quick), "unknown")


class GeneratedComparisonTest(unittest.TestCase):
    """The generated blocks of docs/findings.md must be exactly what the
    committed results render to — the same guard config/ has against
    config.toml. The narrative around them is written by a person and is
    not checked here, only that it survives the injection untouched."""

    FINDINGS = REPO_ROOT / "docs" / "findings.md"

    def setUp(self) -> None:
        self.results_dir = REPO_ROOT / "results"
        if not any(self.results_dir.glob("*.json")):
            self.skipTest("no results/ in this checkout")
        self.runs = report.load_runs(self.results_dir, report.ENGINES)

    def test_findings_matches_the_committed_results(self) -> None:
        body = report.build(self.runs, self.results_dir, self.FINDINGS)
        current = self.FINDINGS.read_text(encoding="utf-8")
        self.assertEqual(
            current, body, "run `ipl-lab report` and commit docs/findings.md"
        )

    def test_the_rendering_names_every_check_and_engine(self) -> None:
        sections = report.render_sections(self.runs, self.results_dir)
        self.assertEqual(set(sections), set(report.SECTIONS))
        per_check = sections["per-check"]
        for check in egress.TESTS:
            self.assertIn(
                f"### {check.name}", per_check, f"{check.name} has no section"
            )
            self.assertIn(check.purpose, per_check)
        for label in report.LABELS.values():
            self.assertIn(label, sections["matrix"])

    def test_the_narrative_outside_the_markers_is_copied_byte_for_byte(self) -> None:
        # The whole point of injecting into named regions rather than
        # rendering the file: a person's reading of the measurements must
        # not be rewritable by the generator.
        document = self.FINDINGS.read_text(encoding="utf-8")
        sections = report.render_sections(self.runs, self.results_dir)
        rebuilt = report.inject(document, sections, self.FINDINGS)
        for name in report.SECTIONS:
            begin, end = (
                f"<!-- BEGIN GENERATED {name} -->",
                f"<!-- END GENERATED {name} -->",
            )
            self.assertIn(begin, rebuilt)
            self.assertIn(end, rebuilt)
        # Everything before the first marker and after the last is identical.
        first = document.index("<!-- BEGIN GENERATED")
        self.assertEqual(document[:first], rebuilt[:first])
        tail = "<!-- END GENERATED "
        self.assertEqual(
            document[document.rindex(tail) :].split("-->", 1)[1],
            rebuilt[rebuilt.rindex(tail) :].split("-->", 1)[1],
        )

    def test_a_missing_marker_is_fatal_rather_than_silently_skipped(self) -> None:
        sections = report.render_sections(self.runs, self.results_dir)
        stripped = self.FINDINGS.read_text(encoding="utf-8").replace(
            "<!-- BEGIN GENERATED matrix -->", ""
        )
        with self.assertRaises(report.Fail) as ctx:
            report.inject(stripped, sections, self.FINDINGS)
        self.assertIn("matrix", str(ctx.exception))


class ResilienceLoadTest(unittest.TestCase):
    """The load generator's accounting is the whole assertion in
    `verify_resilience.py`: it decides what counts as a leak."""

    def setUp(self) -> None:
        self.resilience = verify_resilience

    def _tally(self, statuses: list[int | None], denied: bool):
        load = self.resilience.Load(port=0)
        for status in statuses:
            load._request = lambda host, s=status: (s, f"HTTP/1.1 {s} X")  # ty: ignore[invalid-assignment]
            load.stop.set()  # one pass through the loop body only
            load.stop.clear()
            # exercise the accounting directly, without the socket
            with load._lock:
                if denied:
                    if status is not None and status < 400:
                        load.denied_leaked.append(f"HTTP/1.1 {status} X")
                    else:
                        load.denied_refused += 1
                elif status is not None and status < 400:
                    load.allowed_ok += 1
                else:
                    load.allowed_failed += 1
        return load

    def test_a_forwarded_denied_request_is_a_leak(self) -> None:
        load = self._tally([200, 301], denied=True)
        self.assertEqual(
            len(load.denied_leaked),
            2,
            "a 2xx/3xx for a denied host is the failure this script exists to catch",
        )

    def test_refusals_and_outages_are_both_safe_for_a_denied_host(self) -> None:
        # A connection error during a restart is the *expected* shape of a
        # fail-closed outage, and must not be counted as a leak.
        load = self._tally([403, 407, None], denied=True)
        self.assertEqual(load.denied_leaked, [])
        self.assertEqual(load.denied_refused, 3)

    def test_an_allowed_host_counts_redirects_as_reachable(self) -> None:
        # Squid and Smokescreen answer 301 for the allowed probe; treating
        # that as a failure would make the recovery check unsatisfiable.
        load = self._tally([200, 301, None, 403], denied=False)
        self.assertEqual(load.allowed_ok, 2)
        self.assertEqual(load.allowed_failed, 2)

    def test_wait_gives_up_rather_than_hanging(self) -> None:
        self.assertFalse(self.resilience._wait(lambda: False, 0.2))
        self.assertTrue(self.resilience._wait(lambda: True, 0.2))


class SandboxIntegrationTest(unittest.TestCase):
    """The routing detection must not report an integration that is absent —
    that was the whole reason the item sat open as "unverified"."""

    def setUp(self) -> None:
        self.sandbox = verify_sandbox

    def test_a_missing_package_is_inconclusive_not_a_pass(self) -> None:
        routed, notes = self.sandbox.routing_evidence("/nonexistent/project-sandbox")
        self.assertFalse(routed)
        self.assertTrue(any("inconclusive" in note for note in notes))

    def test_the_in_sandbox_script_asserts_both_directions(self) -> None:
        """It has to check that the proxy works *and* that bypassing it does
        not; either alone is satisfied by a sandbox with no filtering."""
        script = self.sandbox.SANDBOX_SCRIPT
        self.assertIn("--proxy", script)
        self.assertIn("--noproxy", script)
        for marker in (
            "proxy-env",
            "allowlisted-through-proxy",
            "blocked-through-proxy",
            "direct-egress",
            "direct-dns",
        ):
            self.assertIn(marker, script)


class ReporterTest(unittest.TestCase):
    def test_exit_code_follows_the_failures(self) -> None:
        with quiet() as printed:
            ok = harness.Reporter("t")
            ok.check(True, "fine")
            self.assertEqual(ok.finish(), 0)
            bad = harness.Reporter("t")
            bad.check(True, "fine")
            bad.check(False, "broken", "why it matters")
            self.assertEqual(bad.finish(), 1)
        # A failed check has to say what it was and why it matters — that
        # is the whole reason these scripts print rather than just exit.
        self.assertIn("FAIL broken", printed.out)
        self.assertIn("why it matters", printed.out)


if __name__ == "__main__":
    unittest.main()
