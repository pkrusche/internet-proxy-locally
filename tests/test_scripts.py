"""Tests for the generated engine comparison."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Run from the repository root, so everything imports by package name.
from internet_proxy_locally import report
from internet_proxy_locally.checks import egress


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
        "tls_interception": False,
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
        a behavioral difference — that grade changes the summary counts,
        not the finding."""
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


if __name__ == "__main__":
    unittest.main()
