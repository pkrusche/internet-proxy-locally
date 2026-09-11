"""Paired benchmark execution, persistence, and comparison rendering."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from internet_proxy_locally import paths, report
from internet_proxy_locally.checks import egress
from internet_proxy_locally.cli import lab
from internet_proxy_locally.constants import ENGINES
from tests.test_scripts import row, run


class MeasureAllTest(unittest.TestCase):
    def setUp(self) -> None:
        self.results_dir = Path(
            tempfile.mkdtemp(prefix="ipl-measure-test-", dir=paths.workspace_root())
        )
        self.addCleanup(shutil.rmtree, self.results_dir, True)
        self.calls: list[list[str]] = []
        self.engine = ""
        self.tls = False
        self.check_count = 0

    def fake_run(self, cmd: list[str]) -> None:
        self.calls.append(cmd)
        if "up" in cmd:
            self.engine = cmd[cmd.index("--engine") + 1]
            self.tls = "--tls-interception" in cmd

    def fake_subprocess_run(self, cmd, **kwargs):
        if cmd[-2:] == ["check", "--json"]:
            self.check_count += 1
            data = run(self.engine, [row("concurrency-sanity", "fail", "allow")])
            data.pop("_path", None)
            data["tls_interception"] = self.tls
            # FAIL grades are findings, so the check process succeeds.
            return subprocess.CompletedProcess(cmd, 0, json.dumps(data), "")
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def measure(self, check=None) -> int:
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            patch.object(report, "_run", side_effect=self.fake_run),
            patch.object(
                report.subprocess, "run", side_effect=check or self.fake_subprocess_run
            ),
            patch.object(report, "write_findings", return_value=0),
        ):
            return report.measure_all(
                engines=ENGINES,
                results_dir=self.results_dir,
                out=self.results_dir / "findings.md",
            )

    def test_runs_both_modes_and_saves_every_run(self) -> None:
        self.assertEqual(self.measure(), 0)
        self.assertEqual(self.check_count, 7)
        self.assertIn("--tls-interception", self.calls[0])
        self.assertEqual(self.calls[-1][-1], "down")
        ups = [cmd for cmd in self.calls if "up" in cmd]
        for engine in ENGINES:
            modes = ["--tls-interception" in cmd for cmd in ups if engine in cmd]
            self.assertEqual(
                modes, [False] if engine == "smokescreen" else [False, True]
            )
        runs = report.load_runs(self.results_dir, ENGINES)
        self.assertTrue(runs["pipelock"]["_tls_run"]["tls_interception"])
        self.assertFalse(runs["pipelock"]["tls_interception"])
        self.assertNotIn("_tls_run", runs["smokescreen"])
        self.assertTrue(runs["iron"]["_tls_run"]["tls_interception"])
        self.assertFalse(runs["iron"]["tls_interception"])

    def test_interruption_preserves_previous_batch_and_cleans_up(self) -> None:
        path = self.results_dir / "benchmark.json"
        path.write_text("previous measurement")

        def fail_second_check(cmd, **kwargs):
            if cmd[-2:] == ["check", "--json"] and self.check_count == 1:
                return subprocess.CompletedProcess(cmd, 1, "", "startup failed")
            return self.fake_subprocess_run(cmd, **kwargs)

        self.assertEqual(self.measure(fail_second_check), 1)
        self.assertEqual(path.read_text(), "previous measurement")
        self.assertEqual(self.calls[-1][-1], "down")

    def test_errors_are_saved_and_reported_but_exit_one(self) -> None:
        def error_result(cmd, **kwargs):
            proc = self.fake_subprocess_run(cmd, **kwargs)
            if cmd[-2:] == ["check", "--json"]:
                data = json.loads(proc.stdout)
                data["results"][0]["outcome"] = "error"
                data["exit_code"] = 1
                proc.stdout = json.dumps(data)
                proc.returncode = 1
            return proc

        self.assertEqual(self.measure(error_result), 1)
        self.assertEqual(self.check_count, 7)
        self.assertTrue((self.results_dir / "benchmark.json").exists())
        self.assertEqual(self.calls[-1][-1], "down")

    def test_wrong_tls_mode_is_not_published(self) -> None:
        def wrong_mode(cmd, **kwargs):
            proc = self.fake_subprocess_run(cmd, **kwargs)
            if cmd[-2:] == ["check", "--json"]:
                data = json.loads(proc.stdout)
                data["tls_interception"] = not self.tls
                proc.stdout = json.dumps(data)
            return proc

        self.assertEqual(self.measure(wrong_mode), 1)
        self.assertFalse((self.results_dir / "benchmark.json").exists())

    def test_missing_mode_does_not_fall_back_to_legacy_results(self) -> None:
        self.assertEqual(self.measure(), 0)
        path = self.results_dir / "benchmark.json"
        bundle = json.loads(path.read_text())
        del bundle["runs"]["squid"]["on"]
        path.write_text(json.dumps(bundle))
        with self.assertRaisesRegex(report.Fail, "expected modes"):
            report.load_runs(self.results_dir, ENGINES)

    def test_cli_always_runs_all_scenarios(self) -> None:
        opts = lab.build_parser().parse_args(["measure"])
        with patch.object(report, "measure_all", return_value=0) as measure:
            self.assertEqual(opts.func(opts), 0)
            measure.assert_called_once_with(backend="docker", engines=ENGINES)

    def test_missing_iron_run_is_not_a_complete_comparison(self) -> None:
        self.assertEqual(self.measure(), 0)
        path = self.results_dir / "benchmark.json"
        bundle = json.loads(path.read_text())
        del bundle["runs"]["iron"]
        path.write_text(json.dumps(bundle))
        with self.assertRaisesRegex(
            report.Fail, "missing iron results.*ipl-lab measure"
        ):
            report.load_runs(self.results_dir, ENGINES)

    def test_measure_rejects_tls_flag(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            lab.build_parser().parse_args(["measure", "--tls-interception"])

    def test_one_column_per_proxy_and_labeled_differences(self) -> None:
        self.assertEqual(self.measure(), 0)
        runs = report.load_runs(self.results_dir, ENGINES)
        name = "concurrency-sanity"
        for run_data in runs.values():
            for _, data in report.variants(run_data):
                data["results"][0]["outcome"] = "pass"
        runs["squid"]["_tls_run"]["results"][0]["outcome"] = "fail"
        sections = report.render_sections(runs, self.results_dir)
        matrix = sections["matrix"]
        self.assertIn("| Check | Pipelock | Smokescreen | Squid | Iron |", matrix)
        self.assertIn(
            f"| [{name}](#{name}) | PASS | PASS (off only) | off: PASS<br>on: FAIL | PASS |",
            matrix,
        )
        self.assertEqual(matrix.count(f"[{name}](#{name})"), 1)
        self.assertIn("Squid (TLS on)", sections["per-check"])
        self.assertIn("Iron (TLS on)", sections["per-check"])
        self.assertIn("benchmark.json", sections["conditions"])
        self.assertNotIn("| Policy |", sections["conditions"])
        self.assertNotIn("| Policy |", "\n".join(report.conditions_table(runs)))
        for check in egress.TESTS:
            self.assertIn(f"### {check.name}", sections["per-check"])

    def test_denial_cause_differences_are_visible(self) -> None:
        self.assertEqual(
            report.paired_cell("PASS [allowlist]", "PASS [private-ip]"),
            "off: PASS [allowlist]<br>on: PASS [private-ip]",
        )
