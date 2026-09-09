"""In-process tests for report.measure_all's command construction."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from internet_proxy_locally import paths, report
from internet_proxy_locally.constants import ENGINES


class MeasureAllTest(unittest.TestCase):
    """`measure_all` shells out to `ipl-lab`; these tests only inspect argv."""

    def run_measure_all(self, *, tls_interception: bool) -> list[list[str]]:
        """Run `measure_all` with `_run` and `write_findings` stubbed out.

        Returns the argv of every `_run` call (setup, each engine's `up`,
        and the final `down`), so a test can assert on flag placement
        without a container runtime.
        """
        run_calls: list[list[str]] = []

        def fake_run(cmd: list[str]) -> None:
            run_calls.append(cmd)

        def fake_subprocess_run(cmd, **kwargs):
            if cmd[-2:] == ["check", "--json"]:
                return subprocess.CompletedProcess(cmd, 0, '{"engine": "x"}', "")
            run_calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        results_dir = Path(
            tempfile.mkdtemp(prefix="ipl-measure-test-", dir=paths.workspace_root())
        )
        self.addCleanup(shutil.rmtree, results_dir, True)
        with (
            patch.object(report, "_run", side_effect=fake_run),
            patch.object(report.subprocess, "run", side_effect=fake_subprocess_run),
            patch.object(report, "write_findings", return_value=0),
        ):
            code = report.measure_all(
                engines=ENGINES,
                results_dir=results_dir,
                out=results_dir / "findings.md",
                tls_interception=tls_interception,
            )
        self.assertEqual(code, 0)
        return run_calls

    def test_tls_interception_off_adds_no_flag(self) -> None:
        for cmd in self.run_measure_all(tls_interception=False):
            self.assertNotIn("--tls-interception", cmd)

    def test_tls_interception_on_skips_smokescreen(self) -> None:
        calls = self.run_measure_all(tls_interception=True)

        setup = next(c for c in calls if c[-1:] == ["setup"] or "setup" in c)
        self.assertIn("--tls-interception", setup)

        up_smokescreen = next(
            c for c in calls if "--engine" in c and "smokescreen" in c and "up" in c
        )
        self.assertNotIn("--tls-interception", up_smokescreen)

        for engine in ("pipelock", "squid"):
            up = next(c for c in calls if "--engine" in c and engine in c and "up" in c)
            self.assertIn("--tls-interception", up)
