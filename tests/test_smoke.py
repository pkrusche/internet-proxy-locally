"""Exercise smoke-script failure reporting without a runtime or network."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_runpy import REPO_ROOT


class SmokeDiagnosticsTest(unittest.TestCase):
    def run_smoke(self, *, check_exit=0, policy_exit=0, logs_exit=0):
        with tempfile.TemporaryDirectory(prefix="ipl-smoke-test-") as directory:
            root = Path(directory)
            prefix = r"""
docker() { return 0; }
mktemp() { command mktemp "$TEST_TMP/results.XXXXXX"; }
uv() {
    case "$*" in
        *'check --json')
            echo check >> "$TEST_TMP/events"
            printf '%s\n' '{"results":[{"name":"http-denied","outcome":"error","detail":"test diagnostic evidence"}]}'
            return "$CHECK_EXIT" ;;
        *'internet_proxy_locally.release quick'*)
            echo validator >> "$TEST_TMP/events"
            echo "release validator ran"
            return "$POLICY_EXIT" ;;
        *'tail_logs('* )
            echo logs >> "$TEST_TMP/events"
            echo "test container audit evidence"
            return "$LOGS_EXIT" ;;
        *' down') echo down >> "$TEST_TMP/events" ;;
        *) return 0 ;;
    esac
}
"""
            script = (REPO_ROOT / "scripts/smoke.sh").read_text()
            # Keep its cd target valid when executing the script text via -c.
            script = script.replace('cd "$(dirname "${BASH_SOURCE[0]}")/.."', ":")
            proc = subprocess.run(
                [
                    "bash",
                    "-c",
                    prefix + script,
                    "smoke-test",
                    "--backend",
                    "docker",
                    "--engine",
                    "iron",
                    "--skip-setup",
                ],
                cwd=REPO_ROOT,
                env={
                    **os.environ,
                    "TEST_TMP": directory,
                    "CHECK_EXIT": str(check_exit),
                    "POLICY_EXIT": str(policy_exit),
                    "LOGS_EXIT": str(logs_exit),
                },
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(list(root.glob("results.*")), [])
            return proc, (root / "events").read_text().splitlines()

    def test_check_failure_prints_evidence_before_cleanup_and_keeps_exit_code(self):
        for logs_exit in (0, 9):
            with self.subTest(logs_exit=logs_exit):
                proc, events = self.run_smoke(
                    check_exit=7, policy_exit=1, logs_exit=logs_exit
                )
                self.assertEqual(proc.returncode, 7, proc.stderr)
                self.assertEqual(events, ["check", "validator", "logs", "down"])
                self.assertIn("test diagnostic evidence", proc.stderr)
                self.assertIn("test container audit evidence", proc.stderr)
                self.assertIn("engine=iron backend=docker exit=7", proc.stderr)

    def test_validator_failure_also_prints_evidence(self):
        proc, events = self.run_smoke(policy_exit=1)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(events, ["check", "validator", "logs", "down"])
        self.assertIn("test diagnostic evidence", proc.stderr)

    def test_successful_validator_cannot_hide_failed_check(self):
        proc, events = self.run_smoke(check_exit=7)
        self.assertEqual(proc.returncode, 7, proc.stderr)
        self.assertEqual(events, ["check", "validator", "logs", "down"])
        self.assertIn("release validator exited 0", proc.stderr)

    def test_success_does_not_dump_diagnostics(self):
        proc, events = self.run_smoke()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(events, ["check", "validator", "down"])
        self.assertEqual(proc.stderr, "")
