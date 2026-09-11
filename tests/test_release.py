"""Release-gate regressions exercised through Bash without live containers."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class ReleaseScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="ipl-release-test-")
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        script = (REPO_ROOT / "scripts/e2e-release.sh").read_text()
        # Load the actual helper definitions, excluding the top-level release
        # commands that build artifacts, start containers, and install traps.
        self.functions = script.split("run_step() {", 1)[1].split(
            '\nrun_step "static analysis"', 1
        )[0]
        self.functions = "run_step() {" + self.functions
        self.counters = script.split("passed=()", 1)[1].split("sentinel=", 1)[0]
        self.counters = "passed=()" + self.counters

    def shell(self, commands: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-uc", self.counters + self.functions + "\n" + commands],
            cwd=REPO_ROOT,
            env={
                **os.environ,
                "tmp": str(self.tmp),
                "release_root": str(self.tmp / "workspace"),
                "release_ca": str(self.tmp / "release-ca.pem"),
                **env,
            },
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_workspace_includes_static_daemon_config_without_ca_state(self) -> None:
        proc = self.shell("prepare_release_workspace")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            (self.tmp / "workspace/config/smokescreen.conf.yaml").read_bytes(),
            (REPO_ROOT / "config/smokescreen.conf.yaml").read_bytes(),
        )
        self.assertFalse((self.tmp / "workspace/state").exists())

    def test_summary_handles_empty_result_groups_and_preserves_failure_codes(
        self,
    ) -> None:
        for commands, counts, verdict in (
            ("", "0 passed, 0 failed, 0 skipped", "PASSED"),
            (
                'run_step "one passing phase" true',
                "1 passed, 0 failed, 0 skipped",
                "PASSED",
            ),
            (
                'run_step "broken phase" bash -c "exit 7"; test "$?" -eq 7 || exit 99',
                "0 passed, 1 failed, 0 skipped",
                "FAILED",
            ),
            ('skip_step "Docker only"', "0 passed, 0 failed, 1 skipped", "PASSED"),
        ):
            with self.subTest(commands=commands):
                proc = self.shell(commands + "\nprint_summary")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(counts, proc.stdout)
                self.assertIn("RELEASE GATE " + verdict, proc.stdout)
                if verdict == "FAILED":
                    self.assertIn("FAIL  broken phase (exit 7)", proc.stdout)

    def test_only_certificate_errors_prove_untrusted_or_stale_trust(self) -> None:
        for code in (0, 7, 28, 35, 60):
            with self.subTest(curl_exit=code):
                proc = self.shell(
                    'expect_certificate_rejection "untrusted" "$tmp/error" '
                    f'bash -c "exit {code}"'
                )
                self.assertEqual(proc.returncode, 0 if code == 60 else 1)

    def test_denials_before_and_inside_tls_require_policy_evidence(self) -> None:
        fake_curl = r"""
curl() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --output) printf '%s' "$BODY" >"$2"; shift ;;
            --dump-header) printf '%s' "$HEADERS" >"$2"; shift ;;
        esac
        shift
    done
    printf '%s' "$CODES"
    return "$CURL_EXIT"
}
check_denied_destination squid http://127.0.0.1:18089
"""
        marker = "internet-proxy-locally denied this request: not allowlisted"
        for codes, code, body, headers, expected in (
            ("403 000", 56, "", "", 0),
            ("200 403", 0, marker, "", 0),
            ("200 403", 0, "", "X-Squid-Error: ERR_ACCESS_DENIED 0\r\n", 0),
            ("200 403", 0, "origin forbidden", "", 1),
            ("200 200", 0, marker, "", 1),
            ("200 503", 0, marker, "", 1),
            ("200 403", 28, marker, "", 1),
            ("000 000", 7, "", "", 1),
        ):
            with self.subTest(codes=codes, curl_exit=code, body=body, headers=headers):
                proc = self.shell(
                    fake_curl,
                    CODES=codes,
                    CURL_EXIT=str(code),
                    BODY=body,
                    HEADERS=headers,
                )
                self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
