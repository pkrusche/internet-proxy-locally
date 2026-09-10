"""main() — the CLI entry point."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from internet_proxy_locally.checks import egress
from internet_proxy_locally.checks.egress import cli
from internet_proxy_locally.checks.egress.models import Result
from tests import quiet
from tests.egress import support


@support.requires_openssl
class MainTest(unittest.TestCase):
    def test_successful_run_exits_zero(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        with quiet() as printed:
            rc_ok = egress.main(
                [
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--engine",
                    "pipelock",
                    "--quick",
                    "--json",
                ]
            )
        self.assertEqual(rc_ok, 0)
        # --json means the envelope is the whole of stdout, so assert that
        # rather than letting it scroll past.
        self.assertEqual(json.loads(printed.out)["engine"], "pipelock")

    def test_tls_interception_flag_is_recorded(self) -> None:
        _, port = support.start_mock(self, mode="strict")
        with quiet() as printed:
            rc = egress.main(
                [
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--engine",
                    "squid",
                    "--quick",
                    "--json",
                    "--tls-interception",
                ]
            )
        self.assertEqual(rc, 0)
        self.assertIs(json.loads(printed.out)["tls_interception"], True)

        with quiet() as printed:
            egress.main(
                [
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--engine",
                    "squid",
                    "--quick",
                    "--json",
                ]
            )
        self.assertIs(json.loads(printed.out)["tls_interception"], False)


class ExitCodeTest(unittest.TestCase):
    def test_grades_and_errors_in_text_and_json(self) -> None:
        for outcome in ("pass", "fail", "record", "skip", "error"):
            for strict in (False, True):
                for as_json in (False, True):
                    with self.subTest(outcome=outcome, strict=strict, json=as_json):
                        results = [Result("probe", "quick", "deny", outcome, "detail")]
                        args = ["--engine", "pipelock", "--quick"]
                        if strict:
                            args.append("--strict")
                        if as_json:
                            args.append("--json")
                        with (
                            patch.object(cli, "run_suite", return_value=results),
                            quiet() as printed,
                        ):
                            rc = egress.main(args)
                        expected = int(
                            outcome == "error" or (strict and outcome == "skip")
                        )
                        self.assertEqual(rc, expected)
                        if as_json:
                            data = json.loads(printed.out)
                            self.assertEqual(data["exit_code"], expected)
                            self.assertEqual(data["results"][0]["outcome"], outcome)
                        else:
                            self.assertIn(f"summary: 1 {outcome}", printed.out)


if __name__ == "__main__":
    unittest.main()
