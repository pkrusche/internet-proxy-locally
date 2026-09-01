"""diff_results() — `--diff` mode."""

from __future__ import annotations

import unittest

from internet_proxy_locally.checks.egress import diff


class DiffModeTest(unittest.TestCase):
    def test_flags_only_divergent_checks(self) -> None:
        a = {
            "schema_version": 1,
            "engine": "pipelock",
            "results": [
                {
                    "name": "connect-sni-mismatch",
                    "outcome": "pass",
                    "cause": None,
                    "detail": "denied",
                },
                {
                    "name": "allowed-http",
                    "outcome": "pass",
                    "cause": None,
                    "detail": "200",
                },
            ],
        }
        b = {
            "schema_version": 1,
            "engine": "smokescreen",
            "results": [
                {
                    "name": "connect-sni-mismatch",
                    "outcome": "record",
                    "cause": None,
                    "detail": "allowed",
                },
                {
                    "name": "allowed-http",
                    "outcome": "pass",
                    "cause": None,
                    "detail": "301",
                },
            ],
        }
        lines = diff.diff_results(a, b)
        self.assertEqual(len(lines), 1)
        self.assertIn("connect-sni-mismatch", lines[0])

    def test_no_divergence_when_identical(self) -> None:
        a = {
            "results": [{"name": "x", "outcome": "pass", "cause": None, "detail": "d"}]
        }
        self.assertEqual(diff.diff_results(a, a), [])

    def test_flags_checks_present_in_only_one_file(self) -> None:
        a = {
            "results": [{"name": "x", "outcome": "pass", "cause": None, "detail": "d"}]
        }
        b = {"results": []}
        lines = diff.diff_results(a, b)
        self.assertEqual(len(lines), 1)
        self.assertIn("only in A", lines[0])


if __name__ == "__main__":
    unittest.main()
