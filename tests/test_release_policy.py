"""Release acceptance rejects missing evidence and newly broken policy checks."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from internet_proxy_locally import release
from internet_proxy_locally.checks.egress.catalogue import TESTS
from internet_proxy_locally.checks.egress.reporting import SCHEMA_VERSION
from internet_proxy_locally.constants import ENGINES
from internet_proxy_locally.spec import ServiceSpec
from tests import quiet


def sample(engine="pipelock", *, full=True, tls=False):
    return {
        "schema_version": SCHEMA_VERSION,
        "engine": engine,
        "mode": "full" if full else "quick",
        "policy": "test" if full else "unknown",
        "backend": "docker",
        "image": ServiceSpec.load(engine).image,
        "tls_interception": tls,
        "exit_code": 0,
        "results": [
            {
                "name": c.name,
                "group": c.group,
                "expectation": c.expectation,
                "outcome": "pass",
            }
            for c in TESTS
            if full or c.group == "quick"
        ],
    }


def benchmark():
    return {
        "benchmark_version": 1,
        "runs": {
            e: {
                mode: sample(e, tls=mode == "on")
                for mode in (
                    ("off", "on")
                    if ServiceSpec.load(e).supports_tls_interception
                    else ("off",)
                )
            }
            for e in ENGINES
        },
    }


class ReleasePolicyTest(unittest.TestCase):
    def test_only_known_engine_mode_limitations_are_accepted(self):
        bundle = benchmark()
        for engine, modes in bundle["runs"].items():
            for mode, run in modes.items():
                exceptions = release.KNOWN_FAILURES.get((engine, mode == "on"), set())
                for row in run["results"]:
                    row["outcome"] = "fail"
                    with self.subTest(engine=engine, mode=mode, check=row["name"]):
                        self.assertEqual(
                            bool(release.validate_benchmark(bundle)),
                            row["name"] not in exceptions,
                        )
                    row["outcome"] = "pass"
        self.assertEqual(release.validate_benchmark(bundle), [])

    def test_quick_checks_all_require_pass_even_when_process_exits_zero(self):
        for engine in ENGINES:
            data = sample(engine, full=False)
            for row in data["results"]:
                for outcome in ("fail", "skip", "error", "record", None):
                    row["outcome"] = outcome
                    self.assertTrue(
                        release.validate_results(
                            data, engine, full=False, tls_interception=False
                        )
                    )
                row["outcome"] = "pass"
            self.assertEqual(
                release.validate_results(
                    data, engine, full=False, tls_interception=False
                ),
                [],
            )

    def test_missing_duplicate_unknown_and_mislabelled_checks_fail(self):
        base = benchmark()
        for mutation in (
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0].update(name="unknown"),
            lambda rows: rows[0].update(expectation="record"),
            lambda rows: rows[0].update(group="other"),
            lambda rows: rows.append(None),
        ):
            bundle = copy.deepcopy(base)
            mutation(bundle["runs"]["pipelock"]["off"]["results"])
            self.assertTrue(release.validate_benchmark(bundle))

    def test_known_limitations_still_require_conclusive_results(self):
        bundle = benchmark()
        run = bundle["runs"]["squid"]["off"]
        row = next(r for r in run["results"] if r["name"] == "connect-sni-mismatch")
        for outcome in ("skip", "error", "record"):
            row["outcome"] = outcome
            self.assertTrue(release.validate_benchmark(bundle))

    def test_incomplete_or_incorrect_run_conditions_fail(self):
        base = benchmark()
        for key, value in (
            ("image", "stale:1"),
            ("mode", "quick"),
            ("policy", "real"),
            ("backend", "container"),
            ("engine", "squid"),
            ("schema_version", 0),
            ("tls_interception", None),
            ("exit_code", 1),
            ("results", None),
        ):
            bundle = copy.deepcopy(base)
            bundle["runs"]["pipelock"]["off"][key] = value
            self.assertTrue(release.validate_benchmark(bundle), key)
        for engine, mode in (("pipelock", "on"), ("smokescreen", "off")):
            bundle = copy.deepcopy(base)
            del bundle["runs"][engine][mode]
            self.assertTrue(release.validate_benchmark(bundle))
        del base["runs"]["iron"]
        self.assertTrue(release.validate_benchmark(base))

    def test_cli_fails_closed_on_malformed_and_rejected_documents(self):
        with tempfile.TemporaryDirectory(prefix="ipl-acceptance-test-") as tmp:
            file = Path(tmp) / "run.json"
            for text in ("{", "[]", json.dumps(sample(full=False))):
                file.write_text(text)
                with quiet():
                    self.assertEqual(release.main(["benchmark", str(file)]), 1)
            file.write_text(json.dumps(sample(full=False)))
            with quiet():
                self.assertEqual(release.main(["quick", "pipelock", str(file)]), 0)
