"""Release acceptance criteria, separate from comparative measurement grades."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from internet_proxy_locally.checks.egress.catalogue import TESTS
from internet_proxy_locally.checks.egress.reporting import SCHEMA_VERSION
from internet_proxy_locally.constants import ENGINES
from internet_proxy_locally.spec import ServiceSpec

# Documented limitations in docs/findings.md; improvements are welcome, new
# failures are not. These exceptions apply only to full lab measurements.
KNOWN_FAILURES = {
    ("smokescreen", False): {
        "dns-mixed-answers",
        "connect-sni-mismatch",
        "connect-raw-tunnel",
    },
    ("squid", False): {"connect-sni-mismatch", "connect-raw-tunnel"},
    ("squid", True): {"connect-sni-mismatch"},
    ("iron", False): {
        "dns-mixed-answers",
        "connect-sni-mismatch",
        "connect-raw-tunnel",
    },
    ("iron", True): {"dns-mixed-answers", "connect-sni-mismatch", "connect-raw-tunnel"},
}


def validate_results(
    data: dict, engine: str, *, full: bool, tls_interception: bool
) -> list[str]:
    label = f"{engine} (TLS {'on' if tls_interception else 'off'})"
    expected = {
        "schema_version": SCHEMA_VERSION,
        "engine": engine,
        "mode": "full" if full else "quick",
        "image": ServiceSpec.load(engine).image,
        "exit_code": 0,
    }
    if full:
        expected.update(policy="test", backend="docker")
    errors = [
        f"{label}: {key} must be {value!r}, got {data.get(key)!r}"
        for key, value in expected.items()
        if data.get(key) != value
    ]
    if data.get("tls_interception") is not tls_interception:
        errors.append(f"{label}: missing or incorrect TLS mode")
    checks = {c.name: c for c in TESTS if full or c.group == "quick"}
    rows = data.get("results")
    if not isinstance(rows, list):
        return errors + [f"{label}: missing results array"]
    seen = set()
    exceptions = (
        KNOWN_FAILURES.get((engine, tls_interception), set()) if full else set()
    )
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            errors.append(f"{label}: malformed result row")
            continue
        name = row["name"]
        if name not in checks or name in seen:
            errors.append(f"{label}: unexpected or duplicate check {name}")
            continue
        seen.add(name)
        check = checks[name]
        if (
            row.get("group") != check.group
            or row.get("expectation") != check.expectation
        ):
            errors.append(f"{label}: {name} has incorrect group or expectation")
        outcome = row.get("outcome")
        if outcome != "pass" and not (outcome == "fail" and name in exceptions):
            errors.append(f"{label}: {name}: {outcome!r} is not acceptable")
    for name in sorted(checks.keys() - seen):
        errors.append(f"{label}: missing check {name}")
    return errors


def validate_benchmark(bundle: dict) -> list[str]:
    if bundle.get("benchmark_version") != 1:
        return ["missing or unsupported benchmark_version"]
    runs = bundle.get("runs")
    if not isinstance(runs, dict) or set(runs) != set(ENGINES):
        return ["benchmark must contain every supported engine exactly once"]
    errors = []
    for engine in ENGINES:
        modes = runs[engine]
        expected = (
            {"off", "on"}
            if ServiceSpec.load(engine).supports_tls_interception
            else {"off"}
        )
        if not isinstance(modes, dict) or set(modes) != expected:
            errors.append(f"{engine}: expected TLS modes {sorted(expected)}")
            continue
        for mode, data in modes.items():
            if not isinstance(data, dict):
                errors.append(f"{engine}: malformed {mode} run")
                continue
            errors.extend(
                validate_results(data, engine, full=True, tls_interception=mode == "on")
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    quick = commands.add_parser("quick", help="require every operational check to pass")
    quick.add_argument("engine", choices=ENGINES)
    quick.add_argument("file", type=Path)
    benchmark = commands.add_parser("benchmark", help="reject new lab policy failures")
    benchmark.add_argument("file", type=Path)
    opts = parser.parse_args(argv)
    try:
        data = json.loads(opts.file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError("expected a JSON object")
        errors = (
            validate_benchmark(data)
            if opts.command == "benchmark"
            else validate_results(data, opts.engine, full=False, tls_interception=False)
        )
    except (OSError, ValueError, TypeError) as exc:
        errors = [f"{opts.file}: {exc}"]
    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print(f"{opts.file}: release policy checks passed")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
