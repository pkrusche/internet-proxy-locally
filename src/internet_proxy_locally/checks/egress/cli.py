"""Common adversarial egress test suite for internet-proxy-locally."""

from __future__ import annotations

import argparse
import json

from .reporting import envelope, exit_code, print_text
from .runner import run_suite

DEFAULT_PROXY = "http://127.0.0.1:18080"
ENGINES = ("pipelock", "smokescreen", "squid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--proxy", default=DEFAULT_PROXY)
    parser.add_argument("--engine", choices=ENGINES, required=True)
    parser.add_argument(
        "--backend-bin",
        default=None,
        help="container backend binary (docker/container), for engine log capture",
    )
    parser.add_argument(
        "--container",
        default=None,
        help="container name, paired with --backend-bin, for engine log capture",
    )
    parser.add_argument(
        "--fixture-container",
        default=None,
        help="DNS fixture container name, paired with --backend-bin; "
        "dns-rebinding grades on what the fixture observed",
    )
    parser.add_argument(
        "--image",
        default=None,
        help="the engine image reference, recorded in --json output so "
        "a result file says what it measured (`ipl check` passes it)",
    )
    parser.add_argument(
        "--tls-interception",
        action="store_true",
        help="the running engine was started with TLS interception on, "
        "recorded in --json output (`ipl check` passes it)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true")
    mode.add_argument("--full", action="store_true")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat skipped checks as execution errors too",
    )
    opts = parser.parse_args(argv)

    results = run_suite(
        opts.proxy,
        opts.engine,
        full=opts.full,
        backend_bin=opts.backend_bin,
        container=opts.container,
        fixture_container=opts.fixture_container,
    )
    if opts.as_json:
        print(
            json.dumps(
                envelope(
                    results,
                    opts.engine,
                    opts.proxy,
                    full=opts.full,
                    backend=opts.backend_bin,
                    image=opts.image,
                    tls_interception=opts.tls_interception,
                    strict=opts.strict,
                ),
                indent=2,
            )
        )
    else:
        print_text(results, opts.engine)
    return exit_code(results, strict=opts.strict)
