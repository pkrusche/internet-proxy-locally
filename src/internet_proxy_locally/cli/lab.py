"""`ipl-lab` — the measurement lane."""

from __future__ import annotations

import argparse
import sys
from functools import partial

from internet_proxy_locally import report
from internet_proxy_locally.backend import Backend, detect_backend
from internet_proxy_locally.cli import common
from internet_proxy_locally.cli import run as run_cli
from internet_proxy_locally.constants import DEFAULT_ENGINE, DNS_FIXTURE, ENGINES
from internet_proxy_locally.images import prepare_image
from internet_proxy_locally.lab.container import fixture_spec, start_dns_fixture
from internet_proxy_locally.lab.render import (
    sync_test_policies,
    test_config_path,
)


def cmd_setup(opts: argparse.Namespace) -> int:
    """Prepare every engine plus the DNS fixture image.

    The comparison measures all three engines, so this prepares all three
    — unlike `ipl setup`, which prepares the one you are going to run.
    """
    backend = detect_backend(opts.backend)
    print(f"selected backend: {backend.name}")
    sync_test_policies(tls_interception=opts.tls_interception)
    for name in (*ENGINES, DNS_FIXTURE):
        prepare_image(backend, name, rebuild=opts.rebuild)
    print("lab setup complete")
    return 0


def _start_fixture(backend: Backend) -> str:
    """Bring the DNS fixture up and hand back its address for `--dns`.

    It has to exist before the engine that will be pointed at it, which is
    the one ordering constraint this lane adds to `up`.
    """
    fixture = fixture_spec()
    address = start_dns_fixture(backend)
    print(f"started the DNS fixture at {address} (serving {fixture.config_file})")
    return address


def cmd_up(opts: argparse.Namespace) -> int:
    """`ipl up` for the lab lane: the test policy, next to the fixture."""
    return common.run_up_command(
        opts=opts,
        sync=partial(sync_test_policies, tls_interception=opts.tls_interception),
        destination=test_config_path,
        notice="NOTE: starting with the TEST policy — an allowlist that "
        "includes *.nip.io, *.sslip.io and the local fixture zones, and a "
        "dnsmasq container answering them. This is not an operational "
        "proxy. Run `ipl up` for one.",
        prestart=_start_fixture,
        tls_interception=opts.tls_interception,
    )


def cmd_down(opts: argparse.Namespace) -> int:
    """Identical to `ipl down`, and delegated rather than repeated.

    Both lanes remove every engine plus the DNS fixture: "what this
    repository owns" has to have exactly one definition, or a container
    added to one list and not the other survives a `down` in the other
    lane.
    """
    return run_cli.cmd_down(opts)


def cmd_check(opts: argparse.Namespace) -> int:
    """The `full` group of checks.egress: the adversarial suite."""
    backend = detect_backend(opts.backend)
    # dns-rebinding grades on what the fixture observed, so the checker
    # needs its log stream too.
    fixture = fixture_spec()
    extra: list[str] = []
    if backend.container_state(fixture.container_name) == "running":
        extra = ["--fixture-container", fixture.container_name]
    else:
        print(
            "WARNING: the DNS fixture is not running; the fixture-dependent "
            "checks will skip. `ipl-lab up` starts it.",
            file=sys.stderr,
        )
    return common.run_egress_check(
        backend=backend,
        engine=opts.engine,
        cli="ipl-lab",
        group="--full",
        as_json=opts.json,
        extra=extra,
    )


def cmd_measure(opts: argparse.Namespace) -> int:
    """Measure both TLS modes and regenerate the combined findings table."""
    return report.measure_all(backend=opts.backend, engines=ENGINES)


def cmd_report(opts: argparse.Namespace) -> int:
    """Regenerate (or verify) the generated blocks in docs/findings.md."""
    return report.write_findings(check=opts.check)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipl-lab",
        description="The adversarial test policy, the DNS fixture and the "
        "three-engine comparison. Never an operational proxy — "
        "use `ipl` for that.",
    )
    common.add_global_options(
        parser, engine_help=f"proxy engine (default: {DEFAULT_ENGINE})", lab=True
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser(
        "setup", help="prepare every engine plus the DNS fixture image"
    )
    p_setup.add_argument(
        "--rebuild",
        action="store_true",
        help="rebuild locally built images even if present",
    )
    common.add_tls_option(p_setup)
    p_setup.set_defaults(func=cmd_setup)

    sub.add_parser(
        "up", help="start the DNS fixture and an engine on the TEST policy"
    ).set_defaults(func=cmd_up)
    sub.add_parser("down", help="remove the engine and the DNS fixture").set_defaults(
        func=cmd_down
    )

    p_check = sub.add_parser("check", help="the full adversarial egress suite")
    p_check.add_argument("--json", action="store_true", help="machine-readable results")
    p_check.set_defaults(func=cmd_check)

    p_measure = sub.add_parser(
        "measure",
        help="measure all engines in both TLS modes and regenerate docs/findings.md",
    )
    p_measure.set_defaults(func=cmd_measure)

    p_report = sub.add_parser(
        "report", help="regenerate docs/findings.md's tables from results/"
    )
    p_report.add_argument(
        "--check",
        action="store_true",
        help="report drift as a diff and exit 1 instead of writing",
    )
    p_report.set_defaults(func=cmd_report)

    common.add_tls_option(sub.choices["up"])

    return parser


def main(argv: list[str] | None = None) -> int:
    return common.main(build_parser(), argv)


if __name__ == "__main__":
    import sys

    sys.exit(main())
