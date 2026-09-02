"""`ipl-lab` — the measurement lane.

The adversarial test policy, the DNS fixture and the three-engine
comparison. Never an operational proxy: it starts an engine on an allowlist
that includes `*.nip.io`, `*.sslip.io` and the local fixture zones, next to
a resolver whose whole job is to answer those names dishonestly. `ipl` is
the one you put a client behind.

Where a command here is the operational one with a different source, it
delegates rather than repeats — see `cli.common`.
"""

from __future__ import annotations

import argparse
import sys

from internet_proxy_locally.backend import Backend, detect_backend
from internet_proxy_locally.cli import common
from internet_proxy_locally.cli import run as run_cli
from internet_proxy_locally.constants import DEFAULT_ENGINE, DNS_FIXTURE, ENGINES
from internet_proxy_locally.images import prepare_image
from internet_proxy_locally.lab.container import fixture_spec, start_dns_fixture
from internet_proxy_locally.lab.render import (
    check_rendered_test_policies,
    render_test_policies,
    sync_test_policies,
    test_config_path,
)
from internet_proxy_locally.policy.render import report_synced

# What `ipl-lab policy` regenerates from, and the line it prints when it
# has nothing to do. Both lanes render from config.toml; this one adds
# the fixture spec on top, and says so.
_POLICY_SOURCE = "data/lab/fixtures.toml"
_POLICY_LABEL = "lab configs: up to date with config.toml + data/lab/fixtures.toml"


def cmd_policy(opts: argparse.Namespace) -> int:
    """`ipl policy` for the lab lane. Same body, different source."""
    return common.run_policy_command(
        rendered=render_test_policies(),
        check=check_rendered_test_policies,
        sync=sync_test_policies,
        source=_POLICY_SOURCE,
        label=_POLICY_LABEL,
        cli="ipl-lab",
        check_only=opts.check,
    )


def cmd_setup(opts: argparse.Namespace) -> int:
    """Prepare every engine plus the DNS fixture image.

    The comparison measures all three engines, so this prepares all three
    — unlike `ipl setup`, which prepares the one you are going to run.
    """
    backend = detect_backend(opts.backend)
    print(f"selected backend: {backend.name}")
    report_synced(sync_test_policies(), _POLICY_SOURCE)
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
        sync=sync_test_policies,
        source=_POLICY_SOURCE,
        destination=test_config_path,
        missing_hint="run `ipl-lab policy`",
        notice="NOTE: starting with the TEST policy — an allowlist that "
        "includes *.nip.io, *.sslip.io and the local fixture zones, and a "
        "dnsmasq container answering them. This is not an operational "
        "proxy. Run `ipl up` for one.",
        prestart=_start_fixture,
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


def _report():
    """Import `report` lazily — only the report commands need it."""
    from internet_proxy_locally import report

    return report


def cmd_measure(opts: argparse.Namespace) -> int:
    """Measure every engine, then regenerate the tables in docs/findings.md.

    Per engine: setup, `up` on the test policy with the fixture, the full
    suite as JSON into results/<engine>.json. Finishes with a `down`, so no
    engine and no fixture is left running on a test allowlist.
    """
    return _report().measure_all(backend=opts.backend, engines=ENGINES)


def cmd_report(opts: argparse.Namespace) -> int:
    """Regenerate (or verify) the generated blocks in docs/findings.md."""
    return _report().write_findings(check=opts.check)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipl-lab",
        description="The adversarial test policy, the DNS fixture and the "
        "three-engine comparison. Never an operational proxy — "
        "use `ipl` for that.",
    )
    common.add_global_options(
        parser, engine_help=f"proxy engine (default: {DEFAULT_ENGINE})"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_policy = sub.add_parser(
        "policy", help="render lab/config/* from data/lab/fixtures.toml"
    )
    p_policy.add_argument(
        "--check",
        action="store_true",
        help="report drift as a diff and exit 1 instead of writing",
    )
    p_policy.set_defaults(func=cmd_policy)

    p_setup = sub.add_parser(
        "setup", help="prepare every engine plus the DNS fixture image"
    )
    p_setup.add_argument(
        "--rebuild",
        action="store_true",
        help="rebuild locally built images even if present",
    )
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

    sub.add_parser(
        "measure",
        help="measure all three engines, write results/, regenerate docs/findings.md",
    ).set_defaults(func=cmd_measure)

    p_report = sub.add_parser(
        "report", help="regenerate docs/findings.md's tables from results/"
    )
    p_report.add_argument(
        "--check",
        action="store_true",
        help="report drift as a diff and exit 1 instead of writing",
    )
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    return common.main(build_parser(), argv)


# `python -m internet_proxy_locally.cli.lab` as well as the console
# script: the subprocess callers (the egress checker, the verify
# scripts) use the module form, which does not depend on the wrapper
# being on PATH.
if __name__ == "__main__":
    import sys

    sys.exit(main())
