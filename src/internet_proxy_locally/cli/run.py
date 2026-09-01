"""`ipl` — the operational lane.

Runs one engine behind one stable endpoint on the shipped allowlist. This
is the proxy a person actually puts a client behind, which is why it knows
nothing about the DNS fixture beyond the name it has to sweep: a fixture
reachable from here would answer allowlisted names with private addresses.

The measurement lane is `ipl-lab` (see `cli.lab` and docs/lab.md).
"""

from __future__ import annotations

import argparse
import platform

from internet_proxy_locally.backend import Backend, detect_backend
from internet_proxy_locally.cli import common
from internet_proxy_locally.constants import (
    BACKENDS,
    DEFAULT_ENDPOINT,
    DEFAULT_ENGINE,
    ENGINES,
)
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.images import prepare_image
from internet_proxy_locally.lifecycle import (
    all_specs,
    owned_containers,
    running_engine,
    start_engine,
)
from internet_proxy_locally.net import endpoint, port_listening, probe_proxy
from internet_proxy_locally.policy.render import (
    check_rendered_policies,
    fail_on,
    render_policies,
    sync_policies,
    sync_policies_reporting,
)
from internet_proxy_locally.policy.validate import validate_policy_file
from internet_proxy_locally.spec import ServiceSpec


def cmd_policy(opts: argparse.Namespace) -> int:
    """Render config.toml into the engine configs, or report the drift.

    `setup` and `up` do this on their own; this exists so a config.toml
    edit can be reviewed — and CI can assert the committed files match —
    without a container runtime.
    """
    return common.run_policy_command(
        rendered=render_policies(),
        check=check_rendered_policies,
        sync=sync_policies,
        source="config.toml",
        label="configs: up to date with config.toml",
        cli="ipl",
        check_only=opts.check,
    )


def cmd_setup(opts: argparse.Namespace) -> int:
    print(f"python: {platform.python_version()}")

    # Before validating: the files validated below are rendered from
    # config.toml, so a stale one would be reported as a policy problem
    # that editing it could not fix.
    sync_policies_reporting()

    for name in BACKENDS:
        state = "available" if Backend(name).available() else "not installed"
        print(f"backend {name}: {state}")
    backend = detect_backend(opts.backend)
    print(f"selected backend: {backend.name}")

    problems: list[str] = []
    for engine in ENGINES:
        spec = ServiceSpec.load(engine)
        try:
            path = spec.config_path()
        except Fail as exc:
            problems.append(str(exc))
            continue
        problems += validate_policy_file(engine, path)
    fail_on(problems, "configuration validation failed")
    print("configs: valid")

    engines = ENGINES if opts.all else (opts.engine or DEFAULT_ENGINE,)
    for engine in engines:
        prepare_image(backend, engine, rebuild=opts.rebuild)
    print("setup complete")
    return 0


def cmd_up(opts: argparse.Namespace) -> int:
    engine = opts.engine or DEFAULT_ENGINE
    spec = ServiceSpec.load(engine)
    backend = detect_backend(opts.backend)
    host, port = endpoint()

    # The policy the container is about to bind-mount is rendered from
    # config.toml first, so `up` can never start an engine on a config that
    # disagrees with the reviewed allowlist. `sync_policies()` validates
    # the rendered text before writing it, so a bad config.toml fails here
    # rather than replacing a working file.
    sync_policies_reporting()

    config_path = spec.config_path()
    fail_on(
        validate_policy_file(engine, config_path),
        "refusing to start with an invalid policy (fail closed)",
    )

    start_engine(backend, spec, config_path)
    common.client_hint(host, port)
    return 0


def cmd_down(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    removed = False
    for name in owned_containers():
        if backend.remove_container(name):
            print(f"removed {name}")
            removed = True
    if not removed:
        print("nothing to remove")
    return 0


def cmd_restart(opts: argparse.Namespace) -> int:
    cmd_down(opts)
    return cmd_up(opts)


def cmd_status(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    host, port = endpoint()
    active = running_engine(backend)
    print(f"backend:  {backend.name}")
    print(f"endpoint: http://{host}:{port}")
    for spec in all_specs():
        state = backend.container_state(spec.container_name)
        marker = " (active)" if spec.engine == active else ""
        print(f"{spec.engine}: {state}{marker}")
        print(f"  container: {spec.container_name}")
        # The tag `up` runs, not a reconstruction of it: what the pin
        # behind it is belongs to data/images/<engine>/Dockerfile.
        print(f"  image:     {spec.image}")
        print(f"  built:     {'yes' if backend.image_present(spec.image) else 'no'}")
    if active:
        healthy, detail, _ = (
            probe_proxy(host, port)
            if port_listening(host, port)
            else (False, "endpoint not listening", False)
        )
        print(f"proxy check: {'OK' if healthy else 'FAILED'} — {detail}")
        return 0 if healthy else 1
    print("proxy check: skipped (no engine running)")
    return 0


def cmd_logs(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    engine = opts.engine or running_engine(backend)
    if not engine:
        raise Fail(
            "no engine is running; pass --engine to view a stopped container's logs"
        )
    spec = ServiceSpec.load(engine)
    if backend.container_state(spec.container_name) == "absent":
        raise Fail(f"no container {spec.container_name} exists")
    return backend.logs(spec.container_name, follow=opts.follow)


def cmd_check(opts: argparse.Namespace) -> int:
    """The `quick` group of checks.egress: ordinary allow/deny behavior.

    The adversarial `full` group needs the test policy and the DNS fixture,
    so it belongs to the other lane — `ipl-lab check` (docs/lab.md).
    """
    return common.run_egress_check(
        backend=detect_backend(opts.backend),
        engine=opts.engine,
        cli="ipl",
        group="--quick",
        as_json=opts.json,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipl",
        description="Local containerized Internet filtering proxy "
        "(Pipelock, Smokescreen or Squid) "
        f"on http://{DEFAULT_ENDPOINT}",
    )
    common.add_global_options(
        parser,
        engine_help=f"proxy engine (default: {DEFAULT_ENGINE}; "
        "status-dependent for logs/check)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_policy = sub.add_parser(
        "policy", help="render config/* from config.toml (setup/up do this too)"
    )
    p_policy.add_argument(
        "--check",
        action="store_true",
        help="report drift as a diff and exit 1 instead of writing",
    )
    p_policy.set_defaults(func=cmd_policy)

    p_setup = sub.add_parser(
        "setup", help="validate prerequisites, build the engine images"
    )
    p_setup.add_argument(
        "--rebuild",
        action="store_true",
        help="rebuild the image even if it is already present",
    )
    p_setup.add_argument(
        "--all",
        action="store_true",
        help="prepare every engine, not just the selected one",
    )
    p_setup.set_defaults(func=cmd_setup)

    sub.add_parser(
        "up", help="(re)create the proxy container and health-check it"
    ).set_defaults(func=cmd_up)
    sub.add_parser("restart", help="explicit teardown then up").set_defaults(
        func=cmd_restart
    )

    sub.add_parser(
        "down", help="remove containers owned by this repository"
    ).set_defaults(func=cmd_down)
    sub.add_parser(
        "status", help="show engine/backend/image/endpoint state"
    ).set_defaults(func=cmd_status)

    p_logs = sub.add_parser("logs", help="show engine logs")
    p_logs.add_argument("--follow", "-f", action="store_true")
    p_logs.set_defaults(func=cmd_logs)

    p_check = sub.add_parser(
        "check",
        help="ordinary allow/deny behavior (the adversarial suite is `ipl-lab check`)",
    )
    p_check.add_argument("--json", action="store_true", help="machine-readable results")
    p_check.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    return common.main(build_parser(), argv)


# `python -m internet_proxy_locally.cli.run` as well as the console
# script: the subprocess callers (the egress checker, the verify
# scripts) use the module form, which does not depend on the wrapper
# being on PATH.
if __name__ == "__main__":
    import sys

    sys.exit(main())
