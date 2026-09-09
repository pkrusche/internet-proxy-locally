"""`ipl` — the operational lane."""

from __future__ import annotations

import argparse
import platform
import shutil
from pathlib import Path

from internet_proxy_locally import __version__, ca, paths
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
    remove_owned,
    running_engine,
)
from internet_proxy_locally.net import endpoint, port_listening, probe_proxy
from internet_proxy_locally.policy.config import load_policy_config
from internet_proxy_locally.policy.render import (
    config_destination,
    sync_policies,
)
from internet_proxy_locally.spec import ServiceSpec


def cmd_policy(opts: argparse.Namespace) -> int:
    sync_policies()
    return 0


def cmd_setup(opts: argparse.Namespace) -> int:
    print(f"python: {platform.python_version()}")

    sync_policies()

    if load_policy_config().tls_interception and not ca.ca_present():
        ca.generate_ca()
        print(f"generated the TLS-interception CA at {ca.ca_cert_path()}")

    for name in BACKENDS:
        state = "available" if Backend(name).available() else "not installed"
        print(f"backend {name}: {state}")
    backend = detect_backend(opts.backend)
    print(f"selected backend: {backend.name}")

    print("configs: up to date")

    engines = ENGINES if opts.all else (opts.engine or DEFAULT_ENGINE,)
    for engine in engines:
        prepare_image(backend, engine, rebuild=opts.rebuild)
    print("setup complete")
    return 0


def cmd_up(opts: argparse.Namespace) -> int:
    """Start one engine on the shipped policy.

    `sync_policies()` renders the config before starting the engine. No
    resolver is started: `ipl` is the operational lane, and a fixture
    reachable from it would answer allowlisted names with private
    addresses.
    """
    return common.run_up_command(
        opts=opts,
        sync=sync_policies,
        destination=config_destination,
        missing_hint="run `ipl policy`",
        tls_interception=load_policy_config().tls_interception,
    )


def cmd_down(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    removed = False
    for name in owned_containers():
        if remove_owned(backend, name):
            print(f"removed {name}")
            removed = True
    if not removed:
        print("nothing to remove")
    return 0


def cmd_restart(opts: argparse.Namespace) -> int:
    # `up` already uses the recreate path. Keeping the existing service
    # until rendering succeeds avoids an unnecessary outage.
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


def cmd_ca_init(opts: argparse.Namespace) -> int:
    """Generate the CA if absent; `--rebuild` forces a fresh one."""
    if ca.ca_present() and not opts.rebuild:
        print(f"CA already present at {ca.ca_cert_path()}")
        return 0
    ca.generate_ca(force=opts.rebuild)
    print(f"generated the TLS-interception CA at {ca.ca_cert_path()}")
    return 0


def cmd_ca_status(opts: argparse.Namespace) -> int:
    if not ca.ca_cert_path().exists() and not ca.ca_key_path().exists():
        print("CA: absent (run `ipl ca init`)")
        return 0
    subject, expiry = ca.ca_info()
    print(f"CA: present at {ca.ca_cert_path()}")
    print(f"  subject: {subject}")
    print(f"  expires: {expiry.isoformat()}")
    return 0


def cmd_ca_export(opts: argparse.Namespace) -> int:
    """Write the public cert only — never the key — to `--out`."""
    ca.export_ca_cert(opts.out, overwrite=opts.overwrite)
    print(f"exported the CA cert (public only) to {opts.out}")
    return 0


def cmd_ca_rotate(opts: argparse.Namespace) -> int:
    """`ca init --rebuild` under a verb that states the real consequence.

    Not a new mechanism: `generate_ca` is the one code path for "make a new
    CA," and this is a thin alias so the command names what rotation
    actually does — invalidate trust everywhere the old cert was installed.
    """
    ca.generate_ca(force=True)
    print(f"rotated the TLS-interception CA at {ca.ca_cert_path()}")
    return 0


def cmd_init(opts: argparse.Namespace) -> int:
    """Create a standalone workspace without overwriting user files."""
    root = paths.workspace_root()
    policy = root / "config.toml"
    if not policy.exists():
        shutil.copyfile(paths.data_root() / "starter-config.toml", policy)
        print(f"created {policy}")
    daemon = root / "config" / "smokescreen.conf.yaml"
    daemon.parent.mkdir(parents=True, exist_ok=True)
    if not daemon.exists():
        shutil.copyfile(paths.data_root() / "smokescreen.conf.yaml", daemon)
        print(f"created {daemon}")
    sync_policies()
    print("workspace initialized")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipl",
        description="Local containerized Internet filtering proxy "
        "(Pipelock, Smokescreen or Squid) "
        f"on http://{DEFAULT_ENDPOINT}",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    common.add_global_options(
        parser,
        engine_help=f"proxy engine (default: {DEFAULT_ENGINE}; "
        "status-dependent for logs/check)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize a standalone workspace").set_defaults(
        func=cmd_init
    )

    p_policy = sub.add_parser(
        "policy", help="render config/* from config.toml (setup/up do this too)"
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
    sub.add_parser("restart", help="render, then recreate the proxy").set_defaults(
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

    p_ca = sub.add_parser(
        "ca", help="manage the TLS-interception CA (docs/tls-interception.md)"
    )
    ca_sub = p_ca.add_subparsers(dest="ca_command", required=True)

    p_ca_init = ca_sub.add_parser(
        "init", help="generate the CA if absent; --rebuild forces a fresh one"
    )
    p_ca_init.add_argument(
        "--rebuild",
        action="store_true",
        help="regenerate even if a CA is already present "
        "(invalidates trust everywhere the old cert was installed)",
    )
    p_ca_init.set_defaults(func=cmd_ca_init)

    ca_sub.add_parser(
        "status", help="present/absent, cert subject and expiry"
    ).set_defaults(func=cmd_ca_status)

    p_ca_export = ca_sub.add_parser(
        "export", help="write the public cert (never the key) to --out"
    )
    p_ca_export.add_argument(
        "--out", required=True, type=Path, help="destination file for the exported cert"
    )
    p_ca_export.add_argument(
        "--overwrite", action="store_true", help="replace an existing non-managed file"
    )
    p_ca_export.set_defaults(func=cmd_ca_export)

    ca_sub.add_parser(
        "rotate",
        help="generate a new CA "
        "(invalidates trust everywhere the old cert was installed)",
    ).set_defaults(func=cmd_ca_rotate)

    return parser


def main(argv: list[str] | None = None) -> int:
    return common.main(build_parser(), argv)


if __name__ == "__main__":
    import sys

    sys.exit(main())
