"""`ipl` — the operational lane."""

from __future__ import annotations

import argparse
import platform
from functools import partial
from pathlib import Path

from internet_proxy_locally import __version__, ca
from internet_proxy_locally.backend import Backend, detect_backend
from internet_proxy_locally.cli import common
from internet_proxy_locally.constants import (
    BACKENDS,
    DEFAULT_ENDPOINT,
    DEFAULT_ENGINE,
    ENGINES,
    FIXTURE_NETWORK_NAME,
    FIXTURE_PRIVATE_NETWORK_NAME,
)
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.images import prepare_image
from internet_proxy_locally.instances import (
    Endpoint,
    discover_instances,
    selected_container_names,
    selected_spec,
    workspace_id,
)
from internet_proxy_locally.lifecycle import (
    all_specs,
    owned_containers,
    ownership_labels,
    remove_owned,
    running_engine,
)
from internet_proxy_locally.net import (
    endpoint_text,
    port_listening,
    probe_address,
    probe_proxy,
)
from internet_proxy_locally.policy.render import (
    instance_config_destination,
    sync_instance_policies,
    sync_policies,
)
from internet_proxy_locally.spec import ServiceSpec


def cmd_setup(opts: argparse.Namespace) -> int:
    print(f"python: {platform.python_version()}")

    sync_policies(tls_interception=opts.tls_interception)

    if opts.tls_interception and not ca.ca_present():
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
    binding = opts.binding
    return common.run_up_command(
        opts=opts,
        sync=partial(
            sync_instance_policies, binding, tls_interception=opts.tls_interception
        ),
        destination=partial(instance_config_destination, binding=binding),
        tls_interception=opts.tls_interception,
    )


def cmd_down(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    removed = False
    binding: Endpoint | None = getattr(opts, "binding", None)
    if binding is None:
        names = owned_containers()
    else:
        names = selected_container_names(backend, binding)
    for name in names:
        if remove_owned(backend, name):
            print(f"removed {name}")
            removed = True
    if ServiceSpec.load("dnsfixture").container_name in names:
        backend.remove_lab_network(FIXTURE_NETWORK_NAME, ownership_labels())
        backend.remove_lab_network(FIXTURE_PRIVATE_NETWORK_NAME, ownership_labels())
    if not removed:
        print("nothing to remove")
    return 0


def cmd_restart(opts: argparse.Namespace) -> int:
    # `up` already uses the recreate path. Keeping the existing service
    # until rendering succeeds avoids an unnecessary outage.
    return cmd_up(opts)


def cmd_status(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    host, port = opts.binding
    active = running_engine(backend, opts.binding)
    print(f"backend:  {backend.name}")
    print(f"endpoint: http://{endpoint_text(host, port)}")
    for spec in all_specs():
        spec = selected_spec(backend, spec.engine, opts.binding)
        state = backend.container_state(spec.container_name)
        marker = " (active)" if spec.engine == active else ""
        print(f"{spec.engine}: {state}{marker}")
        print(f"  container: {spec.container_name}")
        print(f"  image:     {spec.image}")
        print(f"  built:     {'yes' if backend.image_present(spec.image) else 'no'}")
    if active:
        healthy, detail, _ = (
            probe_proxy(probe_address(host), port)
            if port_listening(probe_address(host), port)
            else (False, "endpoint not listening", False)
        )
        print(f"proxy check: {'OK' if healthy else 'FAILED'} — {detail}")
        return 0 if healthy else 1
    print("proxy check: skipped (no engine running)")
    return 0


def cmd_logs(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    engine = opts.engine or running_engine(backend, opts.binding)
    if not engine:
        raise Fail(
            "no engine is running; pass --engine to view a stopped container's logs"
        )
    spec = selected_spec(backend, engine, opts.binding)
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
        binding=opts.binding,
    )


def cmd_list(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    instances = discover_instances(backend)
    if not instances:
        print("no running IPL instances")
        return 0
    rows = [("ENGINE", "ENDPOINT", "CONTAINER", "WORKSPACE", "ROLE")]
    for instance in sorted(
        instances,
        key=lambda item: (
            item.workspace,
            item.binding or ("", 0),
            item.engine,
            item.name,
        ),
    ):
        workspace = instance.workspace
        if workspace == workspace_id():
            workspace += " (current)"
        rows.append(
            (
                instance.engine,
                endpoint_text(*instance.binding) if instance.binding else "unknown",
                instance.name,
                workspace,
                instance.role,
            )
        )
    widths = [max(len(row[index]) for row in rows) for index in range(5)]
    for row in rows:
        print(
            "  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip()
        )
    return 0


def cmd_ca_init(opts: argparse.Namespace) -> int:
    """Generate the CA if absent; `--rebuild` forces a fresh one."""
    if ca.ca_present() and not opts.rebuild:
        print(f"CA already present at {ca.ca_cert_path()}")
        return 0
    if opts.rebuild:
        _require_proxy_down(opts)
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


def _require_proxy_down(opts: argparse.Namespace) -> None:
    active = [
        instance
        for instance in discover_instances(detect_backend(opts.backend))
        if instance.workspace == workspace_id()
    ]
    if active:
        raise Fail(
            f"cannot rotate CA while {active[0].name} is running — "
            "run `ipl down` first for each running endpoint (or `ipl-lab down` for the lab)"
        )


def cmd_ca_rotate(opts: argparse.Namespace) -> int:
    """Replace the CA only after the proxy has been stopped."""
    _require_proxy_down(opts)
    ca.generate_ca(force=True)
    print(f"rotated the TLS-interception CA at {ca.ca_cert_path()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipl",
        description="Local containerized Internet filtering proxy "
        "(Pipelock, Smokescreen, Squid or Iron) "
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
    parser.add_argument(
        "--ip", help="listening IP (default: IPL_ENDPOINT or 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, help="listening port (default: IPL_ENDPOINT or 18080)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

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
    common.add_tls_option(p_setup)
    p_setup.set_defaults(func=cmd_setup)

    sub.add_parser(
        "up", help="(re)create the proxy container and health-check it"
    ).set_defaults(func=cmd_up)
    sub.add_parser("restart", help="render, then recreate the proxy").set_defaults(
        func=cmd_restart
    )

    sub.add_parser(
        "down", help="remove this workspace's proxy at the selected endpoint"
    ).set_defaults(func=cmd_down)
    sub.add_parser(
        "status", help="show engine/backend/image/endpoint state"
    ).set_defaults(func=cmd_status)
    sub.add_parser(
        "list",
        help="list running IPL instances from all workspaces on the selected backend",
    ).set_defaults(func=cmd_list)

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

    for command in ("up", "restart"):
        common.add_tls_option(sub.choices[command])

    return parser


def main(argv: list[str] | None = None) -> int:
    return common.main(build_parser(), argv)


if __name__ == "__main__":
    import sys

    sys.exit(main())
