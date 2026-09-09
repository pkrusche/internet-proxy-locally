"""Shared CLI options, error handling, and lifecycle commands."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from internet_proxy_locally.backend import Backend, detect_backend
from internet_proxy_locally.constants import BACKENDS, DEFAULT_ENGINE, ENGINES
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lifecycle import egress_command, start_engine
from internet_proxy_locally.net import endpoint
from internet_proxy_locally.spec import ServiceSpec

BACKEND_HELP = (
    "container backend (default: Apple `container` on macOS when "
    "installed, else docker)"
)


def add_global_options(parser: argparse.ArgumentParser, engine_help: str) -> None:
    """`--engine` and `--backend`, on the top-level parser of either lane.

    They sit before the subcommand — `ipl --engine squid up`, not `ipl up
    --engine squid` — which is a consequence of declaring them here rather
    than on each subparser, and is the existing behavior.
    """
    parser.add_argument("--engine", choices=ENGINES, default=None, help=engine_help)
    parser.add_argument("--backend", choices=BACKENDS, default=None, help=BACKEND_HELP)


def main(parser: argparse.ArgumentParser, argv: list[str] | None = None) -> int:
    """Parse, dispatch, and turn `Fail` into one line instead of a traceback.

    Every entry point funnels through here, which is the whole reason
    `Fail` is a single class in `errors`: a command that raised a `Fail`
    defined somewhere else would print a traceback at a user who can only
    read it as a crash.
    """
    opts = parser.parse_args(argv)
    try:
        return opts.func(opts)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def client_hint(host: str, port: int) -> None:
    """The line that tells someone how to actually use what just started."""
    print(
        f"clients: export HTTP_PROXY=http://{host}:{port} "
        f"HTTPS_PROXY=http://{host}:{port}"
    )


def run_up_command(
    *,
    opts: argparse.Namespace,
    sync: Callable[[], list[Path]],
    destination: Callable[[ServiceSpec], Path],
    notice: str = "",
    prestart: Callable[[Backend], str] | None = None,
    tls_interception: bool = False,
) -> int:
    """`up` for either lane: regenerate, then start one engine."""
    engine = opts.engine or DEFAULT_ENGINE
    spec = ServiceSpec.load(engine)
    backend = detect_backend(opts.backend)
    host, port = endpoint()

    sync()

    config_path = destination(spec)
    if not config_path.is_file():
        raise Fail(f"missing generated policy: {config_path}")
    if notice:
        print(notice)

    # Preserve the resolver just started for this engine.
    dns = prestart(backend) if prestart else ""

    start_engine(
        backend,
        spec,
        config_path,
        dns=dns,
        keep_fixture=bool(dns),
        tls_interception=tls_interception,
    )
    client_hint(host, port)
    return 0


def run_egress_check(
    *,
    backend: Backend,
    engine: str | None,
    cli: str,
    group: str,
    as_json: bool,
    extra: list[str] | None = None,
) -> int:
    """`check` for either lane: build the checker argv and run it.

    The lanes differ only in `group` — `--quick` is ordinary allow/deny
    behavior, `--full` the adversarial suite — and in the `extra` arguments
    the lab lane adds to wire up the DNS fixture's log stream.
    """
    cmd = egress_command(backend, engine, cli) + list(extra or [])
    cmd.append(group)
    if as_json:
        cmd.append("--json")
    return subprocess.run(cmd, check=False).returncode
