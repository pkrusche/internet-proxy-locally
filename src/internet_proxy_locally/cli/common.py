"""What both CLIs do the same way.

The two lanes are different commands with different defaults, but they are
one tool: the same global options, the same error funnel, the same `policy`
and `check` bodies. Each of these was two copies before, and at least one
pair had already drifted — `run_policy_command` computed the stale set
before regenerating in one lane and after in the other, which is invisible
right up until `policy --check` passes on the wrong thing in CI.
"""

from __future__ import annotations

import argparse
import difflib
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import BACKENDS, ENGINES
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lifecycle import egress_command
from internet_proxy_locally.policy.render import fail_on, report_synced

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


def pin_epilogue(cli: str) -> None:
    """Recording a pin is half the operation; reviewing it is the other half."""
    print(f"review the change and commit it; then run `{cli} setup`")


def run_policy_command(
    *,
    rendered: dict[Path, str],
    check: Callable[[dict[Path, str]], list[str]],
    sync: Callable[[], list[Path]],
    source: str,
    label: str,
    cli: str,
    check_only: bool,
) -> int:
    """`policy` for either lane: render, validate, then write or diff.

    Both lanes need exactly this — regenerate from the reviewed source, or
    (under `--check`, which is what CI runs) show what the committed files
    would have to become and exit non-zero.

    `source` names what the configs are generated from, `label` is the
    up-to-date line, and `cli` is the command to suggest re-running.
    """
    fail_on(check(rendered), "configuration validation failed")

    if not check_only:
        report_synced(sync(), source)
        print(label)
        return 0

    stale = [
        (path, body)
        for path, body in sorted(rendered.items())
        if not path.is_file() or path.read_text(encoding="utf-8") != body
    ]
    for path, body in stale:
        rel = path.relative_to(paths.workspace_root())
        current = (
            path.read_text(encoding="utf-8").splitlines(keepends=True)
            if path.is_file()
            else []
        )
        sys.stdout.writelines(
            difflib.unified_diff(
                current,
                body.splitlines(keepends=True),
                fromfile=f"{rel} (on disk)",
                tofile=f"{rel} (from {source})",
            )
        )
    if stale:
        names = ", ".join(
            str(path.relative_to(paths.workspace_root())) for path, _ in stale
        )
        print(f"\nSTALE: {names}", file=sys.stderr)
        print(f"Run `{cli} policy` to regenerate, then commit.", file=sys.stderr)
        return 1
    print(label)
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
