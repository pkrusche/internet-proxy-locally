"""`ipl-verify <name>` — one door onto the four verification scripts.

Each script keeps its own options, because they genuinely differ: one
insists on a named backend, one sweeps every installed backend, one takes
`--all` to walk the engines. So this only picks which one to run and hands
it the rest of the argv, rather than trying to unify four argument sets
that have no reason to agree.

    ipl-verify backend --backend docker
    ipl-verify loopback --port 18081
    ipl-verify resilience --all
    ipl-verify sandbox
"""

from __future__ import annotations

import argparse
import sys

VERIFIERS = ("backend", "loopback", "resilience", "sandbox")


def _load(name: str):
    """Import one verifier on demand.

    Lazily, and only because importing all four would start four argparse
    module-level docstring reads for a run that uses one of them — not to
    preserve any bare-interpreter path. There is none.
    """
    from importlib import import_module

    return import_module(f"internet_proxy_locally.verify.{name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ipl-verify",
        description=__doc__.splitlines()[0],
        epilog="Every option after <name> belongs to that verifier; "
        "`ipl-verify <name> --help` lists them.",
    )
    parser.add_argument("name", choices=VERIFIERS, help="which verifier to run")
    opts, rest = parser.parse_known_args(argv)
    return _load(opts.name).main(rest)


if __name__ == "__main__":
    sys.exit(main())
