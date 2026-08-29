#!/usr/bin/env python3
"""Shared plumbing for the end-to-end verification scripts in scripts/.

These scripts test things the unit suite cannot: that a real container
runtime does what `run.py` assumes it does. They therefore drive the real
CLI, on a real backend, and report in one consistent shape — a list of
named checks and an exit code — so that a run can be pasted into
docs/lab.md as evidence rather than summarized from memory.

Stdlib only; Python 3.11+.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_run_module():
    """Import run.py by path. These scripts reuse its Backend/ServiceSpec
    rather than re-deriving what a container is called or how to inspect
    it — the point is to test the code that ships, not a copy of it."""
    spec = importlib.util.spec_from_file_location("run_verify", REPO_ROOT / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Reporter:
    """Named checks with a one-line failure explanation each.

    A failed check prints why it matters and what not to do about it: these
    scripts exist because the invariants they test are ones somebody could
    plausibly "fix" by relaxing them.
    """

    def __init__(self, title: str):
        self.title = title
        self.failures: list[str] = []
        self.passed = 0
        print(f"== {title}")

    def note(self, message: str) -> None:
        print(f"   {message}")

    def check(self, ok: bool, name: str, why: str = "") -> bool:
        if ok:
            self.passed += 1
            print(f"ok   {name}")
        else:
            self.failures.append(name)
            print(f"FAIL {name}")
            if why:
                for line in why.splitlines():
                    print(f"       {line}")
        return ok

    def finish(self) -> int:
        total = self.passed + len(self.failures)
        if self.failures:
            print(f"\n{len(self.failures)}/{total} checks FAILED: "
                  f"{', '.join(self.failures)}")
            return 1
        print(f"\nall {total} checks passed")
        return 0


def run_cli(args: "list[str]", env: "dict[str, str] | None" = None,
            check: bool = True, cli: str = "run.py") -> subprocess.CompletedProcess:
    """Run `./run.py <args>` (or `./lab.py`) the way a person would."""
    cmd = [sys.executable, str(REPO_ROOT / cli), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          env=env or os.environ.copy())
    if check and proc.returncode != 0:
        raise RuntimeError(f"`{' '.join(cmd)}` failed with exit "
                           f"{proc.returncode}:\n{proc.stderr.strip()}")
    return proc


def engine_up(backend: str, engine: str, port: int, test_policy: bool,
              env: "dict[str, str] | None" = None) -> subprocess.CompletedProcess:
    """setup + up, on a chosen endpoint port.

    `test_policy` picks the lane: ./lab.py brings up the DNS fixture and the
    test allowlist, ./run.py the operational one. The port matters — these
    scripts are meant to be runnable on a machine that already has a proxy
    on 18080, without taking it down.
    """
    env = dict(env or os.environ, IPL_ENDPOINT=f"127.0.0.1:{port}")
    cli = "lab.py" if test_policy else "run.py"
    run_cli(["--backend", backend, "--engine", engine, "setup"], env=env, cli=cli)
    return run_cli(["--backend", backend, "--engine", engine, "up"],
                   env=env, cli=cli)


def run_py_down(backend: str, env: "dict[str, str] | None" = None) -> None:
    """Remove everything this repository owns on that backend.

    Always in a `finally`, and always through ./lab.py: it removes the DNS
    fixture as well as the engine, and a fixture must never outlive the run
    that started it.
    """
    run_cli(["--backend", backend, "down"], env=env, check=False, cli="lab.py")
