"""Test package for internet-proxy-locally.

This file exists so that `python -m unittest discover -s tests -t .` works
from the repository root: without it, discovery refuses with "Start
directory is not importable". It also makes `tests.test_runpy` the one
name that module has — it used to be imported both as `test_runpy` and as
`tests.test_runpy`, which ran every inherited CLI test twice.

See docs/lab.md for the invocations.
"""

from __future__ import annotations

import contextlib
import io


class Captured:
    """What a command entry point printed, by stream."""

    def __init__(self, out: io.StringIO, err: io.StringIO):
        self._out, self._err = out, err

    @property
    def out(self) -> str:
        return self._out.getvalue()

    @property
    def err(self) -> str:
        return self._err.getvalue()


@contextlib.contextmanager
def quiet():
    """Capture stdout and stderr from an entry point called in-process.

    checks/egress.py, scripts/harness.py and `run.fail_on` are CLIs:
    printing a result table, or every configuration problem before failing
    closed, is their contract rather than a side effect to suppress in the
    code under test. But a test that calls one writes that output into the
    middle of the suite's own, and enough of them buried the `Ran N tests`
    line entirely.

    The text is yielded rather than dropped, so a test asserts on what was
    printed instead of ignoring it — which is the only reason silencing it
    here is not just hiding it.
    """
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield Captured(out, err)
