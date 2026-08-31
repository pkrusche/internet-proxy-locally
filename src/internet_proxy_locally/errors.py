"""The one error type the CLIs catch.

Every entry point funnels `Fail` into `error: <message>` and exit 1, so
raising it is how code says "this is a problem the person running me can
act on" rather than a bug. Anything else reaching `main` is a traceback on
purpose.

This lives alone in its own module for a reason: it used to be defined
twice — once in the CLI and once in the report generator, same name,
same docstring, different class — and the lab lane's `except Fail`
could not catch the second. A report failure escaped as a traceback
while every other failure printed one clean line.
"""

from __future__ import annotations


class Fail(Exception):
    """Fatal, user-facing error."""
