"""The one error type the CLIs catch."""

from __future__ import annotations


class Fail(Exception):
    """Fatal, user-facing error."""
