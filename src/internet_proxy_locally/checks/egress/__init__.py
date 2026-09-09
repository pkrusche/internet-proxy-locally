"""Common adversarial egress test suite for internet-proxy-locally."""

from __future__ import annotations

from .catalogue import CHECKS_BY_NAME, TESTS, check_purpose
from .cli import DEFAULT_PROXY, ENGINES, main
from .denial import aggregate_cause, classify_denial
from .diff import cmd_diff, diff_results
from .models import Attempt, Check, RawOutcome, Result
from .reporting import SCHEMA_VERSION, envelope, print_text
from .runner import FIXTURE_SKIP, policy_in_use, run_suite
from .transport import HttpResponse, ProxyClient

__all__ = [
    "CHECKS_BY_NAME",
    "DEFAULT_PROXY",
    "ENGINES",
    "FIXTURE_SKIP",
    "SCHEMA_VERSION",
    "TESTS",
    "Attempt",
    "Check",
    "HttpResponse",
    "ProxyClient",
    "RawOutcome",
    "Result",
    "aggregate_cause",
    "check_purpose",
    "classify_denial",
    "cmd_diff",
    "diff_results",
    "envelope",
    "main",
    "policy_in_use",
    "print_text",
    "run_suite",
]
