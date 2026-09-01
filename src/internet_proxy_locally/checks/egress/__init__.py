"""Common adversarial egress test suite for internet-proxy-locally.

Runs the same checks against any engine (Pipelock, Smokescreen or Squid)
through the stable proxy endpoint, and produces comparable results.

Reached as `uv run ipl-check`, and as a subprocess from
`ipl check` / `ipl-lab check`. Stdlib only.

Groups:
  quick — ordinary allow/deny behavior (docs/policy.md)
  full  — quick + SSRF/DNS fixtures and CONNECT-abuse tests

The DNS fixture tests (nip.io / sslip.io, plus the local mixed-answer and
rebinding fixtures) only make sense when the *test* policy is mounted, which
is what `ipl-lab up` does: the fixture hostnames must be allowlisted so
that a rejection can only come from the IP-layer SSRF protections, not from
ordinary hostname policy. The suite auto-detects whether the test policy is
active and skips those tests otherwise. `dns-mixed-answers` and
`dns-rebinding` additionally need the local DNS fixture container, which the
same command starts and points the engine's resolver at; each proves the
fixture is live — a control probe, and the fixture's own lookup log —
before grading anything.

Outcomes:
  pass   — behavior matched the expectation
  fail   — behavior violated the expectation
  record — engine behavior documented, no pass/fail defined (docs/findings.md)
  skip   — prerequisites missing (with reason)
  error  — the test itself could not run

Each result may carry: a best-effort denial `cause` classification, a
wall-clock `elapsed_ms`, per-attempt evidence (`attempts` — used by the
DNS fixtures), full response `headers` (allow-path checks), and the
engine's own log lines for that test's window (`--backend-bin`/
`--container`; `ipl check` and `ipl-lab check` wire this automatically).

`--diff A.json B.json` compares two prior `--json` runs and prints only
the rows that diverge, instead of running the suite.

Each check lives in its own module below (`allowed_http`, `dns_rebind`,
...); `catalogue.TESTS` is the ordered list `report.py` renders
docs/findings.md's tables from.
"""

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
