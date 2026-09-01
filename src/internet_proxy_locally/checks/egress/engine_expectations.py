"""Engine-specific grading overrides for the CONNECT-abuse tests.

Pipelock is expected to reject; Smokescreen and Squid behavior is recorded
(docs/findings.md has the measured outcome — both allow both).

Squid *can* inspect a tunnel, via `ssl_bump peek` + `splice`, but that
configuration was built, measured and rejected: it crashes the daemon
when a peeked connection must be terminated without a signing CA, and it
answers every CONNECT with 200 before evaluating policy. See the header
of config/squid.conf and docs/findings.md.

`dns-mixed-answers` on Smokescreen is the third override and the one that
is a policy call rather than a capability gap. Handed a name that
resolves to one public and one private address, Smokescreen connects to
the public one; docs/policy.md says such a name is rejected, so it
deviates. It is graded `record` rather than `fail` because the row is
still the same measurement either way and the grade was doing a job it
cannot do: `ipl-lab check` exited 1 on every Smokescreen run, so the exit
code stopped distinguishing "this engine has a known, bounded deviation"
from "something broke". Recording keeps the behavior in the report — the
row says `RECORD established` with both answer orderings — and leaves the
exit code meaning what it says. What it costs, and why the deviation is
bounded, is docs/security.md, "Choosing an engine"; the measurement is
docs/findings.md §2.
"""

from __future__ import annotations

ENGINE_EXPECTATIONS = {
    "pipelock": {"connect-sni-mismatch": "deny", "connect-raw-tunnel": "deny"},
    "smokescreen": {
        "connect-sni-mismatch": "record",
        "connect-raw-tunnel": "record",
        "dns-mixed-answers": "record",
    },
    "squid": {"connect-sni-mismatch": "record", "connect-raw-tunnel": "record"},
}

ENGINES = tuple(ENGINE_EXPECTATIONS)
