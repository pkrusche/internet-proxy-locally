"""The local DNS fixture's own log transcript.

`dns-rebinding` and `ptr-allowlist` grade on what the fixture container
itself observed (a trap connection, a PTR query) rather than on what the
checker can infer from its own probes. Import this module (not the name
`FIXTURE_LOG_SOURCE`) so a later reassignment — by `runner.run_suite` in
production, or by a test — is visible to every reader.
"""

from __future__ import annotations

from collections.abc import Callable

# Set by runner.run_suite when `ipl check` passes --fixture-container. Kept
# as a module-level hook so a check can read it without every test function
# growing a parameter, and so unit tests can substitute a canned transcript.
FIXTURE_LOG_SOURCE: Callable[[], list[str]] = list


def parse_fixture_log(lines: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Split the fixture's `IPL-FIXTURE` lines into (answers, trap hits).

    `answers` maps each queried name to the addresses handed out, in order,
    so the number of entries is the number of times the engine resolved
    that name. `trap` holds one entry per connection that reached the
    fixture's private address — each of which is a rebind followed through.
    """
    answers: dict[str, list[str]] = {}
    trap: list[str] = []
    for line in lines:
        if "IPL-FIXTURE" not in line:
            continue
        body = line.split("IPL-FIXTURE", 1)[1].strip()
        fields = dict(part.split("=", 1) for part in body.split() if "=" in part)
        if body.startswith("dns ") and "name" in fields and "answer" in fields:
            answers.setdefault(fields["name"], []).append(fields["answer"])
        elif body.startswith("trap connect"):
            trap.append(fields.get("from", "?"))
    return answers, trap
