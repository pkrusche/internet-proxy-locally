"""Correlate Iron's explicit policy refusals with inconclusive client probes."""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from .denial import aggregate_cause
from .models import Attempt, Result

# Host and container clocks need not agree to the microsecond. Keep this
# allowance bounded: it only widens the audit timestamp filter, never the
# transaction matching, duplicate rejection, or explicit-denial requirements.
AUDIT_CLOCK_SLACK = timedelta(milliseconds=250)


@dataclass(frozen=True)
class _Audit:
    target: str
    peer: str
    sni: str
    mode: str
    method: str
    action: str
    status: int
    time: datetime
    error: str
    path: str
    rejected_by: str


def _audits(
    lines: list[str],
    started_at: datetime,
    ended_at: datetime,
    diagnostics: list[str],
) -> list[_Audit]:
    records = []
    earliest = started_at - AUDIT_CLOCK_SLACK
    latest = ended_at + AUDIT_CLOCK_SLACK
    for line in lines:
        # Docker prefixes JSON with an RFC3339 timestamp; Apple does not.
        _, sep, payload = line.partition("{")
        if not sep:
            continue
        try:
            entry = json.loads("{" + payload)
            audit = entry["audit"]
            stamp = datetime.fromisoformat(entry["time"])
            if entry.get("msg") != "request":
                continue
            in_window = earliest <= stamp <= latest
            window = "outside (rejected)"
            if in_window:
                window = (
                    "inside" if started_at <= stamp <= ended_at else "inside (slack)"
                )
            diagnostics.append(
                f"audit time={stamp.isoformat()} "
                f"host={audit.get('host')!r} method={audit.get('method')!r} "
                f"from_host_start_ms={(stamp - started_at).total_seconds() * 1000:+.3f} "
                f"from_host_end_ms={(stamp - ended_at).total_seconds() * 1000:+.3f} "
                f"window={window}"
            )
            if not in_window:
                continue
            strings = [
                audit[k]
                for k in ("host", "remote_addr", "sni", "mode", "method", "action")
            ]
            error = entry.get("error", "")
            path = audit.get("path", "")
            rejected_by = entry.get("rejected_by", "")
            if not all(
                isinstance(s, str) for s in [*strings, error, path, rejected_by]
            ):
                continue
            if type(audit["status_code"]) is not int:
                continue
            records.append(
                _Audit(
                    audit["host"],
                    audit["remote_addr"],
                    audit["sni"],
                    audit["mode"],
                    audit["method"],
                    audit["action"],
                    audit["status_code"],
                    stamp,
                    error,
                    path,
                    rejected_by,
                )
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            # Do not echo malformed payloads or exception text: the raw engine
            # logs are already retained, and may contain arbitrary input.
            diagnostics.append(f"unusable audit record ({type(exc).__name__})")
            continue
    return records


def _denial(attempt: Attempt, records: list[_Audit]) -> tuple[str, str] | None:
    if attempt.target.startswith("http://"):
        return _http_denial(attempt, records)
    if attempt.outcome != "error" or attempt.status != 200:
        return None
    host, _, port = attempt.target.rpartition(":")
    host = host.strip("[]")
    starts = [
        r for r in records if r.target == attempt.target and r.method == "CONNECT"
    ]
    if len(starts) != 1:
        return None
    start = starts[0]
    if (
        not start.peer
        or start.sni != host
        or start.mode not in ("sni-only", "mitm")
        or start.action != "allow"
        or start.status != 200
    ):
        return None
    # Exactly one terminal audit on the same connection: duplicate, conflicting,
    # or incomplete transactions cannot establish which request was refused.
    same_peer = [r for r in records if r.peer == start.peer and r is not start]
    if len(same_peer) != 1:
        return None
    end = same_peer[0]
    if (
        end.time < start.time
        or end.target != (host if start.mode == "sni-only" else attempt.target)
        or end.sni != host
        or end.mode != start.mode
        or end.method != ("" if start.mode == "sni-only" else "GET")
        or end.action != "error"
        or end.status != 502
    ):
        return None
    match = re.fullmatch(
        r"dial tcp (\[[\da-fA-F:.]+\]|[\d.]+):(\d+): "
        r"denied by upstream_deny_cidrs: ([\da-fA-F:.]+) in ([\da-fA-F:./]+)",
        end.error,
    )
    if match is None or match[2] != ("443" if start.mode == "sni-only" else port):
        return None
    try:
        address = ipaddress.ip_address(match[3])
        dial_address = ipaddress.ip_address(match[1].strip("[]"))
        network = ipaddress.ip_network(match[4])
        if address != dial_address or address not in network or address.is_global:
            return None
    except ValueError:
        return None
    cause = (
        "metadata"
        if str(address) in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
        else "private-ip"
    )
    return cause, f"Iron audit log ({start.peer}): {end.error}"


def _http_denial(attempt: Attempt, records: list[_Audit]) -> tuple[str, str] | None:
    if attempt.outcome != "error" or attempt.status != 403:
        return None
    url = urlsplit(attempt.target)
    target_forms = {url.netloc}
    if url.scheme == "http" and url.port in (None, 80):
        target_forms.add(f"{url.netloc}:80")
    matching = [r for r in records if r.target in target_forms and r.method == "GET"]
    # Exactly one contemporaneous request to this host. A status alone or a
    # stale, duplicate, or conflicting audit cannot resolve the client error.
    if len(matching) != 1:
        return None
    record = matching[0]
    if (
        not record.peer
        or record.path != (url.path or "/")
        or record.sni
        or record.mode != "mitm"
        or record.action != "reject"
        or record.status != 403
        or record.rejected_by != "allowlist"
    ):
        return None
    return (
        "hostname-not-allowlisted",
        f"Iron audit log ({record.peer}): rejected_by allowlist",
    )


def explain_denials(
    result: Result, *, started_at: datetime, ended_at: datetime
) -> Result:
    """Use explicit, correlated log evidence; retain the original client error.

    Call only for Iron, with the wall-clock interval of this check. Timestamps
    outside that interval plus bounded clock slack cannot supply a verdict.
    Only DNS/private-address and plain-HTTP checks have the matching attempt
    evidence needed for this reassessment.
    """
    if (
        result.name
        not in (
            "dns-private-ipv4",
            "dns-private-ipv6",
            "blocked-host-http",
            "metadata-endpoint",
        )
        or result.expectation != "deny"
        or result.outcome != "error"
        or not result.attempts
        or any(a.outcome == "established" for a in result.attempts)
    ):
        return result
    diagnostics = [
        f"host window start={started_at.isoformat()} end={ended_at.isoformat()} (inclusive)",
        (
            f"clock slack=+/-{AUDIT_CLOCK_SLACK.total_seconds() * 1000:g}ms; "
            f"accepted start={(started_at - AUDIT_CLOCK_SLACK).isoformat()} "
            f"end={(ended_at + AUDIT_CLOCK_SLACK).isoformat()} (inclusive)"
        ),
    ]
    records = _audits(result.engine_logs, started_at, ended_at, diagnostics)
    attempts = []
    for attempt in result.attempts:
        evidence = _denial(attempt, records)
        if evidence is not None:
            cause, explanation = evidence
            attempt = replace(
                attempt,
                outcome="denied",
                cause=cause,
                detail=f"denied — {explanation}; client observation: {attempt.detail}",
            )
        attempts.append(attempt)
    complete = all(a.outcome == "denied" for a in attempts)
    if not complete:
        diagnostics.append(
            f"usable in-window audits={len(records)}; "
            f"unresolved attempts={sum(a.outcome != 'denied' for a in attempts)}"
        )
        for diagnostic in diagnostics:
            # stderr keeps --json stdout parseable and is captured by the
            # release log even when smoke cleanup removes the result file.
            print(
                f"Iron audit correlation [{result.name}]: {diagnostic}", file=sys.stderr
            )
    if attempts == result.attempts:
        return result
    detail = "; ".join(f"{a.target}: {a.detail}" for a in attempts)
    return replace(
        result,
        outcome="pass" if complete else "error",
        observed="denied" if complete else result.observed,
        cause=aggregate_cause(detail, attempts) if complete else None,
        detail=detail,
        attempts=attempts,
    )
