"""Correlate Iron's late IP refusals with inconclusive DNS probes."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime

from .denial import aggregate_cause
from .models import Attempt, Result


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


def _audits(lines: list[str], started_at: datetime, ended_at: datetime) -> list[_Audit]:
    records = []
    for line in lines:
        # Docker prefixes JSON with an RFC3339 timestamp; Apple does not.
        _, sep, payload = line.partition("{")
        if not sep:
            continue
        try:
            entry = json.loads("{" + payload)
            audit = entry["audit"]
            stamp = datetime.fromisoformat(entry["time"])
            if entry.get("msg") != "request" or not started_at <= stamp <= ended_at:
                continue
            strings = [
                audit[k]
                for k in ("host", "remote_addr", "sni", "mode", "method", "action")
            ]
            error = entry.get("error", "")
            if not all(isinstance(s, str) for s in [*strings, error]):
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
                )
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    return records


def _denial(attempt: Attempt, records: list[_Audit]) -> tuple[str, str] | None:
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


def explain_denials(
    result: Result, *, started_at: datetime, ended_at: datetime
) -> Result:
    """Use explicit, correlated log evidence; retain the original client error.

    Call only for Iron, with the wall-clock interval of this check. Logs from
    older checks remain diagnostic output but cannot supply a policy verdict.
    Other checks have different controls and failure precedence, so they are
    deliberately excluded from this narrow DNS/private-address reassessment.
    """
    if (
        result.name not in ("dns-private-ipv4", "dns-private-ipv6")
        or result.expectation != "deny"
        or result.outcome != "error"
        or not result.attempts
        or any(a.outcome == "established" for a in result.attempts)
    ):
        return result
    records = _audits(result.engine_logs, started_at, ended_at)
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
    if attempts == result.attempts:
        return result
    complete = all(a.outcome == "denied" for a in attempts)
    detail = "; ".join(f"{a.target}: {a.detail}" for a in attempts)
    return replace(
        result,
        outcome="pass" if complete else "error",
        observed="denied" if complete else result.observed,
        cause=aggregate_cause(detail, attempts) if complete else None,
        detail=detail,
        attempts=attempts,
    )
