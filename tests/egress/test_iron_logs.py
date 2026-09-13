"""Iron log evidence must identify the transaction, not just a denial word."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from internet_proxy_locally.checks.egress import runner
from internet_proxy_locally.checks.egress.iron_logs import explain_denials
from internet_proxy_locally.checks.egress.models import (
    Attempt,
    Check,
    RawOutcome,
    Result,
)
from internet_proxy_locally.checks.egress.reporting import envelope

START = datetime(2026, 9, 10, 16, 47, 34, tzinfo=UTC)
END = START + timedelta(seconds=1)


def transaction(mode="sni-only", address="10.0.0.1", cidr="10.0.0.0/8"):
    host = "10.0.0.1.nip.io"
    begin: dict = {
        "time": (START + timedelta(milliseconds=10)).isoformat(),
        "msg": "request",
        "audit": {
            "host": host + ":80",
            "remote_addr": "172.30.203.1:55506",
            "sni": host,
            "mode": mode,
            "method": "CONNECT",
            "action": "allow",
            "status_code": 200,
        },
    }
    end = copy.deepcopy(begin)
    end["time"] = (START + timedelta(milliseconds=20)).isoformat()
    end["audit"].update(
        host=host if mode == "sni-only" else host + ":80",
        method="" if mode == "sni-only" else "GET",
        action="error",
        status_code=502,
    )
    ip = f"[{address}]" if ":" in address else address
    port = 443 if mode == "sni-only" else 80
    end["error"] = (
        f"dial tcp {ip}:{port}: denied by upstream_deny_cidrs: {address} in {cidr}"
    )
    return begin, end


def result(records, *, mode="sni-only"):
    client = (
        "inconclusive TLS/HTTP exchange after CONNECT: unexpected EOF"
        if mode == "sni-only"
        else "inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway"
    )
    attempt = Attempt(0, "10.0.0.1.nip.io:80", ["10.0.0.1"], "error", 200, 3.0, client)
    return Result(
        "dns-private-ipv4",
        "full",
        "deny",
        "error",
        client,
        attempts=[attempt],
        engine_logs=["2026-09-10T16:47:34Z " + json.dumps(r) for r in records],
    )


def assess(row):
    return explain_denials(row, started_at=START, ended_at=END)


def http_transaction():
    return {
        "time": (START + timedelta(milliseconds=20)).isoformat(),
        "msg": "request",
        "audit": {
            "host": "example.com",
            "remote_addr": "172.30.203.1:55506",
            "path": "/",
            "sni": "",
            "mode": "mitm",
            "method": "GET",
            "action": "reject",
            "status_code": 403,
        },
        "rejected_by": "allowlist",
    }


def http_result(records):
    row = result(records)
    return replace(
        row,
        name="blocked-host-http",
        group="quick",
        attempts=[
            Attempt(0, "http://example.com/", [], "error", 403, 2.0, "bare HTTP 403")
        ],
    )


class IronLogsTest(unittest.TestCase):
    def test_http_denial_requires_matching_explicit_allowlist_rejection(self):
        row = http_result([http_transaction()])
        before = asdict(row)
        updated = assess(row)
        self.assertEqual(updated.outcome, "pass")
        self.assertEqual(updated.cause, "hostname-not-allowlisted")
        self.assertEqual(updated.attempts[0].outcome, "denied")
        self.assertIn("bare HTTP 403", updated.detail)
        self.assertEqual(asdict(row), before)
        for key, value in (
            ("host", "unrelated.test"),
            ("remote_addr", ""),
            ("path", "/different"),
            ("path", None),
            ("sni", "example.com"),
            ("mode", "sni-only"),
            ("method", "CONNECT"),
            ("action", "allow"),
            ("status_code", 502),
        ):
            record = http_transaction()
            record["audit"][key] = value
            with self.subTest(key=key, value=value):
                self.assertEqual(assess(http_result([record])).outcome, "error")
        for rejected_by in (None, "", "other-transform"):
            record = {**http_transaction(), "rejected_by": rejected_by}
            self.assertEqual(assess(http_result([record])).outcome, "error")

    def test_http_stale_missing_duplicate_and_conflicting_audits_are_inconclusive(self):
        record = http_transaction()
        allowed = copy.deepcopy(record)
        allowed["audit"].update(action="allow", status_code=200)
        for records in ([], [record, record], [record, allowed]):
            self.assertEqual(assess(http_result(records)).outcome, "error")
        for stamp in (START - timedelta(seconds=1), END + timedelta(seconds=1)):
            self.assertEqual(
                assess(http_result([{**record, "time": stamp.isoformat()}])).outcome,
                "error",
            )
        for status in (None, 407, 502, 503):
            row = http_result([record])
            row.attempts[0] = replace(row.attempts[0], status=status)
            self.assertIs(assess(row), row)

    def test_http_audit_accepts_the_explicit_default_port_form(self):
        record = http_transaction()
        record["audit"]["host"] = "example.com:80"
        self.assertEqual(assess(http_result([record])).outcome, "pass")

    def test_metadata_http_audit_cannot_mask_connect_errors_or_bypasses(self):
        record = http_transaction()
        record["audit"].update(host="169.254.169.254", path="/latest/meta-data/")
        row = http_result([record])
        row.name = "metadata-endpoint"
        row.attempts[0] = replace(
            row.attempts[0], n=1, target="http://169.254.169.254/latest/meta-data/"
        )
        for outcome, expected in (
            ("denied", "pass"),
            ("error", "error"),
            ("established", "fail"),
        ):
            connect = Attempt(
                0, "169.254.169.254:80", [], outcome, 403, 1.0, "CONNECT observation"
            )
            original = replace(
                row,
                outcome="fail" if outcome == "established" else "error",
                attempts=[connect, row.attempts[0]],
            )
            with self.subTest(connect_outcome=outcome):
                updated = assess(original)
                self.assertEqual(updated.outcome, expected)
                self.assertEqual(updated.attempts[0], connect)

    def test_explicit_refusals_in_both_modes_retain_client_evidence(self):
        for mode in ("sni-only", "mitm"):
            with self.subTest(mode=mode):
                original = result(transaction(mode), mode=mode)
                before = asdict(original)
                updated = assess(original)
                self.assertEqual(updated.outcome, "pass")
                self.assertEqual(updated.cause, "private-ip")
                self.assertEqual(updated.observed, "denied")
                self.assertEqual(updated.attempts[0].status, 200)
                self.assertEqual(updated.attempts[0].outcome, "denied")
                self.assertIn(original.detail, updated.detail)
                self.assertIn("Iron audit log", updated.detail)
                self.assertEqual(updated.engine_logs, original.engine_logs)
                self.assertEqual(asdict(original), before)
                self.assertEqual(assess(updated), updated)

    def test_ipv6_and_metadata_causes(self):
        for mode in ("sni-only", "mitm"):
            for address, cidr, cause in (
                ("::1", "::1/128", "private-ip"),
                ("fd00::1", "fc00::/7", "private-ip"),
                ("169.254.169.254", "169.254.169.254/32", "metadata"),
            ):
                with self.subTest(mode=mode, address=address):
                    self.assertEqual(
                        assess(result(transaction(mode, address, cidr))).cause, cause
                    )

    def test_missing_duplicate_conflicting_and_unrelated_records_remain_errors(self):
        begin, end = transaction()
        for records in ([], [end], [begin], [begin, begin, end], [begin, end, end]):
            with self.subTest(records=records):
                self.assertEqual(assess(result(records)).outcome, "error")
        for key, value in (
            ("host", "other.test"),
            ("remote_addr", "172.30.203.1:9999"),
            ("sni", "other.test"),
            ("mode", "mitm"),
            ("method", "CONNECT"),
            ("action", "allow"),
            ("status_code", 200),
        ):
            changed = copy.deepcopy(end)
            changed["audit"][key] = value
            with self.subTest(key=key):
                self.assertEqual(assess(result([begin, changed])).outcome, "error")
        allowed = copy.deepcopy(end)
        allowed["audit"].update(action="allow", status_code=200)
        self.assertEqual(assess(result([begin, allowed, end])).outcome, "error")

    def test_generic_and_invalid_ip_errors_are_not_policy_evidence(self):
        begin, end = transaction()
        for error in (
            "bad gateway",
            "dial tcp 10.0.0.1:443: connection refused",
            "dial tcp 10.0.0.1:443: denied by upstream_deny_cidrs: 127.0.0.1 in 127.0.0.0/8",
            "dial tcp 10.0.0.1:443: denied by upstream_deny_cidrs: 10.0.0.1 in 192.168.0.0/16",
            "dial tcp 10.0.0.1:80: denied by upstream_deny_cidrs: 10.0.0.1 in 10.0.0.0/8",
        ):
            with self.subTest(error=error):
                self.assertEqual(
                    assess(result([begin, {**end, "error": error}])).outcome, "error"
                )

    def test_stale_future_out_of_order_and_malformed_logs_are_ignored(self):
        begin, end = transaction()
        for stamp in (START - timedelta(seconds=1), END + timedelta(seconds=1), START):
            changed = {**end, "time": stamp.isoformat()}
            self.assertEqual(assess(result([begin, changed])).outcome, "error")
        for bad in (
            None,
            [],
            {},
            {"audit": []},
            {**end, "time": "bad"},
            {**end, "audit": None},
        ):
            self.assertEqual(assess(result([begin, bad])).outcome, "error")
        row = result([begin])
        row.engine_logs += ["not JSON", "{broken", json.dumps({"error": end["error"]})]
        self.assertEqual(assess(row).outcome, "error")

    def test_all_attempts_need_evidence_and_bypasses_keep_precedence(self):
        row = result(transaction())
        missing = replace(row.attempts[0], n=1, target="192.168.1.1.nip.io:80")
        row.attempts.append(missing)
        updated = assess(row)
        self.assertEqual(updated.outcome, "error")
        self.assertEqual([a.outcome for a in updated.attempts], ["denied", "error"])
        self.assertIsNone(updated.cause)
        row.attempts[1] = replace(missing, outcome="established")
        self.assertIs(assess(row), row)
        for name in ("dns-rebinding", "dns-mixed-answers", "connect-sni-mismatch"):
            other = replace(result(transaction()), name=name)
            self.assertIs(assess(other), other)
        for outcome in ("pass", "fail", "skip"):
            other = replace(result(transaction()), outcome=outcome)
            self.assertIs(assess(other), other)

    def test_runner_uses_logs_only_for_iron_and_updates_json_exit_code(self):
        row = result(transaction())
        check = Check(
            row.name,
            "full",
            "deny",
            lambda _: RawOutcome("error", row.detail, row.attempts),
            False,
            "DNS denial",
        )
        for engine, outcome, code in (("iron", "pass", 0), ("squid", "error", 1)):
            with (
                patch.object(runner, "TESTS", (check,)),
                patch.object(runner.socket, "create_connection"),
                patch.object(runner, "_fetch_logs", side_effect=[[], row.engine_logs]),
                patch.object(runner, "datetime") as clock,
            ):
                clock.now.side_effect = [START, END]
                rows = runner.run_suite("http://127.0.0.1:18080", engine, full=True)
            self.assertEqual(rows[0].outcome, outcome)
            document = envelope(rows, engine, "http://127.0.0.1:18080", full=True)
            self.assertEqual(document["exit_code"], code)
            self.assertEqual(document["results"][0]["engine_logs"], row.engine_logs)
