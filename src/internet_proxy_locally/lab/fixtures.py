"""data/lab/fixtures.toml: the test allowlist and the DNS fixture records.

Validated at least as hard as config.toml, and cross-checked against it.
A test policy is the shipped policy plus fixture names — never a different
policy — so an entry that config.toml would reject is rejected here too,
an address that should be public is checked to be public, and a name the
test allowlist covers but the fixture never serves is an error rather than
a check that silently reports NXDOMAIN as a denial.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.policy.config import (
    ALLOW_ENTRY,
    allow_list,
    load_policy_config,
    reject_unknown,
)


@dataclass(frozen=True)
class FixtureConfig:
    """The local DNS fixture's records, from `[fixture]` in data/lab/fixtures.toml.

    `lab/config/dns-fixture.hosts` is rendered from this, so the records the
    fixture serves and the `[policy.test]` allowlist that has to cover them
    come from one place instead of being hand-synced (docs/lab.md).
    """

    control: str
    rebind_zone: str
    ptr_address: str
    ptr_claims: str
    # (name, addresses) in file order; the order of the addresses is the
    # order the fixture answers with, which is half of what the check asks.
    records: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.records)

    @property
    def targets(self) -> tuple[str, ...]:
        """The mixed-answer names — every record except the control."""
        return tuple(name for name in self.names if name != self.control)

    def addresses(self, name: str) -> tuple[str, ...]:
        return dict(self.records).get(name, ())

    @property
    def public_answer(self) -> str:
        """The public address the fixture answers with first.

        The control record is public and nothing else, by the rule
        `_fixture_config()` enforces — so it *is* the public half, and the
        rebinding responder can be handed it rather than restating it.
        """
        return self.addresses(self.control)[0]


# The reserved TLD the fixture's names live under (RFC 6761). Anything in
# `[policy.test].allow` under it is a fixture name and must have a record
# behind it — that is the half of the sync `[fixture]` cannot enforce by
# being the source of the hosts file.
FIXTURE_TLD = ".test"


def _covered_by(name: str, entries: tuple[str, ...]) -> bool:
    """Does the allowlist `entries` permit `name`, in either shared form?"""
    if name in entries:
        return True
    return any(entry.startswith("*.") and name.endswith(entry[1:]) for entry in entries)


def _public_address(raw: str, path: Path, what: str) -> str:
    """An address that must be routable — the half of a fixture answer an
    engine is allowed to reach, and the one `ptr-allowlist` connects to."""
    address = _address(raw, path, what)
    if private_address(address):
        raise Fail(
            f"{path}: {what} is `{raw}`, which is not a public address; "
            "the check it backs would be graded by the SSRF floors "
            "rather than by the rule it is testing"
        )
    return address


def _address(raw: str, path: Path, what: str) -> str:
    if not isinstance(raw, str):
        raise Fail(f"{path}: {what} must be a string (found {raw!r})")
    try:
        ipaddress.ip_address(raw)
    except ValueError as exc:
        raise Fail(f"{path}: {what} is not an IP address: {raw!r}") from exc
    return raw


def private_address(raw: str) -> bool:
    addr = ipaddress.ip_address(raw)
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _fixture_config(
    raw: object, path: Path, allow: list[str], allow_test: list[str]
) -> FixtureConfig:
    """Read and validate `[fixture]`, cross-checked against the allowlists.

    Everything here exists so that one edit cannot half-land: a record the
    test policy does not allowlist would be denied by name and grade
    nothing, and a `[policy.test]` fixture name with no record behind it
    would resolve to NXDOMAIN and skip.
    """
    if not isinstance(raw, dict):
        raise Fail(
            f"{path}: missing the [fixture] table (it holds the DNS "
            "fixture's records; lab/config/dns-fixture.hosts is "
            "rendered from it)"
        )
    known = {"control", "rebind_zone", "ptr_address", "ptr_claims", "records"}
    reject_unknown(raw, known, path, "key(s) in [fixture]")
    missing = sorted(known - set(raw))
    if missing:
        raise Fail(f"{path}: [fixture] is missing {', '.join(missing)}")

    entries = raw["records"]
    if not isinstance(entries, dict) or not entries:
        raise Fail(
            f"{path}: [fixture.records] must be a non-empty table of "
            '`"name" = ["addr", ...]`'
        )
    records: list[tuple[str, tuple[str, ...]]] = []
    allowed = tuple(allow_test)
    for name, addresses in entries.items():
        if not ALLOW_ENTRY.match(name) or name.startswith("*."):
            raise Fail(f"{path}: [fixture.records] key `{name}` is not a hostname")
        if not name.endswith(FIXTURE_TLD):
            raise Fail(
                f"{path}: [fixture.records] key `{name}` must be under "
                f"`{FIXTURE_TLD}`, the reserved TLD that can never "
                "resolve publicly"
            )
        if not isinstance(addresses, list) or not addresses:
            raise Fail(
                f"{path}: [fixture.records] `{name}` must list at least one address"
            )
        parsed = tuple(
            _address(a, path, f"[fixture.records] `{name}`") for a in addresses
        )
        if len(set(parsed)) != len(parsed):
            raise Fail(f"{path}: [fixture.records] `{name}` repeats an address")
        if _covered_by(name, tuple(allow)):
            # The fixture's names belong to the test policy alone. In the
            # real one they would be a shipped allowlist entry for a name
            # that resolves to whatever the fixture says, private addresses
            # included — and `ipl up` never starts the fixture, so the
            # entry would be dead weight at best.
            raise Fail(
                f"config.toml allows the fixture name `{name}`. "
                "Fixture names belong in [policy.test] here only; the "
                "operational policy must never allowlist a name the "
                "fixture answers."
            )
        if not _covered_by(name, allowed):
            raise Fail(
                f"{path}: [fixture.records] `{name}` is not allowlisted by "
                "[policy.test].allow, so the fixture would be refused by "
                "name and the check would grade nothing"
            )
        records.append((name, parsed))

    control = raw["control"]
    by_name = dict(records)
    if control not in by_name:
        raise Fail(
            f"{path}: [fixture] control `{control}` is not one of the "
            f"records ({', '.join(by_name)})"
        )
    if len(by_name[control]) != 1:
        raise Fail(
            f"{path}: [fixture] control `{control}` must resolve to exactly "
            "one address; it is the probe that proves the fixture is live"
        )
    _public_address(by_name[control][0], path, f"the control record `{control}`")

    orderings: set[tuple[bool, ...]] = set()
    for name, addresses in records:
        if name == control:
            continue
        private = tuple(private_address(a) for a in addresses)
        if not any(private) or all(private):
            raise Fail(
                f"{path}: [fixture.records] `{name}` must mix one public and "
                "one private address — that mixture is the whole content of "
                "`dns-mixed-answers`"
            )
        orderings.add(private)
    if len(orderings) < 2:
        raise Fail(
            f"{path}: [fixture.records] must serve both answer orderings "
            "(public first and private first), or an engine that validates "
            "only the first address would not be distinguished from one that "
            "validates all of them"
        )

    rebind_zone = raw["rebind_zone"]
    if (
        not isinstance(rebind_zone, str)
        or not ALLOW_ENTRY.match(rebind_zone)
        or not rebind_zone.endswith(FIXTURE_TLD)
    ):
        raise Fail(
            f"{path}: [fixture] rebind_zone must be a hostname under "
            f"`{FIXTURE_TLD}` (found {rebind_zone!r})"
        )
    if _covered_by(f"probe.{rebind_zone}", tuple(allow)):
        raise Fail(
            f"config.toml allows the rebinding zone "
            f"`{rebind_zone}`. Its answers change between lookups and end "
            "at a private address; it belongs in [policy.test] here only."
        )
    if f"*.{rebind_zone}" not in allow_test:
        raise Fail(
            f"{path}: [fixture] rebind_zone `{rebind_zone}` needs "
            f"`*.{rebind_zone}` in [policy.test].allow; a denial has to be "
            "attributable to the address the engine was handed, not to the name"
        )

    ptr_address = _public_address(raw["ptr_address"], path, "[fixture] ptr_address")
    served = {a for _, addresses in records for a in addresses}
    if ptr_address in served:
        raise Fail(
            f"{path}: [fixture] ptr_address `{ptr_address}` is also a record "
            "address. dnsmasq synthesizes PTR records from the records, so "
            "sharing an address would let a bare-IP destination match the "
            "allowlist under a fixture name"
        )
    ptr_claims = raw["ptr_claims"]
    if not isinstance(ptr_claims, str) or ptr_claims not in allow:
        raise Fail(
            f"{path}: [fixture] ptr_claims must be an exact entry in "
            f"config.toml's allowlist (found {ptr_claims!r}); "
            "`ptr-allowlist` asks whether a PTR record can satisfy the "
            "*real* allowlist"
        )

    # The other direction: a `.test` name in the test policy with no record
    # behind it resolves to NXDOMAIN and silently skips its check.
    for entry in allow_test:
        if not entry.endswith(FIXTURE_TLD):
            continue
        if entry.startswith("*."):
            if entry != f"*.{rebind_zone}":
                raise Fail(
                    f"{path}: policy.test.allow has `{entry}`, which no "
                    f"[fixture] zone serves (the only one is *.{rebind_zone})"
                )
        elif entry not in by_name:
            raise Fail(
                f"{path}: policy.test.allow has `{entry}`, which "
                "[fixture.records] does not serve"
            )

    return FixtureConfig(
        control=control,
        rebind_zone=rebind_zone,
        ptr_address=ptr_address,
        ptr_claims=ptr_claims,
        records=tuple(records),
    )


@dataclass(frozen=True)
class LabConfig:
    """The test policy: the real allowlist plus the fixture-only additions.

    `allow` is config.toml's, unmodified. The test policy is a strict
    superset of the operational one by construction — `allow + allow_test`
    — and `check_rendered_policies()` re-asserts that on the rendered text
    rather than trusting the construction.
    """

    allow: tuple[str, ...]
    allow_test: tuple[str, ...]
    fixture: FixtureConfig


def load_lab_config(path: Path | None = None) -> LabConfig:
    """Read data/lab/fixtures.toml, cross-checked against the real allowlist."""
    path = paths.fixture_file() if path is None else path
    if not path.is_file():
        raise Fail(
            f"missing the test policy source {path} "
            "(it holds [policy.test] and the DNS fixture records)"
        )
    allow = list(load_policy_config().allow)
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    reject_unknown(data, {"policy", "fixture"}, path, "top-level table(s)")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise Fail(f"{path}: missing the [policy.test] table")
    reject_unknown(
        policy,
        {"test"},
        path,
        "key(s) in [policy]",
        hint=". The operational allowlist lives in config.toml.",
    )
    test = policy.get("test", {})
    if not isinstance(test, dict):
        raise Fail(f"{path}: [policy.test] must be a table")
    reject_unknown(test, {"allow"}, path, "key(s) in [policy.test]")
    allow_test = allow_list(test.get("allow", []), path, "policy.test.allow")
    if not allow_test:
        raise Fail(
            f"{path}: policy.test.allow must not be empty; without it the "
            "test policy is the real one and the adversarial checks all skip"
        )
    overlap = sorted(set(allow) & set(allow_test))
    if overlap:
        raise Fail(
            f"{path}: policy.test.allow repeats {', '.join(overlap)}, "
            "which config.toml already permits everywhere"
        )
    fixture = _fixture_config(data.get("fixture"), path, allow, allow_test)
    return LabConfig(tuple(allow), tuple(allow_test), fixture)
