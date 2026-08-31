"""config.toml: the allowlist, read once and validated hard.

The grammar is two forms and nothing else, and both lanes parse it through
here — a test-policy entry that config.toml would reject is not a test
policy, it is a typo with an adversarial name.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.errors import Fail

# The two forms docs/policy.md defines, and nothing else: `d` (that host
# exactly) or `*.d` (subdomains of d, never the apex). At least two labels,
# no leading dot, no regex metacharacters, no scheme/port/path.
ALLOW_ENTRY = re.compile(
    r"\A(?:\*\.)?(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\Z"
)


@dataclass(frozen=True)
class PolicyConfig:
    """The shared logical policy, read from config.toml.

    The allowlist and nothing else. The adversarial test policy lives in
    data/lab/fixtures.toml and is read by ipl-lab alone (docs/lab.md), so
    nothing this file can express is ever a fixture.
    """

    allow: tuple[str, ...]

    # Static: Squid needs the two forms split into a `dstdomain` ACL and a
    # `dstdom_regex` one, and ipl-lab has to split its own entries the same
    # way. Taking the entries as an argument keeps one implementation of
    # "what is a wildcard entry" for both lanes.
    @staticmethod
    def exact(entries: tuple[str, ...] | list[str]) -> list[str]:
        return [entry for entry in entries if not entry.startswith("*.")]

    @staticmethod
    def wild(entries: tuple[str, ...] | list[str]) -> list[str]:
        return [entry for entry in entries if entry.startswith("*.")]


def allow_list(raw: object, path: Path, key: str) -> list[str]:
    if not isinstance(raw, list):
        raise Fail(f"{path}: {key} must be an array of strings")
    entries: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise Fail(f"{path}: {key} must contain only strings (found {item!r})")
        entry = item.strip()
        if entry in entries:
            raise Fail(f"{path}: {key} lists `{entry}` twice")
        if not ALLOW_ENTRY.match(entry):
            raise Fail(
                f"{path}: {key} entry `{entry}` is not a valid allowlist form. "
                "Use `example.com` for one host or `*.example.com` for its "
                "subdomains (docs/policy.md)."
            )
        # `ALLOW_ENTRY` cannot tell 1.2.3.4 from a hostname, and an
        # address-form entry is exactly what `http_access deny ip_literal`
        # exists to refuse: this policy allowlists by name and never by
        # address (docs/findings.md).
        if re.fullmatch(r"[0-9.]+", entry):
            raise Fail(
                f"{path}: {key} entry `{entry}` is an address, not a hostname. "
                "This policy allowlists by name only."
            )
        entries.append(entry)
    return entries


def load_policy_config(path: Path | None = None) -> PolicyConfig:
    """Read and validate config.toml. Fails closed on anything ambiguous."""
    path = paths.policy_file() if path is None else path
    if not path.is_file():
        raise Fail(f"missing the policy source {path} (it holds the allowlist)")
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    unknown = sorted(set(data) - {"policy"})
    if unknown:
        # `[fixture]` and `[policy.test]` moved to the fixture spec; say so
        # rather than reporting them as an anonymous typo.
        hint = ""
        if {"fixture"} & set(unknown):
            hint = (
                "\n[fixture] and [policy.test] belong in data/lab/fixtures.toml, "
                "which only ipl-lab reads (docs/lab.md)."
            )
        raise Fail(f"{path}: unknown top-level table(s): {', '.join(unknown)}{hint}")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise Fail(f"{path}: missing the [policy] table")
    unknown = sorted(set(policy) - {"allow"})
    if unknown:
        # A typo here (`allows = [...]`) would otherwise silently render an
        # empty or truncated allowlist.
        hint = (
            "\nThe test allowlist belongs in data/lab/fixtures.toml (docs/lab.md)."
            if "test" in unknown
            else ""
        )
        raise Fail(f"{path}: unknown key(s) in [policy]: {', '.join(unknown)}{hint}")
    allow = allow_list(policy.get("allow", []), path, "policy.allow")
    if not allow:
        raise Fail(
            f"{path}: policy.allow must not be empty "
            "(default deny needs explicit allows)"
        )
    return PolicyConfig(tuple(allow))
