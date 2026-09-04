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
    # Opt-in, off by default. See docs/tls-interception.md — turning this on
    # makes pipelock/squid the real TLS endpoint for allowlisted HTTPS
    # destinations instead of an opaque CONNECT tunnel.
    tls_interception: bool = False

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


def reject_unknown(
    mapping: dict, known: set[str], path: Path, where: str, hint: str = ""
) -> None:
    """Refuse any key outside `known`, naming all of them at once.

    Both config sources are strict about this for the same reason: a typo
    (`allows = [...]`) is not an error TOML can catch, and the result would
    be a silently empty or truncated allowlist — which is an open policy.
    Every table in both files goes through here so that none of them can be
    the lenient one. `hint` is the sentence that names the fix where there
    is a specific one, such as a key that moved to the other file.
    """
    unknown = sorted(set(mapping) - known)
    if unknown:
        raise Fail(f"{path}: unknown {where}: {', '.join(unknown)}{hint}")


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
    reject_unknown(
        data,
        {"policy"},
        path,
        "top-level table(s)",
        # `[fixture]` and `[policy.test]` moved to the fixture spec; say so
        # rather than reporting them as an anonymous typo.
        hint="\n[fixture] and [policy.test] belong in data/lab/fixtures.toml, "
        "which only ipl-lab reads (docs/lab.md)."
        if "fixture" in data
        else "",
    )
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise Fail(f"{path}: missing the [policy] table")
    reject_unknown(
        policy,
        {"allow", "tls_interception"},
        path,
        "key(s) in [policy]",
        hint="\nThe test allowlist belongs in data/lab/fixtures.toml (docs/lab.md)."
        if "test" in policy
        else "",
    )
    allow = allow_list(policy.get("allow", []), path, "policy.allow")
    if not allow:
        raise Fail(
            f"{path}: policy.allow must not be empty "
            "(default deny needs explicit allows)"
        )
    tls_interception = policy.get("tls_interception", False)
    if not isinstance(tls_interception, bool):
        raise Fail(f"{path}: policy.tls_interception must be a boolean")
    return PolicyConfig(tuple(allow), tls_interception)
