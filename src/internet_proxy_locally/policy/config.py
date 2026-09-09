"""config.toml: the allowlist, read once and validated."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.errors import Fail

# Accept exact hosts or *.domain (subdomains only); see docs/policy.md.
ALLOW_ENTRY = re.compile(
    r"\A(?:\*\.)?(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\Z"
)


@dataclass(frozen=True)
class PolicyConfig:
    """The shared logical policy, read from config.toml."""

    allow: tuple[str, ...]
    tls_interception: bool = False

    @staticmethod
    def exact(entries: tuple[str, ...] | list[str]) -> list[str]:
        return [entry for entry in entries if not entry.startswith("*.")]

    @staticmethod
    def wild(entries: tuple[str, ...] | list[str]) -> list[str]:
        return [entry for entry in entries if entry.startswith("*.")]


def reject_unknown(
    mapping: dict, known: set[str], path: Path, where: str, hint: str = ""
) -> None:
    """Refuse any key outside `known`"""
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
        entry = item.strip().lower()
        if entry.endswith("."):
            raise Fail(f"{path}: {key} entry `{item}` must not have a trailing dot")
        wildcard = entry.startswith("*.")
        name = entry[2:] if wildcard else entry
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise Fail(
                f"{path}: {key} entry `{item}` is not a valid allowlist form "
                f"or IDNA name: {exc}"
            ) from exc
        entry = ("*." if wildcard else "") + name
        if len(name) > 253:
            raise Fail(
                f"{path}: {key} entry `{item}` exceeds the 253-byte DNS name limit"
            )
        if entry in entries:
            raise Fail(f"{path}: {key} lists `{entry}` twice")
        if not ALLOW_ENTRY.match(entry):
            raise Fail(
                f"{path}: {key} entry `{entry}` is not a valid allowlist form. "
                "Use `example.com` for one host or `*.example.com` for its "
                "subdomains (docs/policy.md)."
            )
        # The hostname regex also accepts IPv4 literals; reject them separately.
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
