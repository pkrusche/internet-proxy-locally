"""Reading a rendered config back and checking what it actually says.

Deliberately independent of the generator: it parses the finished file the
way the engine will, so a template that renders something subtly wrong is
caught by a second opinion rather than by the code that produced it.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from internet_proxy_locally import paths
from internet_proxy_locally.errors import Fail


class _StrictYamlLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys instead of resolving them.

    This is the point of parsing the policies rather than matching them
    with regexes. PyYAML resolves a repeated key by taking the last one;
    the regex reader this replaced found the *first* and stopped, so a
    config carrying both `tls_interception.enabled: false` and a later
    `true` passed validation while every real YAML parser — the engine's
    included — read it as enabled. These files are generated, so a repeated
    key is a generator bug, and catching that before it is written is what
    this validator is for.
    """


def _no_duplicate_keys(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictYamlLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def _load_yaml(text: str, path: Path) -> dict:
    """Parse a rendered YAML policy into a mapping, or fail closed."""
    try:
        doc = yaml.load(text, Loader=_StrictYamlLoader)
    except yaml.YAMLError as exc:
        raise Fail(f"{path}: not valid YAML: {str(exc).replace(chr(10), ' ')}") from exc
    if not isinstance(doc, dict):
        raise Fail(
            f"{path}: expected a YAML mapping at the top level, "
            f"found {type(doc).__name__}"
        )
    return doc


def _mappings(node) -> list[dict]:
    """Every mapping in a parsed document, nested ones included."""
    if isinstance(node, dict):
        return [node] + [m for v in node.values() for m in _mappings(v)]
    if isinstance(node, list):
        return [m for item in node for m in _mappings(item)]
    return []


# The IP ranges config/squid.conf must refuse. Pipelock and Smokescreen
# block private destinations in engine code; for Squid the floor is ours to
# write, so it is also ours to check. Dropping a line from the `private_ip`
# ACL would otherwise be a silent, unreviewable widening of the policy.
REQUIRED_SQUID_DENY_RANGES = (
    ("metadata_ip", "169.254.169.254/32"),
    ("private_ip", "10.0.0.0/8"),
    ("private_ip", "127.0.0.0/8"),
    ("private_ip", "169.254.0.0/16"),
    ("private_ip", "172.16.0.0/12"),
    ("private_ip", "192.168.0.0/16"),
    ("private_ip", "::1/128"),
    ("private_ip", "fc00::/7"),
    ("private_ip", "fe80::/10"),
)


# Which denial page each ACL must be wired to. Squid answers a denial with
# a generic "Access control configuration prevents your request" page
# unless a `deny_info` names the ACL that matched, and that page classifies
# as `unknown` — so the bracketed cause in every comparison table, and the
# ability to tell an SSRF refusal from an allowlist refusal at all, rests
# on this mapping. Renaming an ACL without updating its `deny_info` is a
# silent, valid-looking config that loses every reason (docs/findings.md).
#
# `all` is Squid's built-in catch-all ACL and is deliberately here: it is
# the last rule, so it is what an ordinary allowlist miss reports.
REQUIRED_SQUID_DENY_INFO = {
    "metadata_ip": "ERR_IPL_METADATA",
    "private_ip": "ERR_IPL_PRIVATE_IP",
    "ip_literal": "ERR_IPL_IP_LITERAL",
    "TLS_ports": "ERR_IPL_PORT_NOT_ALLOWED",
    "all": "ERR_IPL_NOT_ALLOWLISTED",
}

# ACLs Squid defines itself, which a config may reference without declaring.
SQUID_BUILTIN_ACLS = ("all", "manager", "localhost", "to_localhost", "to_linklocal")


def _squid_access_rules(text: str) -> list[str]:
    """Every `http_access` line, in file order, whitespace-normalized."""
    return [
        " ".join(line.split())
        for line in text.splitlines()
        if re.match(r"^\s*http_access\s", line)
    ]


def _squid_acl_names(text: str) -> set[str]:
    """Every ACL name the file defines."""
    return {
        match.group(1)
        for match in re.finditer(r"^\s*acl\s+(\S+)\s+\S+", text, re.MULTILINE)
    }


def _squid_deny_info(text: str) -> list[tuple[str, str]]:
    """`deny_info <page> <acl>` pairs, in file order."""
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = re.match(r"^\s*deny_info\s+(\S+)\s+(\S+)\s*$", line)
        if match:
            pairs.append((match.group(1), match.group(2)))
    return pairs


def _squid_acl_values(text: str, name: str, acl_type: str) -> list[str]:
    """Values accumulated across every `acl <name> <type> ...` line."""
    values: list[str] = []
    for line in text.splitlines():
        match = re.match(
            rf"^\s*acl\s+{re.escape(name)}\s+{re.escape(acl_type)}\s+(.*)$", line
        )
        if match:
            values += [tok for tok in match.group(1).split() if not tok.startswith("-")]
    return values


def _squid_regex_to_glob(pattern: str) -> str:
    r"""`\.github\.com$` -> `*.github.com`.

    Anything that is not that exact anchored-suffix shape is returned
    unchanged, so a hand-written pattern surfaces as allowlist drift
    instead of being silently read as a wildcard entry.
    """
    match = re.fullmatch(r"\\\.((?:[\w-]+\\\.)*[\w-]+)\$", pattern)
    if not match:
        return pattern
    return "*." + match.group(1).replace("\\.", ".")


def _require(cond: bool, path: Path, message: str, problems: list[str]) -> None:
    if not cond:
        problems.append(f"{path}: {message}")


def _validate_squid_deny_info(text: str, path: Path) -> list[str]:
    """Every denial page must be wired to an ACL the file still defines.

    Squid does not complain about a `deny_info` naming an ACL that no
    longer exists — it just never fires, and the denial falls back to the
    stock page, which says nothing about why. So renaming `private_ip`
    without updating its `deny_info` turns every SSRF denial from
    `private-ip` into `unknown` while leaving a config that starts, passes
    every other check here, and still denies the right requests. Nothing
    would have caught it; this does.
    """
    problems: list[str] = []
    defined = _squid_acl_names(text) | set(SQUID_BUILTIN_ACLS)
    pairs = _squid_deny_info(text)
    seen: dict[str, str] = {}
    for page, acl in pairs:
        _require(
            acl in defined,
            path,
            f"`deny_info {page} {acl}` names an ACL this file does not define; "
            "the page would never be shown and the denial would lose its reason",
            problems,
        )
        _require(
            acl not in seen,
            path,
            f"`{acl}` has two denial pages ({seen.get(acl)} and {page}); "
            "only one of them can ever be shown",
            problems,
        )
        seen[acl] = page
    for acl, page in REQUIRED_SQUID_DENY_INFO.items():
        _require(
            seen.get(acl) == page,
            path,
            f"`deny_info {page} {acl}` is missing (found "
            f"{seen.get(acl) or 'nothing'} for `{acl}`); without it that denial "
            "reports Squid's generic page and classifies as `unknown`",
            problems,
        )
    return problems


def check_squid_error_pages(text: str, path: Path) -> list[str]:
    """Every page a `deny_info` names must exist in the Squid image.

    Separate from `validate_policy_text` because it is the one Squid check
    that has to look outside the config: a `deny_info` naming a template
    that was never written answers with "Internal Error: Missing Template".
    """
    problems: list[str] = []
    for page, acl in _squid_deny_info(text):
        if not page.startswith("ERR_"):
            continue  # `deny_info 302:https://…` redirects to a URL, not a page
        _require(
            (paths.squid_error_dir() / page).is_file(),
            path,
            f"`deny_info {page} {acl}` names a page that does not exist at "
            f"{paths.squid_error_dir() / page}; Squid would "
            "answer `Internal Error: Missing Template`",
            problems,
        )
    return problems


def validate_policy_file(engine: str, path: Path) -> list[str]:
    """Return a list of human-readable policy problems (empty = OK)."""
    return validate_policy_text(engine, path.read_text(), path)


def validate_policy_text(engine: str, text: str, path: Path) -> list[str]:
    """As `validate_policy_file`, on text that may not be on disk yet.

    `sync_policies()` uses this to check a rendered policy *before* writing
    it, so a generator bug cannot overwrite a working config with a broken
    one. `path` is used only to name the file in the messages.
    """
    problems: list[str] = []
    if engine in ("pipelock", "smokescreen"):
        try:
            doc = _load_yaml(text, path)
        except Fail as exc:
            # A policy that cannot be parsed is a policy that cannot be
            # checked: report it as a problem so the caller fails closed
            # rather than starting on an unvalidated file.
            return [str(exc)]
    if engine == "pipelock":
        _require(doc.get("mode") == "strict", path, "must set `mode: strict`", problems)
        _require(doc.get("enforce") is True, path, "must set `enforce: true`", problems)
        fp = doc.get("forward_proxy") or {}
        _require(
            fp.get("enabled") is True,
            path,
            "forward_proxy.enabled must be true",
            problems,
        )
        _require(
            fp.get("sni_verification") is True,
            path,
            "forward_proxy.sni_verification must be true",
            problems,
        )
        _require(
            fp.get("sni_require_tls") is True,
            path,
            "forward_proxy.sni_require_tls must be true",
            problems,
        )
        ti = doc.get("tls_interception") or {}
        _require(
            ti.get("enabled") is False,
            path,
            "tls_interception.enabled must be false in v1",
            problems,
        )
        _require(
            bool(doc.get("api_allowlist")),
            path,
            "api_allowlist must not be empty (default deny needs explicit allows)",
            problems,
        )
    elif engine == "smokescreen":
        _require(doc.get("version") == "v1", path, "must set `version: v1`", problems)
        # Every mapping, not just `default`: `services` carries per-role
        # entries with the same shape, and one of those set to `open` is
        # an open proxy for that role.
        _require(
            not any(m.get("action") == "open" for m in _mappings(doc)),
            path,
            "`action: open` is forbidden (no open proxy mode)",
            problems,
        )
        default_block = doc.get("default") or {}
        _require(
            default_block.get("action") == "enforce",
            path,
            "default.action must be `enforce`",
            problems,
        )
        _require(
            bool(default_block.get("allowed_domains")),
            path,
            "default.allowed_domains must not be empty",
            problems,
        )
    elif engine == "squid":
        rules = _squid_access_rules(text)
        _require(
            bool(rules) and rules[-1] == "http_access deny all",
            path,
            "the last http_access rule must be `http_access deny all` (default deny)",
            problems,
        )
        _require(
            not any(re.match(r"http_access\s+allow\s+all\b", rule) for rule in rules),
            path,
            "`http_access allow all` is forbidden (no open proxy mode)",
            problems,
        )
        # First match wins, so an allow placed above the SSRF floors would
        # let an allowlisted hostname reach a private address.
        first_allow = next(
            (i for i, rule in enumerate(rules) if rule.startswith("http_access allow")),
            len(rules),
        )
        # `ip_literal` is here for the same reason as the SSRF floors but a
        # different failure: Squid retries a `dstdomain` miss as a reverse
        # lookup, so an address-form destination reaches the allowlist under
        # whatever name its PTR claims. Refusing it earlier is the only fix
        # Squid offers (docs/findings.md).
        for acl in ("metadata_ip", "private_ip", "ip_literal"):
            index = next(
                (
                    i
                    for i, rule in enumerate(rules)
                    if rule == f"http_access deny {acl}"
                ),
                None,
            )
            _require(
                index is not None and index < first_allow,
                path,
                f"`http_access deny {acl}` must appear before the first `http_access allow` "
                "(http_access is first-match-wins)",
                problems,
            )
        for acl, cidr in REQUIRED_SQUID_DENY_RANGES:
            _require(
                cidr in _squid_acl_values(text, acl, "dst"),
                path,
                f"the `{acl}` ACL must deny {cidr}",
                problems,
            )
        _require(
            re.search(r"^\s*ssl_bump\s+.*\bbump\b", text, re.MULTILINE) is None,
            path,
            "`ssl_bump ... bump` is forbidden (no TLS interception in v1)",
            problems,
        )
        _require(
            re.search(r"^\s*cache\s+deny\s+all\b", text, re.MULTILINE) is not None,
            path,
            "must set `cache deny all` (a cache hit is a response nobody re-authorized)",
            problems,
        )
        problems += _validate_squid_deny_info(text, path)
        _require(
            len(policy_allowlist_text("squid", text)) > 0,
            path,
            "the allowlist must not be empty (default deny needs explicit allows)",
            problems,
        )
    else:
        raise Fail(f"unknown engine: {engine}")
    return problems


def policy_allowlist(engine: str, path: Path) -> set[str]:
    """The engine's allowlist, normalized to the shared `d` / `*.d` forms of
    docs/policy.md so the three files can be compared directly."""
    return policy_allowlist_text(engine, path.read_text())


def policy_allowlist_text(engine: str, text: str) -> set[str]:
    """As `policy_allowlist`, on text that may not be on disk yet."""
    if engine == "squid":
        entries = set(_squid_acl_values(text, "allowlist_exact", "dstdomain"))
        entries.update(
            _squid_regex_to_glob(pattern)
            for pattern in _squid_acl_values(text, "allowlist_wild", "dstdom_regex")
        )
        return entries
    doc = _load_yaml(text, Path(f"<{engine} policy>"))
    if engine == "pipelock":
        return set(doc.get("api_allowlist") or ())
    return set((doc.get("default") or {}).get("allowed_domains") or ())
