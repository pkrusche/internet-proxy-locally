#!/usr/bin/env -S uv run --quiet python
"""internet-proxy-locally lab — the adversarial test policy and the engine
comparison.

The other lane. `./run.py` starts a proxy on the reviewed allowlist in
config.toml and knows nothing about any of this. This script owns
everything that exists to *measure* an engine rather than to run one:

  * the test policy and DNS fixture in lab/fixtures.toml, rendered into
    lab/config/;
  * the dnsmasq fixture container that serves the mixed-answer and
    rebinding records;
  * `checks/egress.py --full`, the adversarial group, which only means
    anything with both of those in place;
  * the three-engine comparison and the generated tables in
    docs/findings.md.

Nothing here can affect an operational run: the fixture names live under
`.test`, `./run.py` never reads lab/fixtures.toml, and any `./run.py up`
removes the fixture container.

Run through uv (see the shebang). See docs/lab.md.
"""

from __future__ import annotations

import argparse
import difflib
import ipaddress
import re
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

import run  # noqa: E402  (the prod lane; imported for reuse, never modified)
from run import Backend, Fail, ServiceSpec  # noqa: E402

LAB_DIR = REPO_ROOT / "lab"
FIXTURE_FILE = LAB_DIR / "fixtures.toml"
LAB_CONFIG_DIR = LAB_DIR / "config"
DNS_FIXTURE = "dnsfixture"
FINDINGS = REPO_ROOT / "docs" / "findings.md"

# The allowlist grammar and its parser, shared with the operational lane:
# a test-policy entry that config.toml would reject is not a test policy,
# it is a typo with an adversarial name.
_ALLOW_ENTRY = run._ALLOW_ENTRY
_allow_list = run._allow_list


def test_config_path(spec: ServiceSpec) -> Path:
    """`config/squid.conf` -> `lab/config/squid.test.conf`.

    By convention rather than by a key in services/*.toml: the engine
    definitions describe how to run an engine, and where this lane keeps
    its rendered fixtures is not their business.
    """
    name = Path(spec.config_file).name
    stem, _, suffix = name.partition(".")
    return LAB_CONFIG_DIR / f"{stem}.test.{suffix}"


# ---------------------------------------------------------------------------
# The test policy and the fixture records (lab/fixtures.toml)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FixtureConfig:
    """The local DNS fixture's records, from `[fixture]` in lab/fixtures.toml.

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


# The reserved TLD the fixture's names live under (RFC 6761). Anything in
# `[policy.test].allow` under it is a fixture name and must have a record
# behind it — that is the half of the sync `[fixture]` cannot enforce by
# being the source of the hosts file.
FIXTURE_TLD = ".test"


def _covered_by(name: str, entries: "tuple[str, ...]") -> bool:
    """Does the allowlist `entries` permit `name`, in either shared form?"""
    if name in entries:
        return True
    return any(entry.startswith("*.") and name.endswith(entry[1:])
               for entry in entries)


def _public_address(raw: str, path: Path, what: str) -> str:
    """An address that must be routable — the half of a fixture answer an
    engine is allowed to reach, and the one `ptr-allowlist` connects to."""
    address = _address(raw, path, what)
    if _private_address(address):
        raise Fail(f"{path}: {what} is `{raw}`, which is not a public address; "
                   "the check it backs would be graded by the SSRF floors "
                   "rather than by the rule it is testing")
    return address


def _address(raw: str, path: Path, what: str) -> str:
    if not isinstance(raw, str):
        raise Fail(f"{path}: {what} must be a string (found {raw!r})")
    try:
        ipaddress.ip_address(raw)
    except ValueError as exc:
        raise Fail(f"{path}: {what} is not an IP address: {raw!r}") from exc
    return raw


def _private_address(raw: str) -> bool:
    addr = ipaddress.ip_address(raw)
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _fixture_config(raw: object, path: Path, allow: "list[str]",
                    allow_test: "list[str]") -> FixtureConfig:
    """Read and validate `[fixture]`, cross-checked against the allowlists.

    Everything here exists so that one edit cannot half-land: a record the
    test policy does not allowlist would be denied by name and grade
    nothing, and a `[policy.test]` fixture name with no record behind it
    would resolve to NXDOMAIN and skip.
    """
    if not isinstance(raw, dict):
        raise Fail(f"{path}: missing the [fixture] table (it holds the DNS "
                   "fixture's records; lab/config/dns-fixture.hosts is "
                   "rendered from it)")
    known = {"control", "rebind_zone", "ptr_address", "ptr_claims", "records"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise Fail(f"{path}: unknown key(s) in [fixture]: {', '.join(unknown)}")
    missing = sorted(known - set(raw))
    if missing:
        raise Fail(f"{path}: [fixture] is missing {', '.join(missing)}")

    entries = raw["records"]
    if not isinstance(entries, dict) or not entries:
        raise Fail(f"{path}: [fixture.records] must be a non-empty table of "
                   "`\"name\" = [\"addr\", ...]`")
    records: list[tuple[str, tuple[str, ...]]] = []
    allowed = tuple(allow_test)
    for name, addresses in entries.items():
        if not _ALLOW_ENTRY.match(name) or name.startswith("*."):
            raise Fail(f"{path}: [fixture.records] key `{name}` is not a hostname")
        if not name.endswith(FIXTURE_TLD):
            raise Fail(f"{path}: [fixture.records] key `{name}` must be under "
                       f"`{FIXTURE_TLD}`, the reserved TLD that can never "
                       "resolve publicly")
        if not isinstance(addresses, list) or not addresses:
            raise Fail(f"{path}: [fixture.records] `{name}` must list at least "
                       "one address")
        parsed = tuple(_address(a, path, f"[fixture.records] `{name}`") for a in addresses)
        if len(set(parsed)) != len(parsed):
            raise Fail(f"{path}: [fixture.records] `{name}` repeats an address")
        if _covered_by(name, tuple(allow)):
            # The fixture's names belong to the test policy alone. In the
            # real one they would be a shipped allowlist entry for a name
            # that resolves to whatever the fixture says, private addresses
            # included — and `./run.py up` never starts the fixture, so the
            # entry would be dead weight at best.
            raise Fail(f"config.toml allows the fixture name `{name}`. "
                       "Fixture names belong in [policy.test] here only; the "
                       "operational policy must never allowlist a name the "
                       "fixture answers.")
        if not _covered_by(name, allowed):
            raise Fail(f"{path}: [fixture.records] `{name}` is not allowlisted by "
                       "[policy.test].allow, so the fixture would be refused by "
                       "name and the check would grade nothing")
        records.append((name, parsed))

    control = raw["control"]
    by_name = dict(records)
    if control not in by_name:
        raise Fail(f"{path}: [fixture] control `{control}` is not one of the "
                   f"records ({', '.join(by_name)})")
    if len(by_name[control]) != 1:
        raise Fail(f"{path}: [fixture] control `{control}` must resolve to exactly "
                   "one address; it is the probe that proves the fixture is live")
    _public_address(by_name[control][0], path, f"the control record `{control}`")

    orderings: set[tuple[bool, ...]] = set()
    for name, addresses in records:
        if name == control:
            continue
        private = tuple(_private_address(a) for a in addresses)
        if not any(private) or all(private):
            raise Fail(f"{path}: [fixture.records] `{name}` must mix one public and "
                       "one private address — that mixture is the whole content of "
                       "`dns-mixed-answers`")
        orderings.add(private)
    if len(orderings) < 2:
        raise Fail(f"{path}: [fixture.records] must serve both answer orderings "
                   "(public first and private first), or an engine that validates "
                   "only the first address would not be distinguished from one that "
                   "validates all of them")

    rebind_zone = raw["rebind_zone"]
    if not isinstance(rebind_zone, str) or not _ALLOW_ENTRY.match(rebind_zone) \
            or not rebind_zone.endswith(FIXTURE_TLD):
        raise Fail(f"{path}: [fixture] rebind_zone must be a hostname under "
                   f"`{FIXTURE_TLD}` (found {rebind_zone!r})")
    if _covered_by(f"probe.{rebind_zone}", tuple(allow)):
        raise Fail(f"config.toml allows the rebinding zone "
                   f"`{rebind_zone}`. Its answers change between lookups and end "
                   "at a private address; it belongs in [policy.test] here only.")
    if f"*.{rebind_zone}" not in allow_test:
        raise Fail(f"{path}: [fixture] rebind_zone `{rebind_zone}` needs "
                   f"`*.{rebind_zone}` in [policy.test].allow; a denial has to be "
                   "attributable to the address the engine was handed, not to the name")

    ptr_address = _public_address(raw["ptr_address"], path, "[fixture] ptr_address")
    served = {a for _, addresses in records for a in addresses}
    if ptr_address in served:
        raise Fail(f"{path}: [fixture] ptr_address `{ptr_address}` is also a record "
                   "address. dnsmasq synthesizes PTR records from the records, so "
                   "sharing an address would let a bare-IP destination match the "
                   "allowlist under a fixture name")
    ptr_claims = raw["ptr_claims"]
    if not isinstance(ptr_claims, str) or ptr_claims not in allow:
        raise Fail(f"{path}: [fixture] ptr_claims must be an exact entry in "
                   f"config.toml's allowlist (found {ptr_claims!r}); "
                   "`ptr-allowlist` asks whether a PTR record can satisfy the "
                   "*real* allowlist")

    # The other direction: a `.test` name in the test policy with no record
    # behind it resolves to NXDOMAIN and silently skips its check.
    for entry in allow_test:
        if not entry.endswith(FIXTURE_TLD):
            continue
        if entry.startswith("*."):
            if entry != f"*.{rebind_zone}":
                raise Fail(f"{path}: policy.test.allow has `{entry}`, which no "
                           f"[fixture] zone serves (the only one is *.{rebind_zone})")
        elif entry not in by_name:
            raise Fail(f"{path}: policy.test.allow has `{entry}`, which "
                       "[fixture.records] does not serve")

    return FixtureConfig(control=control, rebind_zone=rebind_zone,
                         ptr_address=ptr_address, ptr_claims=ptr_claims,
                         records=tuple(records))



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


def load_lab_config(path: Path = FIXTURE_FILE) -> LabConfig:
    """Read lab/fixtures.toml, cross-checked against the real allowlist."""
    if not path.is_file():
        raise Fail(f"missing the test policy source {path} "
                   "(it holds [policy.test] and the DNS fixture records)")
    allow = list(run.load_policy_config().allow)
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    unknown = sorted(set(data) - {"policy", "fixture"})
    if unknown:
        raise Fail(f"{path}: unknown top-level table(s): {', '.join(unknown)}")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise Fail(f"{path}: missing the [policy.test] table")
    unknown = sorted(set(policy) - {"test"})
    if unknown:
        raise Fail(f"{path}: unknown key(s) in [policy]: {', '.join(unknown)}. "
                   "The operational allowlist lives in config.toml.")
    test = policy.get("test", {})
    if not isinstance(test, dict):
        raise Fail(f"{path}: [policy.test] must be a table")
    unknown = sorted(set(test) - {"allow"})
    if unknown:
        raise Fail(f"{path}: unknown key(s) in [policy.test]: {', '.join(unknown)}")
    allow_test = _allow_list(test.get("allow", []), path, "policy.test.allow")
    if not allow_test:
        raise Fail(f"{path}: policy.test.allow must not be empty; without it the "
                   "test policy is the real one and the adversarial checks all skip")
    overlap = sorted(set(allow) & set(allow_test))
    if overlap:
        raise Fail(f"{path}: policy.test.allow repeats {', '.join(overlap)}, "
                   "which config.toml already permits everywhere")
    fixture = _fixture_config(data.get("fixture"), path, allow, allow_test)
    return LabConfig(tuple(allow), tuple(allow_test), fixture)


# ---------------------------------------------------------------------------
# Rendering lab/config/
# ---------------------------------------------------------------------------


def render_test_policies(config: LabConfig | None = None) -> dict[Path, str]:
    """Render the `.test` configs and the fixture hosts file.

    Same templates and same Jinja environment as `./run.py policy` — only
    `test_policy` differs, so the two lanes cannot disagree about anything
    but the allowlist itself.
    """
    config = load_lab_config() if config is None else config
    env = run.jinja_env()
    exact, wild = run.PolicyConfig.exact, run.PolicyConfig.wild
    rendered: dict[Path, str] = {}
    for engine in run.ENGINES:
        spec = ServiceSpec.load(engine)
        name = run._template_name(spec)
        if not (run.TEMPLATE_DIR / name).is_file():
            raise Fail(f"missing template: {run.TEMPLATE_DIR / name}")
        rendered[test_config_path(spec)] = env.get_template(name).render(
            template_name=f"templates/{name}",
            test_policy=True,
            allow=list(config.allow),
            allow_test=list(config.allow_test),
            allow_exact=exact(config.allow),
            allow_wild=wild(config.allow),
            allow_test_exact=exact(config.allow_test),
            allow_test_wild=wild(config.allow_test),
        )
    rendered.update(_render_fixture_hosts(env, config.fixture))
    return rendered


def _render_fixture_hosts(env, fixture: FixtureConfig) -> dict[Path, str]:
    """Render lab/config/dns-fixture.hosts from `[fixture]`.

    The hosts file is not a policy — nothing in it is enforced — but it is
    the other half of the test policy, and hand-syncing it against
    `[policy.test].allow` is exactly what `load_lab_config()` refuses to
    leave to care (docs/lab.md).
    """
    spec = fixture_spec()
    name = run._template_name(spec)
    if not (run.TEMPLATE_DIR / name).is_file():
        raise Fail(f"missing template: {run.TEMPLATE_DIR / name}")
    rows = []
    for record, addresses in fixture.records:
        shape = ["private" if _private_address(a) else "public" for a in addresses]
        rows.append({
            "name": record,
            "addresses": list(addresses),
            "role": "control" if record == fixture.control else "mixed",
            "shape": f"{shape[0].capitalize()} answer first, {shape[-1]} second",
        })
    text = env.get_template(name).render(
        template_name=f"templates/{name}",
        test_policy=True,   # for the shared banner: this file is lab.py's
        fixture=fixture,
        fixture_records=rows,
    )
    return {REPO_ROOT / spec.config_file: text}


def check_rendered_test_policies(rendered: dict[Path, str]) -> list[str]:
    """`run.check_rendered_policies()` plus the superset rule.

    The superset rule is the one check that needs both lanes at once, so it
    lives in the lane that has both: every entry the operational policy
    allows must still be allowed by the test policy, or a `.test` run would
    be measuring a *narrower* policy than the one that ships and its
    verdicts would not transfer.
    """
    problems = run.check_rendered_policies(rendered)
    for engine in run.ENGINES:
        spec = ServiceSpec.load(engine)
        real_path = spec.config_path()
        test_path = test_config_path(spec)
        real = run.policy_allowlist(engine, real_path)
        test = run.policy_allowlist_text(engine, rendered[test_path])
        for entry in sorted(real - test):
            problems.append(f"{test_path}: the test policy must be a strict superset "
                            f"of the real one, but drops `{entry}`")
    return problems


def sync_test_policies(config: LabConfig | None = None) -> list[Path]:
    """Regenerate lab/config/; return what changed. Validates before writing."""
    rendered = render_test_policies(config)
    problems = check_rendered_test_policies(rendered)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("refusing to write a test policy that fails validation (fail closed)")
    changed: list[Path] = []
    for path, text in sorted(rendered.items()):
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            changed.append(path)
    return changed


# ---------------------------------------------------------------------------
# The DNS fixture container
# ---------------------------------------------------------------------------


def fixture_spec() -> ServiceSpec:
    return ServiceSpec.load(DNS_FIXTURE, root=LAB_DIR)


def start_dns_fixture(backend: Backend) -> str:
    """Start the dnsmasq fixture container and return its address.

    No host port is published: the fixture is reachable from the engine
    container and from nothing else.
    """
    spec = fixture_spec()
    image = spec.run_image_ref()
    if not backend.image_present(image):
        raise Fail(
            f"the DNS fixture image {image} is not built — run `./lab.py setup`.\n"
            "`./lab.py check` needs it to serve the mixed-answer records "
            "(docs/lab.md)."
        )
    backend.remove_container(spec.container_name)
    backend.run_detached(
        name=spec.container_name,
        image=image,
        publish_host="",
        publish_port=0,
        internal_port=spec.internal_port,
        mounts=spec.mounts(),
        args=spec.args,
        publish=False,
    )
    deadline = time.monotonic() + run.HEALTH_WAIT_SECONDS
    while time.monotonic() < deadline:
        address = backend.container_ip(spec.container_name)
        if address:
            return address
        if backend.container_state(spec.container_name) != "running":
            break
        time.sleep(0.5)
    logs = backend.tail_logs(spec.container_name)
    raise Fail(f"the DNS fixture container did not report an address\n"
               f"--- last container logs ---\n{logs}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_policy(opts: argparse.Namespace) -> int:
    rendered = render_test_policies()
    problems = check_rendered_test_policies(rendered)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("configuration validation failed")

    if not opts.check:
        for path in sync_test_policies():
            print(f"regenerated {path.relative_to(REPO_ROOT)} from lab/fixtures.toml")
        print("lab configs: up to date with config.toml + lab/fixtures.toml")
        return 0

    stale = [(path, body) for path, body in sorted(rendered.items())
             if not path.is_file() or path.read_text(encoding="utf-8") != body]
    for path, body in stale:
        rel = path.relative_to(REPO_ROOT)
        current = (path.read_text(encoding="utf-8").splitlines(keepends=True)
                   if path.is_file() else [])
        sys.stdout.writelines(difflib.unified_diff(
            current, body.splitlines(keepends=True),
            fromfile=f"{rel} (on disk)", tofile=f"{rel} (from lab/fixtures.toml)"))
    if stale:
        names = ", ".join(str(path.relative_to(REPO_ROOT)) for path, _ in stale)
        print(f"\nSTALE: {names}", file=sys.stderr)
        print("Run `./lab.py policy` to regenerate, then commit.", file=sys.stderr)
        return 1
    print("lab configs: up to date with config.toml + lab/fixtures.toml")
    return 0


def cmd_setup(opts: argparse.Namespace) -> int:
    """Prepare every engine plus the DNS fixture image.

    The comparison measures all three engines, so this prepares all three
    — unlike `./run.py setup`, which prepares the one you are going to run.
    """
    backend = run.detect_backend(opts.backend)
    print(f"selected backend: {backend.name}")
    for path in sync_test_policies():
        print(f"regenerated {path.relative_to(REPO_ROOT)} from lab/fixtures.toml")
    for engine in run.ENGINES:
        run.prepare_engine(backend, engine, rebuild=opts.rebuild)
    run._setup_package_image(backend, fixture_spec(), rebuild=opts.rebuild)
    print("lab setup complete")
    return 0


def cmd_up(opts: argparse.Namespace) -> int:
    engine = opts.engine or run.DEFAULT_ENGINE
    spec = ServiceSpec.load(engine)
    backend = run.detect_backend(opts.backend)
    host, port = run.endpoint()

    for path in sync_test_policies():
        print(f"regenerated {path.relative_to(REPO_ROOT)} from lab/fixtures.toml")

    config_path = test_config_path(spec)
    if not config_path.is_file():
        raise Fail(f"missing test policy: {config_path} — run `./lab.py policy`")
    problems = run.validate_policy_file(engine, config_path)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("refusing to start with an invalid policy (fail closed)")

    print("NOTE: starting with the TEST policy — an allowlist that includes "
          "*.nip.io, *.sslip.io and the local fixture zones, and a dnsmasq "
          "container answering them. This is not an operational proxy. "
          "Run `./run.py up` for one.")

    fixture = fixture_spec()
    fixture_dns = start_dns_fixture(backend)
    print(f"started the DNS fixture at {fixture_dns} (serving {fixture.config_file})")

    run.start_engine(backend, spec, config_path, dns=fixture_dns,
                     keep_fixture=True)
    print(f"clients: export HTTP_PROXY=http://{host}:{port} HTTPS_PROXY=http://{host}:{port}")
    return 0


def cmd_down(opts: argparse.Namespace) -> int:
    """Identical to `./run.py down`, and delegated rather than repeated.

    Both lanes remove every engine plus the DNS fixture: "what this
    repository owns" has to have exactly one definition, or a container
    added to one list and not the other survives a `down` in the other
    lane.
    """
    return run.cmd_down(opts)


def cmd_check(opts: argparse.Namespace) -> int:
    """The `full` group of checks/egress.py: the adversarial suite."""
    backend = run.detect_backend(opts.backend)
    cmd = run.egress_command(backend, opts.engine, "lab.py")
    # dns-rebinding grades on what the fixture observed, so the checker
    # needs its log stream too.
    fixture = fixture_spec()
    if backend.container_state(fixture.container_name) == "running":
        cmd += ["--fixture-container", fixture.container_name]
    else:
        print("WARNING: the DNS fixture is not running; the fixture-dependent "
              "checks will skip. `./lab.py up` starts it.", file=sys.stderr)
    cmd.append("--full")
    if opts.json:
        cmd.append("--json")
    return subprocess.run(cmd).returncode


def cmd_pin(opts: argparse.Namespace) -> int:
    """Pin the DNS fixture's apk versions. Engine pins are `./run.py pin`."""
    spec = fixture_spec()
    backend = run.detect_backend(opts.backend)
    names = sorted(spec.packages)
    base = spec.base_image
    if not base:
        raise Fail(f"{spec.toml_path}: [build] base_image is required to pin")
    print(f"asking {base} which versions of {', '.join(names)} it would install")
    output = backend.run_once(base, [
        "sh", "-c",
        f"apk update >/dev/null 2>&1 && apk list {' '.join(names)} 2>/dev/null",
    ])
    for name in names:
        versions = re.findall(rf"^{re.escape(name)}-(\d[\w.]*-r\d+)\s", output, re.M)
        if not versions:
            raise Fail(f"could not read a {name} version from {base}.\n"
                       f"Check it by hand (`apk list {name}` in that image) and put "
                       f"it in {spec.toml_path}")
        resolved = sorted(set(versions))[-1]
        run._write_pin(spec.toml_path, name, resolved)
        print(f"pinned dnsfixture {name}={resolved} (from {base})")
    print("review the change and commit it; then run `./lab.py setup`")
    return 0


def _report():
    """Import scripts/report.py lazily — only the report commands need it."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import report
    return report


def cmd_measure(opts: argparse.Namespace) -> int:
    """Measure every engine, then regenerate the tables in docs/findings.md.

    Per engine: setup, `up` on the test policy with the fixture, the full
    suite as JSON into results/<engine>.json. Finishes with a `down`, so no
    engine and no fixture is left running on a test allowlist.
    """
    return _report().measure_all(backend=opts.backend, engines=run.ENGINES)


def cmd_report(opts: argparse.Namespace) -> int:
    """Regenerate (or verify) the generated blocks in docs/findings.md."""
    return _report().write_findings(check=opts.check)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab.py",
        description="The adversarial test policy, the DNS fixture and the "
                    "three-engine comparison. Never an operational proxy — "
                    "use ./run.py for that.",
    )
    parser.add_argument("--engine", choices=run.ENGINES, default=None,
                        help=f"proxy engine (default: {run.DEFAULT_ENGINE})")
    parser.add_argument("--backend", choices=run.BACKENDS, default=None,
                        help="container backend (default: Apple `container` on macOS "
                             "when installed, else docker)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_policy = sub.add_parser("policy", help="render lab/config/* from lab/fixtures.toml")
    p_policy.add_argument("--check", action="store_true",
                          help="report drift as a diff and exit 1 instead of writing")
    p_policy.set_defaults(func=cmd_policy)

    p_setup = sub.add_parser("setup", help="prepare every engine plus the DNS fixture image")
    p_setup.add_argument("--rebuild", action="store_true",
                         help="rebuild locally built images even if present")
    p_setup.set_defaults(func=cmd_setup)

    sub.add_parser("up", help="start the DNS fixture and an engine on the TEST policy") \
       .set_defaults(func=cmd_up)
    sub.add_parser("down", help="remove the engine and the DNS fixture") \
       .set_defaults(func=cmd_down)

    p_check = sub.add_parser("check", help="the full adversarial egress suite")
    p_check.add_argument("--json", action="store_true", help="machine-readable results")
    p_check.set_defaults(func=cmd_check)

    sub.add_parser("measure",
                   help="measure all three engines, write results/, regenerate "
                        "docs/findings.md") \
       .set_defaults(func=cmd_measure)

    p_report = sub.add_parser("report",
                              help="regenerate docs/findings.md's tables from results/")
    p_report.add_argument("--check", action="store_true",
                          help="report drift as a diff and exit 1 instead of writing")
    p_report.set_defaults(func=cmd_report)

    sub.add_parser("pin", help="record the DNS fixture's apk pins (needs network)") \
       .set_defaults(func=cmd_pin)
    return parser


def main(argv: list[str] | None = None) -> int:
    opts = build_parser().parse_args(argv)
    try:
        return opts.func(opts)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
