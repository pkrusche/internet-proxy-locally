#!/usr/bin/env python3
"""internet-proxy-locally — local containerized Internet filtering proxy.

One CLI for both Docker and Apple `container`. Exposes a single stable
host endpoint (http://127.0.0.1:18080) backed by Pipelock, Smokescreen or
Squid, with a default-deny destination policy.

Stdlib only; Python 3.11+.
"""

from __future__ import annotations

import sys

# Ahead of the stdlib imports on purpose. `tomllib` arrived in 3.11, so on
# an older interpreter (macOS Command Line Tools still ships 3.9) the next
# import would die with a bare ModuleNotFoundError that names a module the
# reader has no reason to connect to a version requirement.
if sys.version_info < (3, 11):
    sys.exit(
        f"error: Python 3.11+ required, found {sys.version.split()[0]} "
        f"at {sys.executable}.\n"
        "This repository is a uv project: run `uv sync` once, then "
        "`uv run ./run.py ...`."
    )

import argparse
import difflib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

DEFAULT_ENDPOINT = "127.0.0.1:18080"
ENGINES = ("pipelock", "smokescreen", "squid")
DEFAULT_ENGINE = "pipelock"
# Engines whose image this repository builds locally rather than pulling.
BUILT_ENGINES = ("smokescreen", "squid")
BACKENDS = ("docker", "container")

HEALTH_WAIT_SECONDS = 15.0

# The local DNS fixture: a dnsmasq container serving
# config/dns-fixture.hosts, started only by `up --test-policy` so that
# `check --full` can grade dns-mixed-answers. Not an engine — it never
# appears in ENGINES — but it is pinned, built and torn down like one.
#
# It has to be a resolver rather than a bind-mounted /etc/hosts: duplicate
# names in a hosts file collapse to one address (musl keeps the first,
# Squid's parser the last), so the engine would never see a multi-address
# answer. dnsmasq's --addn-hosts aggregates them.
DNS_FIXTURE = "dnsfixture"
PINNABLE = ENGINES + (DNS_FIXTURE,)


class Fail(Exception):
    """Fatal, user-facing error."""


def endpoint() -> tuple[str, int]:
    """Host endpoint; IPL_ENDPOINT override exists for the test suite only."""
    raw = os.environ.get("IPL_ENDPOINT", DEFAULT_ENDPOINT)
    host, _, port = raw.rpartition(":")
    return host, int(port)


# ---------------------------------------------------------------------------
# Service specs (services/*.toml)
# ---------------------------------------------------------------------------


@dataclass
class ServiceSpec:
    engine: str
    image_repository: str
    image_tag: str = ""
    image_digest: str = ""
    source_repo: str = ""
    source_ref: str = ""
    packages: dict[str, str] = field(default_factory=dict)
    go_image: str = ""
    runtime_image: str = ""
    base_image: str = ""
    container_name: str = ""
    internal_port: int = 0
    config_file: str = ""
    test_config_file: str = ""
    config_mount: str = ""
    extra_config_file: str = ""
    extra_config_mount: str = ""
    args: list[str] = field(default_factory=list)

    @property
    def toml_path(self) -> Path:
        return REPO_ROOT / "services" / f"{self.engine}.toml"

    @classmethod
    def load(cls, engine: str) -> "ServiceSpec":
        path = REPO_ROOT / "services" / f"{engine}.toml"
        if not path.is_file():
            raise Fail(f"missing service definition: {path}")
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        image = data.get("image", {})
        source = data.get("source", {})
        build = data.get("build", {})
        container = data.get("container", {})
        spec = cls(
            engine=engine,
            image_repository=image.get("repository", ""),
            image_tag=image.get("tag", ""),
            image_digest=image.get("digest", ""),
            source_repo=source.get("repo", ""),
            source_ref=source.get("ref", ""),
            packages=dict(source.get("packages", {})),
            go_image=build.get("go_image", ""),
            runtime_image=build.get("runtime_image", ""),
            base_image=build.get("base_image", ""),
            container_name=container.get("name", ""),
            internal_port=int(container.get("internal_port", 0)),
            config_file=container.get("config_file", ""),
            test_config_file=container.get("test_config_file", ""),
            config_mount=container.get("config_mount", ""),
            extra_config_file=container.get("extra_config_file", ""),
            extra_config_mount=container.get("extra_config_mount", ""),
            args=list(container.get("args", [])),
        )
        if not spec.image_repository or not spec.container_name or not spec.internal_port:
            raise Fail(f"{path}: image.repository, container.name and container.internal_port are required")
        if spec.image_tag == "latest":
            raise Fail(f"{path}: refusing to use a 'latest' tag; pin a release")
        if "--unsafe-allow-private-ranges" in spec.args or "--danger-allow-access-to-private-ranges" in spec.args:
            raise Fail(f"{path}: private-range blocking must never be disabled")
        return spec

    @property
    def primary_package_version(self) -> str:
        """The version the image is tagged with: the package matching the
        service name where there is one (squid), else the first pinned."""
        if self.engine in self.packages:
            return self.packages[self.engine]
        return next(iter(self.packages.values()), "")

    @property
    def pin_kind(self) -> str:
        """What kind of thing this service is pinned by, inferred from which
        keys its TOML defines: an OCI digest (Pipelock), a distribution
        package version (Squid, the DNS fixture), or a source commit
        (Smokescreen). Upstreams publish different things; each pin is
        whatever is immutable for that upstream."""
        if self.packages:
            return "package"
        if self.source_repo:
            return "source"
        return "digest"

    def run_image_ref(self) -> str:
        """Immutable image reference for `up`; fails closed when unpinned."""
        pin_hint = (f"Run `./run.py pin {self.engine}` (needs network), review, commit, "
                    "then `./run.py setup`.")
        if self.pin_kind == "digest":
            if not self.image_digest:
                raise Fail(f"{self.engine} image digest is not pinned in "
                           f"services/{self.engine}.toml.\n{pin_hint}")
            return f"{self.image_repository}@{self.image_digest}"
        if self.pin_kind == "package":
            missing = sorted(name for name, version in self.packages.items() if not version)
            if missing:
                raise Fail(f"{self.engine} package version is not pinned in "
                           f"services/{self.engine}.toml ({', '.join(missing)}).\n{pin_hint}")
            # Tagged by the package the service is named for, so the tag
            # still reads as a version rather than a hash of several.
            return f"{self.image_repository}:{self.primary_package_version}"
        if not self.source_ref:
            raise Fail(f"{self.engine} source ref is not pinned in "
                       f"services/{self.engine}.toml.\n{pin_hint}")
        return f"{self.image_repository}:{self.source_ref[:12]}"

    def config_path(self, test_policy: bool) -> Path:
        rel = self.test_config_file if test_policy else self.config_file
        if not rel:
            raise Fail(f"services/{self.engine}.toml: missing config_file")
        path = REPO_ROOT / rel
        if not path.is_file():
            raise Fail(f"missing config file: {path}")
        return path

    def mounts(self, test_policy: bool) -> list[tuple[Path, str]]:
        """Read-only bind mounts for `up`: the policy file, plus any daemon config."""
        pairs = [(self.config_path(test_policy), self.config_mount)]
        if self.extra_config_file:
            path = REPO_ROOT / self.extra_config_file
            if not path.is_file():
                raise Fail(f"missing config file: {path}")
            if not self.extra_config_mount:
                raise Fail(f"services/{self.engine}.toml: extra_config_file needs extra_config_mount")
            pairs.append((path, self.extra_config_mount))
        return pairs


# ---------------------------------------------------------------------------
# Container backends
# ---------------------------------------------------------------------------


class Backend:
    """Thin wrapper over the docker / Apple `container` CLIs.

    Only behavior available in both CLIs is used; anything backend-specific
    is isolated here so the security semantics stay identical (docs/backends.md).
    """

    def __init__(self, name: str):
        if name not in BACKENDS:
            raise Fail(f"unknown backend: {name}")
        self.name = name
        self.bin = name

    # -- low-level ----------------------------------------------------------

    def _run(self, *args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.bin, *args]
        proc = subprocess.run(cmd, capture_output=capture, text=True)
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise Fail(f"`{' '.join(cmd)}` failed:\n{detail}")
        return proc

    def available(self) -> bool:
        return shutil.which(self.bin) is not None

    # -- containers ---------------------------------------------------------

    def container_state(self, name: str) -> str:
        """Return 'running', 'stopped', or 'absent'."""
        proc = self._run("inspect", name, check=False)
        if proc.returncode != 0:
            return "absent"
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return "absent"
        if not info:
            return "absent"
        entry = info[0] if isinstance(info, list) else info
        if not isinstance(entry, dict):
            return "absent"
        # docker:          {"State": {"Status": "running"}}
        # Apple container: {"status": {"state": "running", ...}}
        #                  (older shapes use a plain string for either key)
        status = ""
        for key in ("State", "status"):
            value = entry.get(key)
            if isinstance(value, str):
                status = value
            elif isinstance(value, dict):
                status = value.get("Status") or value.get("state") or ""
            if status:
                break
        return "running" if str(status).lower() == "running" else "stopped"

    def container_ip(self, name: str) -> str:
        """The container's address on the backend's own network.

        Only used to point an engine's resolver at the DNS fixture, which is
        why no host port is published for it. Docker reports it under
        `NetworkSettings`; Apple `container` under `status.networks[]` as a
        CIDR that has to be trimmed.
        """
        proc = self._run("inspect", name, check=False)
        if proc.returncode != 0:
            return ""
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ""
        entry = (info[0] if isinstance(info, list) and info else info) or {}
        if not isinstance(entry, dict):
            return ""
        settings = entry.get("NetworkSettings")
        if isinstance(settings, dict):
            address = settings.get("IPAddress")
            if isinstance(address, str) and address:
                return address
            for network in (settings.get("Networks") or {}).values():
                address = (network or {}).get("IPAddress")
                if isinstance(address, str) and address:
                    return address
        networks = (entry.get("status") or {}).get("networks")
        if isinstance(networks, list):
            for network in networks:
                address = (network or {}).get("ipv4Address")
                if isinstance(address, str) and address:
                    return address.split("/", 1)[0]
        return ""

    def published_ports(self, name: str) -> list[tuple[str, int, int]]:
        """(host address, host port, container port) for each published port.

        The endpoint is supposed to be loopback-only, and `--publish
        ip:host:container` is the whole of that guarantee — a release that
        quietly ignored the address half would widen it to every interface
        with no error and no visible change. This reads the binding back out
        of the runtime so that scripts/verify_loopback.py can assert it
        rather than trust it (docs/backends.md).

        Docker:          HostConfig.PortBindings {"8888/tcp": [{HostIp, HostPort}]}
        Apple container: configuration.publishedPorts [{hostAddress, hostPort,
                         containerPort}]
        """
        proc = self._run("inspect", name, check=False)
        if proc.returncode != 0:
            return []
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []
        entry = (info[0] if isinstance(info, list) and info else info) or {}
        if not isinstance(entry, dict):
            return []
        bindings: list[tuple[str, int, int]] = []
        published = (entry.get("configuration") or {}).get("publishedPorts")
        if isinstance(published, list):
            for item in published:
                if not isinstance(item, dict):
                    continue
                try:
                    bindings.append((str(item.get("hostAddress", "")),
                                     int(item["hostPort"]), int(item["containerPort"])))
                except (KeyError, TypeError, ValueError):
                    continue
        port_bindings = (entry.get("HostConfig") or {}).get("PortBindings") or {}
        if isinstance(port_bindings, dict):
            for spec, targets in port_bindings.items():
                container_port = int(str(spec).split("/", 1)[0] or 0)
                for target in targets or []:
                    if not isinstance(target, dict):
                        continue
                    try:
                        bindings.append((str(target.get("HostIp", "")),
                                         int(target["HostPort"]), container_port))
                    except (KeyError, TypeError, ValueError):
                        continue
        return bindings

    def remove_container(self, name: str) -> bool:
        """Remove a container if present; returns True if something was removed."""
        if self.container_state(name) == "absent":
            return False
        if self.name == "docker":
            self._run("rm", "-f", name, check=False)
        else:
            self._run("stop", name, check=False)
            self._run("rm", name, check=False)
        return True

    def run_detached(
        self,
        *,
        name: str,
        image: str,
        publish_host: str,
        publish_port: int,
        internal_port: int,
        mounts: list[tuple[Path, str]],
        args: list[str],
        publish: bool = True,
        dns: str = "",
    ) -> None:
        cmd: list[str] = ["run", "--detach", "--name", name]
        if publish:
            cmd += ["--publish", f"{publish_host}:{publish_port}:{internal_port}"]
        if dns:
            # Both CLIs spell this `--dns <ip>`. Docker also has --add-host,
            # which would be a tidier way to inject a single record, but
            # Apple `container` has no equivalent and a hosts entry cannot
            # carry a multi-address answer anyway (docs/backends.md).
            cmd += ["--dns", dns]
        for src, dst in mounts:
            cmd += ["--volume", f"{src}:{dst}:ro"]
        cmd.append(image)
        cmd += args
        self._run(*cmd)

    def logs(self, name: str, follow: bool) -> int:
        cmd = [self.bin, "logs"]
        if follow:
            cmd.append("--follow")
        cmd.append(name)
        return subprocess.run(cmd).returncode

    def tail_logs(self, name: str, lines: int = 40) -> str:
        proc = self._run("logs", name, check=False)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
        return "\n".join(out[-lines:])

    # -- images -------------------------------------------------------------

    def _image(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        # `image <verb>` works for both docker and Apple `container`.
        return self._run("image", *args, check=check)

    def pull(self, ref: str) -> None:
        if self.name == "docker":
            self._run("pull", ref, capture=False)
        else:
            self._run("image", "pull", ref, capture=False)

    def image_present(self, ref: str) -> bool:
        proc = self._image("inspect", ref, check=False)
        return proc.returncode == 0

    def image_digest(self, ref: str) -> str:
        """Best-effort immutable digest lookup for a local image."""
        proc = self._image("inspect", ref, check=False)
        if proc.returncode != 0:
            return ""
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ""
        entry = (info[0] if isinstance(info, list) and info else info) or {}
        if not isinstance(entry, dict):
            return ""
        digests = entry.get("RepoDigests")
        if isinstance(digests, list) and digests:
            return str(digests[0]).rpartition("@")[2]
        # Apple `container image inspect` reports the manifest digest under
        # `configuration.descriptor.digest` (a manifest-list digest for
        # multi-arch images); older shapes put it at the top level.
        descriptor = (entry.get("configuration") or {}).get("descriptor") or {}
        for source in (descriptor, entry):
            if not isinstance(source, dict):
                continue
            for key in ("digest", "Digest"):
                value = source.get(key)
                if isinstance(value, str) and value.startswith("sha256:"):
                    return value
        return ""

    def image_size(self, ref: str) -> int:
        """On-disk size of a local image in bytes; 0 when it cannot be read.

        Reported by `scripts/verify_resilience.py` rather than enforced —
        image size is one of the operational numbers the engine choice is
        weighed on, and it was never collected. Docker puts it at `Size`;
        Apple `container` reports the manifest's layer sizes instead, so
        the two are summed to something comparable rather than equal.
        """
        proc = self._image("inspect", ref, check=False)
        if proc.returncode != 0:
            return 0
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return 0
        entry = (info[0] if isinstance(info, list) and info else info) or {}
        if not isinstance(entry, dict):
            return 0
        for key in ("Size", "size", "VirtualSize"):
            value = entry.get(key)
            if isinstance(value, (int, float)) and value > 0:
                return int(value)
        variants = (entry.get("variants") or entry.get("manifests") or [])
        total = 0
        for variant in variants if isinstance(variants, list) else []:
            for layer in (variant or {}).get("layers") or []:
                value = (layer or {}).get("size")
                if isinstance(value, (int, float)):
                    total += int(value)
        return total

    def run_once(self, image: str, args: list[str]) -> str:
        """Run a throwaway container and return its stdout. Used by `pin` to
        ask a base image what package version it would install."""
        proc = self._run("run", "--rm", image, *args)
        return proc.stdout or ""

    def build(self, *, tag: str, dockerfile: Path, context: Path, build_args: dict[str, str]) -> None:
        cmd = ["build", "--tag", tag, "--file", str(dockerfile)]
        for key, value in build_args.items():
            cmd += ["--build-arg", f"{key}={value}"]
        cmd.append(str(context))
        self._run(*cmd, capture=False)


def detect_backend(override: str | None) -> Backend:
    if override:
        backend = Backend(override)
        if not backend.available():
            raise Fail(f"requested backend `{override}` is not installed")
        return backend
    candidates = [Backend("container"), Backend("docker")] if platform.system() == "Darwin" \
        else [Backend("docker"), Backend("container")]
    for backend in candidates:
        if backend.available():
            return backend
    raise Fail("no container backend found: install Docker or Apple `container`")


# ---------------------------------------------------------------------------
# Policy generation
# ---------------------------------------------------------------------------
#
# config.toml holds the allowlist once; templates/*.j2 hold everything else
# each engine needs, as literal text. Rendering the two together produces
# config/<engine>.{yaml,conf} and the `.test` variants, so the three
# engines cannot express different policies — the thing docs/policy.md used
# to ask a human to keep true by editing three files.
#
# Nothing security-critical is parameterized: the deny floors, the rule
# order, `cache deny all` and `tls_interception: false` are literal text in
# the templates. The generator only ever fills in domains, and its output
# is put through the same `validate_policy_file()` the hand-written files
# went through — before it is allowed to touch the disk.


POLICY_FILE = REPO_ROOT / "config.toml"
TEMPLATE_DIR = REPO_ROOT / "templates"

# The two forms docs/policy.md defines, and nothing else: `d` (that host
# exactly) or `*.d` (subdomains of d, never the apex). At least two labels,
# no leading dot, no regex metacharacters, no scheme/port/path.
_ALLOW_ENTRY = re.compile(
    r"\A(?:\*\.)?(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\Z"
)


@dataclass(frozen=True)
class FixtureConfig:
    """The local DNS fixture's records, read from `[fixture]` in config.toml.

    `config/dns-fixture.hosts` is rendered from this, so the records the
    fixture serves and the `[policy.test]` allowlist that has to cover them
    come from one place instead of being hand-synced (docs/policy.md).
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


@dataclass(frozen=True)
class PolicyConfig:
    """The shared logical policy, read from config.toml."""

    allow: tuple[str, ...]
    allow_test: tuple[str, ...]
    # Optional so a test can render the engine configs from a bare
    # allowlist; `load_policy_config()` always supplies one.
    fixture: FixtureConfig | None = None

    def exact(self, entries: tuple[str, ...]) -> list[str]:
        return [entry for entry in entries if not entry.startswith("*.")]

    def wild(self, entries: tuple[str, ...]) -> list[str]:
        return [entry for entry in entries if entry.startswith("*.")]


def _allow_list(raw: object, path: Path, key: str) -> list[str]:
    if not isinstance(raw, list):
        raise Fail(f"{path}: {key} must be an array of strings")
    entries: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise Fail(f"{path}: {key} must contain only strings (found {item!r})")
        entry = item.strip()
        if entry in entries:
            raise Fail(f"{path}: {key} lists `{entry}` twice")
        if not _ALLOW_ENTRY.match(entry):
            raise Fail(
                f"{path}: {key} entry `{entry}` is not a valid allowlist form. "
                "Use `example.com` for one host or `*.example.com` for its "
                "subdomains (docs/policy.md)."
            )
        # `_ALLOW_ENTRY` cannot tell 1.2.3.4 from a hostname, and an
        # address-form entry is exactly what `http_access deny ip_literal`
        # exists to refuse: this policy allowlists by name and never by
        # address (docs/engines.md).
        if re.fullmatch(r"[0-9.]+", entry):
            raise Fail(
                f"{path}: {key} entry `{entry}` is an address, not a hostname. "
                "This policy allowlists by name only."
            )
        entries.append(entry)
    return entries


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
                   "fixture's records; config/dns-fixture.hosts is rendered "
                   "from it)")
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
            # included — and `up` without --test-policy does not even start
            # the fixture, so the entry would be dead weight at best.
            raise Fail(f"{path}: [policy].allow permits the fixture name `{name}`. "
                       "Fixture names belong in [policy.test].allow only; the real "
                       "policy must never allowlist a name the fixture answers.")
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
        raise Fail(f"{path}: [policy].allow permits the rebinding zone "
                   f"`{rebind_zone}`. Its answers change between lookups and end "
                   "at a private address; it belongs in [policy.test].allow only.")
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
                   f"[policy].allow (found {ptr_claims!r}); `ptr-allowlist` asks "
                   "whether a PTR record can satisfy the *real* allowlist")

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


def load_policy_config(path: Path = POLICY_FILE) -> PolicyConfig:
    """Read and validate config.toml. Fails closed on anything ambiguous."""
    if not path.is_file():
        raise Fail(f"missing the policy source {path} (it holds the allowlist)")
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    unknown = sorted(set(data) - {"policy", "fixture"})
    if unknown:
        raise Fail(f"{path}: unknown top-level table(s): {', '.join(unknown)}")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise Fail(f"{path}: missing the [policy] table")
    unknown = sorted(set(policy) - {"allow", "test"})
    if unknown:
        # A typo here (`allows = [...]`) would otherwise silently render an
        # empty or truncated allowlist.
        raise Fail(f"{path}: unknown key(s) in [policy]: {', '.join(unknown)}")
    allow = _allow_list(policy.get("allow", []), path, "policy.allow")
    if not allow:
        raise Fail(f"{path}: policy.allow must not be empty "
                   "(default deny needs explicit allows)")
    test = policy.get("test", {})
    if not isinstance(test, dict):
        raise Fail(f"{path}: [policy.test] must be a table")
    unknown = sorted(set(test) - {"allow"})
    if unknown:
        raise Fail(f"{path}: unknown key(s) in [policy.test]: {', '.join(unknown)}")
    allow_test = _allow_list(test.get("allow", []), path, "policy.test.allow")
    overlap = sorted(set(allow) & set(allow_test))
    if overlap:
        raise Fail(f"{path}: policy.test.allow repeats {', '.join(overlap)}, "
                   "which policy.allow already permits everywhere")
    fixture = _fixture_config(data.get("fixture"), path, allow, allow_test)
    return PolicyConfig(tuple(allow), tuple(allow_test), fixture)


def _yaml_scalar(entry: str) -> str:
    """Quote what YAML would otherwise read as syntax — `*` starts an alias."""
    return entry if entry[:1].isalnum() else f'"{entry}"'


def _squid_wild(entry: str) -> str:
    r"""`*.github.com` -> `\.github\.com$`.

    The exact anchored-suffix shape `_squid_regex_to_glob()` reads back, so
    generation and the cross-engine comparison are inverses of each other.
    """
    if not entry.startswith("*."):
        raise Fail(f"not a wildcard allowlist entry: {entry}")
    return "\\." + entry[2:].replace(".", "\\.") + "$"


def _template_name(spec: "ServiceSpec") -> str:
    """`config/squid.conf` -> `squid.conf.j2`."""
    return Path(spec.config_file).name + ".j2"


def render_policies(config: PolicyConfig | None = None) -> dict[Path, str]:
    """Render every engine config from config.toml. Path -> file contents."""
    config = load_policy_config() if config is None else config
    try:
        from jinja2 import Environment, FileSystemLoader, StrictUndefined
    except ModuleNotFoundError as exc:  # pragma: no cover - environment issue
        raise Fail(
            "jinja2 is required to render the engine policies from config.toml.\n"
            "Run `uv sync` once, then use `uv run ./run.py ...` "
            "(or install jinja2 into the interpreter you are using)."
        ) from exc
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        autoescape=False,  # config files, not markup
    )
    env.filters["yaml_scalar"] = _yaml_scalar
    env.filters["squid_wild"] = _squid_wild

    rendered: dict[Path, str] = {}
    for engine in ENGINES:
        spec = ServiceSpec.load(engine)
        name = _template_name(spec)
        if not (TEMPLATE_DIR / name).is_file():
            raise Fail(f"missing template: {TEMPLATE_DIR / name}")
        template = env.get_template(name)
        for test_policy in (False, True):
            rel = spec.test_config_file if test_policy else spec.config_file
            if not rel:
                raise Fail(f"services/{engine}.toml: config_file and "
                           "test_config_file are both required")
            rendered[REPO_ROOT / rel] = template.render(
                template_name=f"templates/{name}",
                test_policy=test_policy,
                allow=list(config.allow),
                allow_test=list(config.allow_test),
                allow_exact=config.exact(config.allow),
                allow_wild=config.wild(config.allow),
                allow_test_exact=config.exact(config.allow_test),
                allow_test_wild=config.wild(config.allow_test),
            )
    if config.fixture is not None:
        rendered.update(_render_fixture_hosts(env, config.fixture))
    return rendered


def _render_fixture_hosts(env, fixture: FixtureConfig) -> dict[Path, str]:
    """Render config/dns-fixture.hosts from `[fixture]`.

    The hosts file is not a policy — nothing in it is enforced — but it is
    the other half of the test policy, and hand-syncing it against
    `[policy.test].allow` is exactly what `load_policy_config()` now
    refuses to leave to care (docs/policy.md).
    """
    spec = ServiceSpec.load(DNS_FIXTURE)
    name = _template_name(spec)
    if not (TEMPLATE_DIR / name).is_file():
        raise Fail(f"missing template: {TEMPLATE_DIR / name}")
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
        fixture=fixture,
        fixture_records=rows,
    )
    return {REPO_ROOT / spec.config_file: text}


def check_rendered_policies(rendered: dict[Path, str]) -> list[str]:
    """Validate rendered text before it is allowed near the disk.

    Auto-regeneration means a template or generator bug could otherwise
    overwrite a reviewed, working policy with a broken one. The same
    `validate_policy_file()` invariants that guarded the hand-written files
    guard the generated ones, plus the superset rule the two variants of
    each file have to satisfy.
    """
    problems: list[str] = []
    for engine in ENGINES:
        spec = ServiceSpec.load(engine)
        real_path = REPO_ROOT / spec.config_file
        test_path = REPO_ROOT / spec.test_config_file
        real, test = rendered[real_path], rendered[test_path]
        problems += validate_policy_text(engine, real, real_path)
        problems += validate_policy_text(engine, test, test_path)
        if engine == "squid":
            problems += check_squid_error_pages(real, real_path)
            problems += check_squid_error_pages(test, test_path)
        missing = policy_allowlist_text(engine, real) - policy_allowlist_text(engine, test)
        for entry in sorted(missing):
            problems.append(f"{test_path}: the test policy must be a strict superset "
                            f"of the real one, but drops `{entry}`")
    return problems


def sync_policies(config: PolicyConfig | None = None) -> list[Path]:
    """Regenerate the engine configs from config.toml; return what changed.

    Files whose contents already match are left alone, so a no-op `up`
    does not churn mtimes or the working tree.
    """
    rendered = render_policies(config)
    problems = check_rendered_policies(rendered)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("refusing to write a policy that fails validation (fail closed)")
    changed: list[Path] = []
    for path, text in sorted(rendered.items()):
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            changed.append(path)
    return changed


def sync_policies_reporting() -> None:
    """`sync_policies()` for the lifecycle commands: quiet when up to date."""
    for path in sync_policies():
        print(f"regenerated {path.relative_to(REPO_ROOT)} from config.toml")


# ---------------------------------------------------------------------------
# Policy validation (lightweight, stdlib-only — independent of the generator)
# ---------------------------------------------------------------------------


def _yaml_list(text: str, key: str) -> list[str]:
    """Extract a top-level-ish `key:` sequence of scalar items."""
    match = re.search(rf"^(\s*){re.escape(key)}:\s*$", text, re.MULTILINE)
    if not match:
        return []
    indent = len(match.group(1))
    items: list[str] = []
    for line in text[match.end():].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        this_indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped.startswith("- ") and this_indent > indent:
            items.append(stripped[2:].strip().strip('"').strip("'"))
        elif this_indent <= indent:
            break
    return items


def _yaml_block(text: str, key: str) -> str:
    match = re.search(rf"^(\s*){re.escape(key)}:\s*$", text, re.MULTILINE)
    if not match:
        return ""
    indent = len(match.group(1))
    lines: list[str] = []
    for line in text[match.end():].splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            if len(line) - len(line.lstrip()) <= indent:
                break
        lines.append(line)
    return "\n".join(lines)


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
# silent, valid-looking config that loses every reason (docs/engines.md).
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

SQUID_ERROR_DIR = REPO_ROOT / "images" / "squid" / "errors"


def _squid_access_rules(text: str) -> list[str]:
    """Every `http_access` line, in file order, whitespace-normalized."""
    return [" ".join(line.split()) for line in text.splitlines()
            if re.match(r"^\s*http_access\s", line)]


def _squid_acl_names(text: str) -> set[str]:
    """Every ACL name the file defines."""
    return {match.group(1) for match in
            re.finditer(r"^\s*acl\s+(\S+)\s+\S+", text, re.M)}


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
        match = re.match(rf"^\s*acl\s+{re.escape(name)}\s+{re.escape(acl_type)}\s+(.*)$", line)
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
        _require(acl in defined, path,
                 f"`deny_info {page} {acl}` names an ACL this file does not define; "
                 "the page would never be shown and the denial would lose its reason",
                 problems)
        _require(acl not in seen, path,
                 f"`{acl}` has two denial pages ({seen.get(acl)} and {page}); "
                 "only one of them can ever be shown", problems)
        seen[acl] = page
    for acl, page in REQUIRED_SQUID_DENY_INFO.items():
        _require(seen.get(acl) == page, path,
                 f"`deny_info {page} {acl}` is missing (found "
                 f"{seen.get(acl) or 'nothing'} for `{acl}`); without it that denial "
                 "reports Squid's generic page and classifies as `unknown`",
                 problems)
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
        _require((SQUID_ERROR_DIR / page).is_file(), path,
                 f"`deny_info {page} {acl}` names a page that does not exist at "
                 f"{(SQUID_ERROR_DIR / page).relative_to(REPO_ROOT)}; Squid would "
                 "answer `Internal Error: Missing Template`", problems)
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
    if engine == "pipelock":
        _require(re.search(r"^mode:\s*strict\b", text, re.M) is not None, path,
                 "must set `mode: strict`", problems)
        _require(re.search(r"^enforce:\s*true\b", text, re.M) is not None, path,
                 "must set `enforce: true`", problems)
        fp = _yaml_block(text, "forward_proxy")
        _require(bool(re.search(r"^\s*enabled:\s*true\b", fp, re.M)), path,
                 "forward_proxy.enabled must be true", problems)
        _require(bool(re.search(r"^\s*sni_verification:\s*true\b", fp, re.M)), path,
                 "forward_proxy.sni_verification must be true", problems)
        _require(bool(re.search(r"^\s*sni_require_tls:\s*true\b", fp, re.M)), path,
                 "forward_proxy.sni_require_tls must be true", problems)
        ti = _yaml_block(text, "tls_interception")
        _require(bool(re.search(r"^\s*enabled:\s*false\b", ti, re.M)), path,
                 "tls_interception.enabled must be false in v1", problems)
        _require(len(_yaml_list(text, "api_allowlist")) > 0, path,
                 "api_allowlist must not be empty (default deny needs explicit allows)", problems)
    elif engine == "smokescreen":
        _require(re.search(r"^version:\s*v1\b", text, re.M) is not None, path,
                 "must set `version: v1`", problems)
        _require(re.search(r"\baction:\s*open\b", text) is None, path,
                 "`action: open` is forbidden (no open proxy mode)", problems)
        default_block = _yaml_block(text, "default")
        _require(bool(re.search(r"^\s*action:\s*enforce\b", default_block, re.M)), path,
                 "default.action must be `enforce`", problems)
        _require(len(_yaml_list(default_block, "allowed_domains")) > 0, path,
                 "default.allowed_domains must not be empty", problems)
    elif engine == "squid":
        rules = _squid_access_rules(text)
        _require(bool(rules) and rules[-1] == "http_access deny all", path,
                 "the last http_access rule must be `http_access deny all` (default deny)", problems)
        _require(not any(re.match(r"http_access\s+allow\s+all\b", rule) for rule in rules), path,
                 "`http_access allow all` is forbidden (no open proxy mode)", problems)
        # First match wins, so an allow placed above the SSRF floors would
        # let an allowlisted hostname reach a private address.
        first_allow = next((i for i, rule in enumerate(rules)
                            if rule.startswith("http_access allow")), len(rules))
        # `ip_literal` is here for the same reason as the SSRF floors but a
        # different failure: Squid retries a `dstdomain` miss as a reverse
        # lookup, so an address-form destination reaches the allowlist under
        # whatever name its PTR claims. Refusing it earlier is the only fix
        # Squid offers (docs/engines.md).
        for acl in ("metadata_ip", "private_ip", "ip_literal"):
            index = next((i for i, rule in enumerate(rules)
                          if rule == f"http_access deny {acl}"), None)
            _require(index is not None and index < first_allow, path,
                     f"`http_access deny {acl}` must appear before the first `http_access allow` "
                     "(http_access is first-match-wins)", problems)
        for acl, cidr in REQUIRED_SQUID_DENY_RANGES:
            _require(cidr in _squid_acl_values(text, acl, "dst"), path,
                     f"the `{acl}` ACL must deny {cidr}", problems)
        _require(re.search(r"^\s*ssl_bump\s+.*\bbump\b", text, re.M) is None, path,
                 "`ssl_bump ... bump` is forbidden (no TLS interception in v1)", problems)
        _require(re.search(r"^\s*cache\s+deny\s+all\b", text, re.M) is not None, path,
                 "must set `cache deny all` (a cache hit is a response nobody re-authorized)",
                 problems)
        problems += _validate_squid_deny_info(text, path)
        _require(len(policy_allowlist_text("squid", text)) > 0, path,
                 "the allowlist must not be empty (default deny needs explicit allows)", problems)
    else:
        raise Fail(f"unknown engine: {engine}")
    return problems


def policy_allowlist(engine: str, path: Path) -> set[str]:
    """The engine's allowlist, normalized to the shared `d` / `*.d` forms of
    docs/policy.md so the three files can be compared directly."""
    return policy_allowlist_text(engine, path.read_text())


def policy_allowlist_text(engine: str, text: str) -> set[str]:
    """As `policy_allowlist`, on text that may not be on disk yet."""
    if engine == "pipelock":
        return set(_yaml_list(text, "api_allowlist"))
    if engine == "squid":
        entries = set(_squid_acl_values(text, "allowlist_exact", "dstdomain"))
        entries.update(_squid_regex_to_glob(pattern) for pattern
                       in _squid_acl_values(text, "allowlist_wild", "dstdom_regex"))
        return entries
    return set(_yaml_list(_yaml_block(text, "default"), "allowed_domains"))


def check_allowlist_sync(test_policy: bool = False) -> list[str]:
    """Warn when the engines' allowlists have drifted apart.

    Compared pairwise rather than against a designated master: there is no
    master. docs/policy.md is the logical policy and each config is one
    expression of it, so any disagreement is a finding no matter which file
    is the odd one out.
    """
    allowlists: dict[str, set[str]] = {}
    try:
        for engine in ENGINES:
            spec = ServiceSpec.load(engine)
            allowlists[engine] = policy_allowlist(engine, spec.config_path(test_policy))
    except Fail:
        return []
    warnings = []
    label = "test policy" if test_policy else "policy"
    for i, first in enumerate(ENGINES):
        for second in ENGINES[i + 1:]:
            for entry in sorted(allowlists[first] - allowlists[second]):
                warnings.append(f"{label}: `{entry}` is allowed in {first} but not {second}")
            for entry in sorted(allowlists[second] - allowlists[first]):
                warnings.append(f"{label}: `{entry}` is allowed in {second} but not {first}")
    return warnings


# ---------------------------------------------------------------------------
# Health probing
# ---------------------------------------------------------------------------


def port_listening(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_proxy(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str, bool]:
    """Ask the proxy for a guaranteed-non-allowlisted host.

    Healthy means: the proxy answers with an HTTP error (policy denial or
    resolution failure). A 2xx/3xx would mean the proxy is not enforcing at
    all, which we refuse to call healthy (fail closed).

    Returns (healthy, detail, retryable). `retryable` marks a failure that
    only says the engine is not serving *yet* — no answer, or an answer that
    is not HTTP. Docker publishes the host port as soon as the container is
    created, so a connection can be accepted seconds before the engine
    listens behind it; those probes must be retried, not treated as verdicts.
    A proxy that answers and allows the probe is never retryable: it is
    enforcing nothing, and waiting longer cannot fix that.
    """
    request = (
        "GET http://ipl-health-probe.invalid/ HTTP/1.1\r\n"
        "Host: ipl-health-probe.invalid\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request.encode())
            data = sock.recv(4096)
    except OSError as exc:
        return False, f"no response from proxy: {exc}", True
    line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace") if data else ""
    match = re.match(r"HTTP/\d\.\d\s+(\d{3})", line)
    if not match:
        return False, f"non-HTTP response: {line!r}", True
    status = int(match.group(1))
    if status >= 400:
        return True, f"denies unknown destinations ({line.strip()})", False
    return False, f"proxy allowed a non-allowlisted host ({line.strip()}) — NOT healthy", False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def all_specs() -> list[ServiceSpec]:
    return [ServiceSpec.load(engine) for engine in ENGINES]


def start_dns_fixture(backend: Backend) -> str:
    """Start the dnsmasq fixture container and return its address.

    Only called for `up --test-policy`. No host port is published: the
    fixture is reachable from the engine container and from nothing else.
    """
    spec = ServiceSpec.load(DNS_FIXTURE)
    image = spec.run_image_ref()
    if not backend.image_present(image):
        raise Fail(
            f"the DNS fixture image {image} is not built — run `./run.py setup`.\n"
            "`up --test-policy` needs it to serve the mixed-answer records that "
            "`check --full` grades (docs/security.md)."
        )
    backend.remove_container(spec.container_name)
    backend.run_detached(
        name=spec.container_name,
        image=image,
        publish_host="",
        publish_port=0,
        internal_port=spec.internal_port,
        mounts=spec.mounts(False),
        args=spec.args,
        publish=False,
    )
    deadline = time.monotonic() + HEALTH_WAIT_SECONDS
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


def running_engine(backend: Backend) -> str | None:
    for spec in all_specs():
        if backend.container_state(spec.container_name) == "running":
            return spec.engine
    return None


def cmd_policy(opts: argparse.Namespace) -> int:
    """Render config.toml into the engine configs, or report the drift.

    `setup` and `up` do this on their own; this exists so a config.toml
    edit can be reviewed — and CI can assert the committed files match —
    without a container runtime.
    """
    rendered = render_policies()
    problems = check_rendered_policies(rendered)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("configuration validation failed")

    stale = [(path, body) for path, body in sorted(rendered.items())
             if not path.is_file() or path.read_text(encoding="utf-8") != body]
    if not opts.check:
        for path in sync_policies():
            print(f"regenerated {path.relative_to(REPO_ROOT)} from config.toml")
        print("configs: up to date with config.toml")
        return 0

    for path, body in stale:
        rel = path.relative_to(REPO_ROOT)
        current = (path.read_text(encoding="utf-8").splitlines(keepends=True)
                   if path.is_file() else [])
        sys.stdout.writelines(difflib.unified_diff(
            current, body.splitlines(keepends=True),
            fromfile=f"{rel} (on disk)", tofile=f"{rel} (from config.toml)"))
    if stale:
        names = ", ".join(str(path.relative_to(REPO_ROOT)) for path, _ in stale)
        print(f"\nSTALE: {names}", file=sys.stderr)
        print("Run `./run.py policy` to regenerate, then commit.", file=sys.stderr)
        return 1
    print("configs: up to date with config.toml")
    return 0


def cmd_setup(opts: argparse.Namespace) -> int:
    # The hard guard is at the top of this file, ahead of the stdlib
    # imports; by here the version is known good and only worth reporting.
    print(f"python: {platform.python_version()} — OK")

    # Before validating: the files validated below are rendered from
    # config.toml, so a stale one would be reported as a policy problem
    # that editing it could not fix.
    sync_policies_reporting()

    for name in BACKENDS:
        state = "available" if Backend(name).available() else "not installed"
        print(f"backend {name}: {state}")
    backend = detect_backend(opts.backend)
    print(f"selected backend: {backend.name}")

    problems: list[str] = []
    for engine in ENGINES:
        spec = ServiceSpec.load(engine)
        for test_policy in (False, True):
            try:
                path = spec.config_path(test_policy)
            except Fail as exc:
                problems.append(str(exc))
                continue
            problems += validate_policy_file(engine, path)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("configuration validation failed")
    print("configs: valid")
    for warning in check_allowlist_sync(False) + check_allowlist_sync(True):
        print(f"WARNING: {warning}")

    engines = ENGINES if opts.engine == "all" else (opts.engine,)
    for engine in engines:
        spec = ServiceSpec.load(engine)
        if engine == "pipelock":
            _setup_pipelock(backend, spec)
        elif spec.pin_kind == "package":
            _setup_package_image(backend, spec, rebuild=opts.rebuild)
        else:
            _setup_smokescreen(backend, spec, rebuild=opts.rebuild)
    # The DNS fixture is needed by `up --test-policy` whichever engine is
    # chosen, so it is prepared unconditionally rather than per engine.
    _setup_package_image(backend, ServiceSpec.load(DNS_FIXTURE), rebuild=opts.rebuild)
    print("setup complete")
    return 0


def _setup_pipelock(backend: Backend, spec: ServiceSpec) -> None:
    if spec.image_digest:
        ref = f"{spec.image_repository}@{spec.image_digest}"
        print(f"pipelock: pulling pinned image {ref}")
        backend.pull(ref)
        return
    ref = f"{spec.image_repository}:{spec.image_tag}"
    print(f"pipelock: no digest pinned yet; pulling {ref} to record one")
    backend.pull(ref)
    digest = backend.image_digest(ref)
    if not digest:
        raise Fail(
            "could not determine the image digest automatically.\n"
            f"Find it (e.g. `docker image inspect {ref}` → RepoDigests) and put it in services/pipelock.toml"
        )
    _write_pin(spec.toml_path, "digest", digest)
    print(f"pipelock: recorded digest {digest} in services/pipelock.toml — review and commit it")


def _setup_smokescreen(backend: Backend, spec: ServiceSpec, rebuild: bool = False) -> None:
    if not spec.source_ref:
        raise Fail(
            "smokescreen source ref is not pinned.\n"
            "Run `./run.py pin smokescreen` (needs network), review and commit, then re-run setup."
        )
    tag = spec.run_image_ref()
    if backend.image_present(tag) and not rebuild:
        print(f"smokescreen: image {tag} already built")
        return
    print(f"smokescreen: building {tag} from {spec.source_repo}@{spec.source_ref}")
    build_args = {"SMOKESCREEN_REPO": spec.source_repo, "SMOKESCREEN_REF": spec.source_ref}
    if spec.go_image:
        build_args["GO_IMAGE"] = spec.go_image
    if spec.runtime_image:
        build_args["RUNTIME_IMAGE"] = spec.runtime_image
    context = REPO_ROOT / "images" / "smokescreen"
    backend.build(tag=tag, dockerfile=context / "Dockerfile", context=context, build_args=build_args)
    print(f"smokescreen: built {tag}")


def _setup_package_image(backend: Backend, spec: ServiceSpec, rebuild: bool = False) -> None:
    """Build an image around a pinned distribution package — Squid, and the
    dnsmasq DNS fixture. The Dockerfile takes `<PACKAGE>_VERSION`."""
    tag = spec.run_image_ref()   # raises when any package is unpinned
    if backend.image_present(tag) and not rebuild:
        print(f"{spec.engine}: image {tag} already built")
        return
    pinned = ", ".join(f"{name}={version}" for name, version in sorted(spec.packages.items()))
    print(f"{spec.engine}: building {tag} from {spec.base_image} ({pinned})")
    build_args = {f"{name.upper()}_VERSION": version
                  for name, version in spec.packages.items()}
    if spec.base_image:
        build_args["BASE_IMAGE"] = spec.base_image
    context = REPO_ROOT / "images" / spec.engine
    backend.build(tag=tag, dockerfile=context / "Dockerfile", context=context, build_args=build_args)
    print(f"{spec.engine}: built {tag}")


def _write_pin(toml_path: Path, key: str, value: str) -> None:
    text = toml_path.read_text()
    new_text, count = re.subn(rf'^{key} = "[^"]*"$', f'{key} = "{value}"', text, count=1, flags=re.M)
    if count != 1:
        raise Fail(f"could not update `{key}` in {toml_path}; edit it manually to {value!r}")
    toml_path.write_text(new_text)


def cmd_pin(opts: argparse.Namespace) -> int:
    engine = opts.target
    spec = ServiceSpec.load(engine)
    if engine == "pipelock":
        backend = detect_backend(opts.backend)
        ref = f"{spec.image_repository}:{spec.image_tag}"
        print(f"pulling {ref} to resolve its digest")
        backend.pull(ref)
        digest = backend.image_digest(ref)
        if not digest:
            raise Fail(f"could not resolve a digest for {ref}; inspect the image manually")
        _write_pin(spec.toml_path, "digest", digest)
        print(f"pinned pipelock {spec.image_tag} @ {digest}")
    elif spec.pin_kind == "package":
        names = sorted(spec.packages)
        if opts.ref:
            if len(names) != 1:
                raise Fail(f"--ref pins a single package, but {engine} pins "
                           f"{len(names)} ({', '.join(names)}); edit "
                           f"services/{engine}.toml directly")
            _write_pin(spec.toml_path, names[0], opts.ref)
            print(f"pinned {engine} {names[0]}={opts.ref}")
        else:
            backend = detect_backend(opts.backend)
            base = spec.base_image
            if not base:
                raise Fail(f"services/{engine}.toml: [build] base_image is required "
                           f"to pin {engine}")
            print(f"asking {base} which versions of {', '.join(names)} it would install")
            output = backend.run_once(base, [
                "sh", "-c",
                f"apk update >/dev/null 2>&1 && apk list {' '.join(names)} 2>/dev/null",
            ])
            for name in names:
                versions = re.findall(rf"^{re.escape(name)}-(\d[\w.]*-r\d+)\s", output, re.M)
                if not versions:
                    raise Fail(
                        f"could not read a {name} version from {base}.\n"
                        f"Check it by hand (`apk list {name}` in that image) and put it in "
                        f"services/{engine}.toml"
                    )
                resolved = sorted(set(versions))[-1]
                _write_pin(spec.toml_path, name, resolved)
                print(f"pinned {engine} {name}={resolved} (from {base})")
    else:
        git = shutil.which("git")
        if not git:
            raise Fail("git is required to pin smokescreen")
        target = opts.ref or "HEAD"
        proc = subprocess.run([git, "ls-remote", spec.source_repo, target],
                              capture_output=True, text=True)
        if proc.returncode != 0 or not proc.stdout.strip():
            raise Fail(f"git ls-remote {spec.source_repo} {target} failed:\n{proc.stderr.strip()}")
        sha = proc.stdout.split()[0]
        _write_pin(spec.toml_path, "ref", sha)
        print(f"pinned smokescreen {target} @ {sha}")
    print("review the change and commit it; then run `./run.py setup`")
    return 0


def cmd_up(opts: argparse.Namespace) -> int:
    engine = opts.engine or DEFAULT_ENGINE
    spec = ServiceSpec.load(engine)
    backend = detect_backend(opts.backend)
    host, port = endpoint()

    # The policy the container is about to bind-mount is rendered from
    # config.toml first, so `up` can never start an engine on a config that
    # disagrees with the reviewed allowlist. `sync_policies()` validates
    # the rendered text before writing it, so a bad config.toml fails here
    # rather than replacing a working file.
    sync_policies_reporting()

    config_path = spec.config_path(opts.test_policy)
    problems = validate_policy_file(engine, config_path)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("refusing to start with an invalid policy (fail closed)")
    for warning in check_allowlist_sync(opts.test_policy):
        print(f"WARNING: {warning}")
    if opts.test_policy:
        print("NOTE: starting with the TEST policy (extra DNS fixture domains, and a "
              "local dnsmasq serving the mixed-answer records). "
              "Run `./run.py up` again without --test-policy for normal operation.")

    image = spec.run_image_ref()
    if engine in BUILT_ENGINES and not backend.image_present(image):
        raise Fail(f"image {image} not built yet — run `./run.py --engine {engine} setup`")

    # `up` recreates: remove every container owned by this repository first
    # (every engine publishes the same endpoint, so they cannot coexist).
    # The DNS fixture goes too — a stale one would outlive the engine that
    # was pointed at it, and must never be left running under a real policy.
    for owned in all_specs() + [ServiceSpec.load(DNS_FIXTURE)]:
        if backend.remove_container(owned.container_name):
            print(f"removed existing container {owned.container_name}")

    if port_listening(host, port):
        raise Fail(
            f"{host}:{port} is already in use by something this repository does not own — "
            "refusing to start (choose down the other service or free the port)"
        )

    fixture_dns = ""
    if opts.test_policy:
        fixture_dns = start_dns_fixture(backend)
        print(f"started the DNS fixture at {fixture_dns} "
              f"(serving {ServiceSpec.load(DNS_FIXTURE).config_file})")

    print(f"starting {engine} ({image}) on http://{host}:{port}")
    backend.run_detached(
        name=spec.container_name,
        image=image,
        publish_host=host,
        publish_port=port,
        internal_port=spec.internal_port,
        mounts=spec.mounts(opts.test_policy),
        args=spec.args,
        dns=fixture_dns,
    )

    deadline = time.monotonic() + HEALTH_WAIT_SECONDS
    healthy, detail = False, "timed out waiting for the proxy to listen"
    while time.monotonic() < deadline:
        if port_listening(host, port):
            healthy, detail, retryable = probe_proxy(host, port)
            if healthy or not retryable:
                break
        if backend.container_state(spec.container_name) != "running":
            detail = "container exited during startup"
            break
        time.sleep(0.5)
    if not healthy:
        logs = backend.tail_logs(spec.container_name)
        raise Fail(
            f"post-start health check failed: {detail}\n"
            f"--- last container logs ---\n{logs}\n"
            f"(the container is left in place for debugging; `./run.py down` removes it)"
        )
    print(f"healthy: {detail}")
    print(f"clients: export HTTP_PROXY=http://{host}:{port} HTTPS_PROXY=http://{host}:{port}")
    return 0


def cmd_down(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    removed = False
    for spec in all_specs() + [ServiceSpec.load(DNS_FIXTURE)]:
        if backend.remove_container(spec.container_name):
            print(f"removed {spec.container_name}")
            removed = True
    if not removed:
        print("nothing to remove")
    return 0


def cmd_restart(opts: argparse.Namespace) -> int:
    cmd_down(opts)
    return cmd_up(opts)


def cmd_status(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    host, port = endpoint()
    active = running_engine(backend)
    print(f"backend:  {backend.name}")
    print(f"endpoint: http://{host}:{port}")
    for spec in all_specs():
        state = backend.container_state(spec.container_name)
        if spec.engine == "pipelock":
            pin = spec.image_digest
        elif spec.pin_kind == "package":
            pin = spec.primary_package_version
        else:
            pin = spec.source_ref
        pin = pin or "(unpinned)"
        marker = " (active)" if spec.engine == active else ""
        print(f"{spec.engine}: {state}{marker}")
        print(f"  container: {spec.container_name}")
        tag = spec.image_tag or spec.primary_package_version or spec.source_ref[:12] or "?"
        print(f"  image:     {spec.image_repository}:{tag}")
        print(f"  pin:       {pin or '(unpinned)'}")
    if active:
        healthy, detail, _ = probe_proxy(host, port) if port_listening(host, port) \
            else (False, "endpoint not listening", False)
        print(f"proxy check: {'OK' if healthy else 'FAILED'} — {detail}")
        return 0 if healthy else 1
    print("proxy check: skipped (no engine running)")
    return 0


def cmd_logs(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    engine = opts.engine or running_engine(backend)
    if not engine:
        raise Fail("no engine is running; pass --engine to view a stopped container's logs")
    spec = ServiceSpec.load(engine)
    if backend.container_state(spec.container_name) == "absent":
        raise Fail(f"no container {spec.container_name} exists")
    return backend.logs(spec.container_name, follow=opts.follow)


def cmd_check(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    active = running_engine(backend)
    if not active:
        raise Fail("no engine is running — `./run.py up` first")
    engine = opts.engine or active
    if engine != active:
        raise Fail(f"--engine {engine} requested but {active} is running; `./run.py --engine {engine} up` first")
    spec = ServiceSpec.load(engine)
    host, port = endpoint()
    cmd = [sys.executable, str(REPO_ROOT / "checks" / "egress.py"),
           "--proxy", f"http://{host}:{port}", "--engine", engine,
           "--backend-bin", backend.bin, "--container", spec.container_name,
           # Recorded in the JSON envelope so a result file states which
           # build it measured; scripts/report.py reads it back into the
           # conditions table in docs/engines.md.
           "--image", spec.run_image_ref()]
    # dns-rebinding grades on what the fixture observed, so the checker
    # needs its log stream too. Only present under `up --test-policy`.
    fixture = ServiceSpec.load(DNS_FIXTURE)
    if backend.container_state(fixture.container_name) == "running":
        cmd += ["--fixture-container", fixture.container_name]
    cmd.append("--full" if opts.full else "--quick")
    if opts.json:
        cmd.append("--json")
    return subprocess.run(cmd).returncode


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Local containerized Internet filtering proxy "
                    "(Pipelock, Smokescreen or Squid) "
                    f"on http://{DEFAULT_ENDPOINT}",
    )
    parser.add_argument("--engine", choices=ENGINES, default=None,
                        help=f"proxy engine (default: {DEFAULT_ENGINE}; status-dependent for logs/check)")
    parser.add_argument("--backend", choices=BACKENDS, default=None,
                        help="container backend (default: Apple `container` on macOS when installed, else docker)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_policy = sub.add_parser("policy",
                              help="render config/* from config.toml (setup/up do this too)")
    p_policy.add_argument("--check", action="store_true",
                          help="report drift as a diff and exit 1 instead of writing")
    p_policy.set_defaults(func=cmd_policy)

    p_setup = sub.add_parser("setup", help="validate prerequisites, pull/build pinned images")
    p_setup.add_argument("--rebuild", action="store_true",
                         help="rebuild a locally built image (smokescreen, squid) even if present")
    p_setup.set_defaults(func=cmd_setup)

    p_up = sub.add_parser("up", help="(re)create the proxy container and health-check it")
    p_up.add_argument("--test-policy", action="store_true",
                      help="use config/<engine>.test.yaml (DNS fixture domains for `check --full`)")
    p_up.set_defaults(func=cmd_up)

    p_restart = sub.add_parser("restart", help="explicit teardown then up")
    p_restart.add_argument("--test-policy", action="store_true")
    p_restart.set_defaults(func=cmd_restart)

    sub.add_parser("down", help="remove containers owned by this repository").set_defaults(func=cmd_down)
    sub.add_parser("status", help="show engine/backend/pin/endpoint state").set_defaults(func=cmd_status)

    p_logs = sub.add_parser("logs", help="show engine logs")
    p_logs.add_argument("--follow", "-f", action="store_true")
    p_logs.set_defaults(func=cmd_logs)

    p_check = sub.add_parser("check", help="run the egress security test suite")
    mode = p_check.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="ordinary allow/deny behavior (default)")
    mode.add_argument("--full", action="store_true", help="include SSRF and CONNECT-abuse fixtures")
    p_check.add_argument("--json", action="store_true", help="machine-readable results")
    p_check.set_defaults(func=cmd_check)

    p_pin = sub.add_parser("pin", help="record immutable pins in services/*.toml (needs network)")
    p_pin.add_argument("target", choices=PINNABLE)
    p_pin.add_argument("--ref", help="smokescreen: pin a specific tag/branch instead of HEAD; "
                                     "squid: pin a specific apk version instead of the base image's")
    p_pin.set_defaults(func=cmd_pin)

    # `setup` prepares one engine by default; allow all.
    p_setup.add_argument("--all", dest="engine_all", action="store_true",
                         help="prepare every engine")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    opts = parser.parse_args(argv)
    if opts.command == "setup":
        opts.engine = "all" if getattr(opts, "engine_all", False) else (opts.engine or DEFAULT_ENGINE)
    try:
        return opts.func(opts)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
