"""One service definition: which image to run and what to mount where.

There are four of these and they change about as often as the code does,
so they are constants rather than data files. They used to be
`data/services/*.toml`, parsed at every call, carrying an `[image]` /
`[source]` / `[build]` table that Python read pins out of and wrote pins
back into. Pins now live in the Dockerfiles (see `images.py`) and what is
left is the part that genuinely describes a *run*: a container name, the
port it listens on, and which rendered config file is bind-mounted where.

The engines are `ENGINES`; `dnsfixture` is the lab lane's and is reached
only through `lab.container.fixture_spec()`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from internet_proxy_locally import ca, paths
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.images import (
    DNSFIXTURE_IMAGE,
    PIPELOCK_IMAGE,
    SMOKESCREEN_IMAGE,
    SQUID_IMAGE,
)


@dataclass(frozen=True)
class ServiceSpec:
    engine: str
    # The tag `images.py` builds and `up` runs. Not reconstructed from
    # parts anywhere: one string, named once.
    image: str
    container_name: str
    internal_port: int
    # Rendered from data/templates/ into the workspace, then bind-mounted
    # read-only at `config_mount`. The template is named by the basename of
    # `config_file`, so this one key moves the template, the destination and
    # the mount together (`policy.render._template_name()`).
    config_file: str
    config_mount: str
    # A second mounted file, where a service needs one: Smokescreen's daemon
    # config (`allow_missing_role` is a config-file key with no CLI
    # equivalent) and the DNS fixture's `[fixture]` facts.
    extra_config_file: str = ""
    extra_config_mount: str = ""
    # Whether this engine can be started with TLS interception on, and
    # where the CA material mounts in its container if so. Only pipelock
    # and squid set these — smokescreen/dnsfixture keep the defaults, which
    # is what makes `lifecycle.start_engine()`'s fail-closed check refuse
    # smokescreen with no smokescreen-specific code anywhere.
    supports_tls_interception: bool = False
    ca_cert_mount: str = ""
    ca_key_mount: str = ""

    @classmethod
    def load(cls, engine: str) -> ServiceSpec:
        """The spec for `engine`, by name."""
        spec = SERVICES.get(engine)
        if spec is None:
            raise Fail(f"unknown service: {engine}")
        return spec

    def config_path(self) -> Path:
        if not self.config_file:
            raise Fail(f"{self.engine}: no config_file")
        path = paths.workspace_root() / self.config_file
        if not path.is_file():
            raise Fail(f"missing config file: {path}")
        return path

    def mounts(self, config_path: Path | None = None) -> list[tuple[Path, str]]:
        """Read-only bind mounts: the policy file, plus any second file.

        `config_path` overrides the shipped policy — ipl-lab passes the
        rendered test policy from lab/config/ there, which is the only way
        an engine ever starts on anything but `config_file`.
        """
        pairs = [(config_path or self.config_path(), self.config_mount)]
        if self.extra_config_file:
            path = paths.workspace_root() / self.extra_config_file
            if not path.is_file():
                raise Fail(f"missing config file: {path}")
            if not self.extra_config_mount:
                raise Fail(f"{self.engine}: extra_config_file needs extra_config_mount")
            pairs.append((path, self.extra_config_mount))
        return pairs

    def ca_mounts(self) -> list[tuple[Path, str]]:
        """Read-only bind mounts for the CA cert+key, or none if unsupported.

        Separate from `mounts()` deliberately: that method resolves
        checked-in, reviewed-in-a-diff paths named by this spec, and CA
        material is neither — it is generated, gitignored, and named by
        `ca.py` under `paths.ca_dir()`.
        """
        if not self.supports_tls_interception:
            return []
        return [
            (ca.ca_cert_path(), self.ca_cert_mount),
            (ca.ca_key_path(), self.ca_key_mount),
        ]


SERVICES = {
    "pipelock": ServiceSpec(
        engine="pipelock",
        image=PIPELOCK_IMAGE,
        container_name="internet-proxy-pipelock",
        internal_port=8888,
        config_file="config/pipelock.yaml",
        config_mount="/config/pipelock.yaml",
        supports_tls_interception=True,
        ca_cert_mount="/config/ca.pem",
        ca_key_mount="/config/ca-key.pem",
    ),
    "smokescreen": ServiceSpec(
        engine="smokescreen",
        image=SMOKESCREEN_IMAGE,
        container_name="internet-proxy-smokescreen",
        internal_port=4750,
        config_file="config/smokescreen.yaml",
        config_mount="/etc/smokescreen/acl.yaml",
        # Hand-maintained rather than rendered: it carries no allowlist.
        extra_config_file="config/smokescreen.conf.yaml",
        extra_config_mount="/etc/smokescreen/config.yaml",
    ),
    "squid": ServiceSpec(
        engine="squid",
        image=SQUID_IMAGE,
        container_name="internet-proxy-squid",
        internal_port=3128,
        config_file="config/squid.conf",
        config_mount="/etc/squid/squid.conf",
        supports_tls_interception=True,
        ca_cert_mount="/etc/squid/ca.pem",
        ca_key_mount="/etc/squid/ca-key.pem",
    ),
    # NOT an engine, and never part of an operational run — `ENGINES` does
    # not contain it and only the lab lane loads it. It answers allowlisted
    # names with private addresses on purpose, which is why `down` sweeps
    # its container from both lanes.
    "dnsfixture": ServiceSpec(
        engine="dnsfixture",
        image=DNSFIXTURE_IMAGE,
        container_name="internet-proxy-dnsfixture",
        internal_port=53,
        config_file="lab/config/dns-fixture.hosts",
        config_mount="/fixture/hosts",
        # What the responder serves — the rebinding zone, the public answer
        # and the PTR claim — rendered from `[fixture]` in fixtures.toml
        # alongside the hosts file, so an edit there takes effect on the
        # next `up` rather than on the next rebuild.
        extra_config_file="lab/config/fixture.env",
        extra_config_mount="/fixture/fixture.env",
    ),
}
