"""One service definition, read from a `data/services/*.toml` spec.

A spec says which image to run, how to pin it immutably, and what to mount
where. `pin_kind` is the central dispatch key: it is what decides whether
an engine is pulled by digest, built from a source commit or built around a
pinned package version, and both `setup` and `pin` branch on it rather than
on the engine name — so adding an engine never means adding a branch.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.errors import Fail


@dataclass
class ServiceSpec:
    engine: str
    image_repository: str
    image_tag: str = ""
    image_digest: str = ""
    source_repo: str = ""
    source_ref: str = ""
    packages: dict[str, str] = field(default_factory=dict)
    # Whatever `[build]` in the TOML says, passed through to the Dockerfile
    # as `--build-arg KEY.upper()=value`. Kept generic on purpose: naming
    # each key here as a field, then mapping it back to its uppercase ARG
    # by hand, made a new base pin a two-file change for no gain.
    build: dict[str, str] = field(default_factory=dict)
    container_name: str = ""
    internal_port: int = 0
    config_file: str = ""
    config_mount: str = ""
    extra_config_file: str = ""
    extra_config_mount: str = ""
    args: list[str] = field(default_factory=list)
    # Where this service is defined. `data/services/` for the proxy
    # engines; `data/lab/` for the DNS fixture, which only the lab lane
    # ever loads. Both the TOML and the image build context are found
    # relative to it.
    root: Path = field(default_factory=paths.service_dir)

    @property
    def toml_path(self) -> Path:
        return self.root / f"{self.engine}.toml"

    @property
    def image_context(self) -> Path:
        """The directory holding this service's Dockerfile."""
        if self.root == paths.service_dir():
            return paths.image_dir() / self.engine
        return self.root / self.engine

    @classmethod
    def load(cls, engine: str, root: Path | None = None) -> ServiceSpec:
        root = paths.service_dir() if root is None else root
        path = root / f"{engine}.toml"
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
            build={str(key): str(value) for key, value in build.items()},
            container_name=container.get("name", ""),
            internal_port=int(container.get("internal_port", 0)),
            config_file=container.get("config_file", ""),
            config_mount=container.get("config_mount", ""),
            extra_config_file=container.get("extra_config_file", ""),
            extra_config_mount=container.get("extra_config_mount", ""),
            args=list(container.get("args", [])),
            root=root,
        )
        if (
            not spec.image_repository
            or not spec.container_name
            or not spec.internal_port
        ):
            raise Fail(
                f"{path}: image.repository, container.name and container.internal_port are required"
            )
        if spec.image_tag == "latest":
            raise Fail(f"{path}: refusing to use a 'latest' tag; pin a release")
        if (
            "--unsafe-allow-private-ranges" in spec.args
            or "--danger-allow-access-to-private-ranges" in spec.args
        ):
            raise Fail(f"{path}: private-range blocking must never be disabled")
        return spec

    @property
    def base_image(self) -> str:
        """The image `pin` interrogates for package versions.

        The only `[build]` key anything but the Dockerfile needs to know
        by name, because `pin` has to run `apk list` inside exactly the
        image the build will use.
        """
        return self.build.get("base_image", "")

    @property
    def build_args(self) -> dict[str, str]:
        """`[build]` plus the pinned package versions, as Dockerfile ARGs."""
        args = {key.upper(): value for key, value in self.build.items()}
        args.update(
            {
                f"{name.upper()}_VERSION": version
                for name, version in self.packages.items()
            }
        )
        return args

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
        pin_hint = (
            f"Run `ipl pin {self.engine}` (needs network), review, commit, "
            "then `ipl setup`."
        )
        if self.pin_kind == "digest":
            if not self.image_digest:
                raise Fail(
                    f"{self.engine} image digest is not pinned in "
                    f"data/services/{self.engine}.toml.\n{pin_hint}"
                )
            return f"{self.image_repository}@{self.image_digest}"
        if self.pin_kind == "package":
            missing = sorted(
                name for name, version in self.packages.items() if not version
            )
            if missing:
                raise Fail(
                    f"{self.engine} package version is not pinned in "
                    f"data/services/{self.engine}.toml ({', '.join(missing)}).\n{pin_hint}"
                )
            # Tagged by the package the service is named for, so the tag
            # still reads as a version rather than a hash of several.
            return f"{self.image_repository}:{self.primary_package_version}"
        if not self.source_ref:
            raise Fail(
                f"{self.engine} source ref is not pinned in "
                f"data/services/{self.engine}.toml.\n{pin_hint}"
            )
        return f"{self.image_repository}:{self.source_ref[:12]}"

    def config_path(self) -> Path:
        if not self.config_file:
            raise Fail(f"{self.toml_path}: missing config_file")
        path = paths.workspace_root() / self.config_file
        if not path.is_file():
            raise Fail(f"missing config file: {path}")
        return path

    def mounts(self, config_path: Path | None = None) -> list[tuple[Path, str]]:
        """Read-only bind mounts: the policy file, plus any daemon config.

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
                raise Fail(
                    f"{self.toml_path}: extra_config_file needs extra_config_mount"
                )
            pairs.append((path, self.extra_config_mount))
        return pairs
