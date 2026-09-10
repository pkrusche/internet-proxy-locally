"""Rendering the allowlist into engine configs, and writing the result."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from internet_proxy_locally import paths
from internet_proxy_locally.constants import ENGINES
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.policy.config import PolicyConfig, load_policy_config
from internet_proxy_locally.spec import ServiceSpec


def _yaml_scalar(entry: str) -> str:
    """Quote what YAML would otherwise read as syntax — `*` starts an alias."""
    return entry if entry[:1].isalnum() else f'"{entry}"'


def _squid_wild(entry: str) -> str:
    r"""Render `*.github.com` as Squid's `\.github\.com$` suffix regex."""
    if not entry.startswith("*."):
        raise Fail(f"not a wildcard allowlist entry: {entry}")
    return "\\." + entry[2:].replace(".", "\\.") + "$"


def _iron_domain(entry: str) -> str:
    """Iron's `*.d` includes the apex; `?*.d` requires a subdomain.

    The latter uses Iron's ordinary Go path.Match glob branch rather than
    its special `*.` suffix matcher. Both globs cover nested subdomains.
    """
    return "?" + entry if entry.startswith("*.") else entry


def _template_name(spec: ServiceSpec) -> str:
    """`config/squid.conf` -> `squid.conf.j2`."""
    return Path(spec.config_file).name + ".j2"


def jinja_env():
    """The shared Jinja environment for data/templates/."""
    env = Environment(
        loader=FileSystemLoader(str(paths.template_dir())),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        autoescape=False,  # config files, not markup
    )
    env.filters["yaml_scalar"] = _yaml_scalar
    env.filters["squid_wild"] = _squid_wild
    env.filters["iron_domain"] = _iron_domain
    return env


def render_named(env, name: str, **variables) -> str:
    """Render one template from data/templates/ by file name."""
    if not (paths.template_dir() / name).is_file():
        raise Fail(f"missing template: {paths.template_dir() / name}")
    return env.get_template(name).render(
        template_name=f"data/templates/{name}", **variables
    )


def render_template(env, spec: ServiceSpec, **variables) -> str:
    """Render the template a service's `config_file` names."""
    return render_named(env, _template_name(spec), **variables)


def config_destination(spec: ServiceSpec) -> Path:
    """Workspace destination for the generated engine config."""
    if not spec.config_file:
        raise Fail(f"{spec.engine}: no config_file in spec.SERVICES")
    return paths.workspace_root() / spec.config_file


def render_engine_policies(
    *,
    allow: tuple[str, ...] | list[str],
    allow_test: tuple[str, ...] | list[str],
    test_policy: bool,
    destination: Callable[[ServiceSpec], Path],
    tls_interception: bool = False,
) -> dict[Path, str]:
    """Render every engine's config from one allowlist pair."""
    env = jinja_env()
    rendered: dict[Path, str] = {}
    for engine in ENGINES:
        spec = ServiceSpec.load(engine)
        rendered[destination(spec)] = render_template(
            env,
            spec,
            test_policy=test_policy,
            allow=list(allow),
            allow_test=list(allow_test),
            allow_exact=PolicyConfig.exact(allow),
            allow_wild=PolicyConfig.wild(allow),
            allow_test_exact=PolicyConfig.exact(allow_test),
            allow_test_wild=PolicyConfig.wild(allow_test),
            tls_interception=tls_interception,
        )
    return rendered


def render_policies(
    config: PolicyConfig | None = None, *, tls_interception: bool = False
) -> dict[Path, str]:
    """Render every engine config from config.toml. Path -> file contents."""
    config = load_policy_config() if config is None else config
    return render_engine_policies(
        allow=config.allow,
        allow_test=[],
        test_policy=False,
        destination=config_destination,
        tls_interception=tls_interception,
    )


def sync_policies(
    config: PolicyConfig | None = None, *, tls_interception: bool = False
) -> list[Path]:
    """Regenerate the engine configs from config.toml; return what changed."""
    return write_rendered(render_policies(config, tls_interception=tls_interception))


def write_rendered(rendered: dict[Path, str]) -> list[Path]:
    """Write rendered files atomically, leaving matching files alone."""
    changed: list[Path] = []
    for path, text in sorted(rendered.items()):
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, path)
            finally:
                Path(tmp_name).unlink(missing_ok=True)
            changed.append(path)
    return changed
