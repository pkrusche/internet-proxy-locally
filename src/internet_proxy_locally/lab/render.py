"""Rendering lab/config/: the test policy and the fixture hosts file."""

from __future__ import annotations

from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.lab.container import fixture_spec
from internet_proxy_locally.lab.fixtures import (
    FixtureConfig,
    LabConfig,
    load_lab_config,
    private_address,
)
from internet_proxy_locally.policy.render import (
    jinja_env,
    render_engine_policies,
    render_named,
    render_template,
    write_rendered,
)
from internet_proxy_locally.spec import ServiceSpec


def test_config_path(spec: ServiceSpec) -> Path:
    """`config/squid.conf` -> `lab/config/squid.test.conf`.

    By convention rather than by a key in `spec.SERVICES`: the service
    definitions describe how to run an engine, and where this lane keeps
    its rendered fixtures is not their business.
    """
    name = Path(spec.config_file).name
    stem, _, suffix = name.partition(".")
    return paths.lab_config_dir() / f"{stem}.test.{suffix}"


def render_test_policies(
    config: LabConfig | None = None, *, tls_interception: bool = False
) -> dict[Path, str]:
    """Render lab configs with the shared policy templates and fixture data."""
    config = load_lab_config() if config is None else config
    rendered = render_engine_policies(
        allow=config.allow,
        allow_test=config.allow_test,
        test_policy=True,
        destination=test_config_path,
        tls_interception=tls_interception,
    )
    env = jinja_env()
    rendered.update(_render_fixture_hosts(env, config.fixture))
    rendered.update(_render_fixture_env(env, config.fixture))
    return rendered


def _render_fixture_hosts(env, fixture: FixtureConfig) -> dict[Path, str]:
    """Render lab/config/dns-fixture.hosts from `[fixture]`."""
    spec = fixture_spec()
    rows = []
    for record, addresses in fixture.records:
        shape = ["private" if private_address(a) else "public" for a in addresses]
        rows.append(
            {
                "name": record,
                "addresses": list(addresses),
                "role": "control" if record == fixture.control else "mixed",
                "shape": f"{shape[0].capitalize()} answer first, {shape[-1]} second",
            }
        )
    text = render_template(
        env,
        spec,
        test_policy=True,  # for the shared banner: this file is the lab lane's
        fixture=fixture,
        fixture_records=rows,
    )
    return {paths.workspace_root() / spec.config_file: text}


def _render_fixture_env(env, fixture: FixtureConfig) -> dict[Path, str]:
    """Render lab/config/fixture.env, the responder's half of `[fixture]`."""
    spec = fixture_spec()
    text = render_named(
        env,
        "fixture.env.j2",
        test_policy=True,  # for the shared banner: this file is the lab lane's
        fixture=fixture,
    )
    return {paths.workspace_root() / spec.extra_config_file: text}


def sync_test_policies(
    config: LabConfig | None = None, *, tls_interception: bool = False
) -> list[Path]:
    """Regenerate lab/config/; return what changed."""
    return write_rendered(
        render_test_policies(config, tls_interception=tls_interception)
    )
