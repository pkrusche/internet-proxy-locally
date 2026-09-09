"""Rendering lab/config/: the test policy and the fixture hosts file.

The same templates and the same renderer as the operational lane, with
`test_policy=True` and a second allowlist — which is what guarantees the
`.test` configs are the shipped policy plus fixture names rather than an
independently written policy that happens to look similar.
"""

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


def render_test_policies(config: LabConfig | None = None) -> dict[Path, str]:
    """Render the `.test` configs and the fixture hosts file.

    Same templates and same Jinja environment as `ipl policy` — only
    `test_policy` differs, so the two lanes cannot disagree about anything
    but the allowlist itself.
    """
    config = load_lab_config() if config is None else config
    rendered = render_engine_policies(
        allow=config.allow,
        allow_test=config.allow_test,
        test_policy=True,
        destination=test_config_path,
        tls_interception=config.tls_interception,
    )
    env = jinja_env()
    rendered.update(_render_fixture_hosts(env, config.fixture))
    rendered.update(_render_fixture_env(env, config.fixture))
    return rendered


def _render_fixture_hosts(env, fixture: FixtureConfig) -> dict[Path, str]:
    """Render lab/config/dns-fixture.hosts from `[fixture]`.

    The hosts file is not a policy — nothing in it is enforced — but it is
    the other half of the test policy, and hand-syncing it against
    `[policy.test].allow` is exactly what `load_lab_config()` refuses to
    leave to care (docs/lab.md).
    """
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
    """Render lab/config/fixture.env, the responder's half of `[fixture]`.

    The hosts file above covers the static records; this covers the four
    facts only `rebind.py` needs — the rebinding zone, the public answer
    and the PTR claim. They used to reach the container as build args, so
    an already-built image went on serving the previous values after an
    edit to fixtures.toml. Mounted, they are read at container start and
    `[fixture]` stays the one source.
    """
    spec = fixture_spec()
    text = render_named(
        env,
        "fixture.env.j2",
        test_policy=True,  # for the shared banner: this file is the lab lane's
        fixture=fixture,
    )
    return {paths.workspace_root() / spec.extra_config_file: text}


def sync_test_policies(config: LabConfig | None = None) -> list[Path]:
    """Regenerate lab/config/; return what changed."""
    return write_rendered(render_test_policies(config))
