"""Rendering the allowlist into engine configs, and writing the result.

config.toml holds the allowlist once; data/templates/*.j2 hold everything else
each engine needs, as literal text. Rendering the two together produces
config/<engine>.{yaml,conf} and the `.test` variants, so the three
engines cannot express different policies — the thing docs/policy.md used
to ask a human to keep true by editing three files.

Almost nothing security-critical is parameterized: the deny floors, the
rule order and `cache deny all` are literal text in the templates. The one
exception is `tls_interception`, and even that is not a knob with a range
— it is a single on/off gate between two fixed, literal recipes (plain
`http_port`/no `ssl_bump` vs. the full CA-backed bump recipe for Squid; the
same shape for Pipelock), each reviewed as a whole. The generator fills in
domains and that one gate, and its output is put through the same
`validate_policy_file()` the hand-written files went through — before it
is allowed to touch the disk.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from internet_proxy_locally import paths
from internet_proxy_locally.constants import ENGINES
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.policy.config import PolicyConfig, load_policy_config
from internet_proxy_locally.policy.validate import (
    check_squid_error_pages,
    validate_policy_text,
)
from internet_proxy_locally.spec import ServiceSpec


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


def _template_name(spec: ServiceSpec) -> str:
    """`config/squid.conf` -> `squid.conf.j2`."""
    return Path(spec.config_file).name + ".j2"


def jinja_env():
    """The shared Jinja environment for data/templates/.

    Public because ipl-lab renders the same templates with `test_policy`
    set, and a second environment configured slightly differently would be
    a way for the two lanes to disagree about whitespace or undefined
    handling rather than about policy.
    """
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
    return env


def render_named(env, name: str, **variables) -> str:
    """Render one template from data/templates/ by file name.

    The existence check is here rather than at the call sites because a
    missing template has to fail loudly: rendering nothing would produce
    an empty policy, and an empty policy is an open one.
    """
    if not (paths.template_dir() / name).is_file():
        raise Fail(f"missing template: {paths.template_dir() / name}")
    return env.get_template(name).render(
        template_name=f"data/templates/{name}", **variables
    )


def render_template(env, spec: ServiceSpec, **variables) -> str:
    """Render the template a service's `config_file` names."""
    return render_named(env, _template_name(spec), **variables)


def config_destination(spec: ServiceSpec) -> Path:
    """Where `ipl policy` writes this engine's config."""
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
    """Render every engine's config from one allowlist pair.

    Both lanes come through here, differing only in `test_policy`, the
    second allowlist and where the result is written — so they cannot
    disagree about anything else. That is the whole point: the `.test`
    configs have to be the shipped policy plus fixture names, and the
    cheapest way to guarantee it is for one function to render both.
    """
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


def render_policies(config: PolicyConfig | None = None) -> dict[Path, str]:
    """Render every engine config from config.toml. Path -> file contents.

    The operational policy only. The `.test` variants of these same
    templates are rendered by ipl-lab into lab/config/, which is the only
    place a fixture domain can enter a config file.
    """
    config = load_policy_config() if config is None else config
    return render_engine_policies(
        allow=config.allow,
        allow_test=[],
        test_policy=False,
        destination=config_destination,
        tls_interception=config.tls_interception,
    )


def check_rendered_policies(rendered: dict[Path, str]) -> list[str]:
    """Validate rendered text before it is allowed near the disk.

    Auto-regeneration means a template or generator bug could otherwise
    overwrite a reviewed, working policy with a broken one. The same
    `validate_policy_file()` invariants that guarded the hand-written files
    guard the generated ones.

    ipl-lab calls this on its own rendered `.test` files too, and adds the
    superset rule those have to satisfy against these.
    """
    problems: list[str] = []
    for path, text in sorted(rendered.items()):
        engine = _engine_for_config(path)
        if engine is None:
            continue  # not an engine policy (the fixture's hosts file)
        problems += validate_policy_text(engine, text, path)
        if engine == "squid":
            problems += check_squid_error_pages(text, path)
    return problems


def fail_on(problems: list[str], message: str) -> None:
    """Report every configuration problem, then fail closed.

    Every caller that validates something does exactly this, and the one
    that did it slightly differently is the drift worth removing: the
    problems all have to be printed — the first is rarely the useful one —
    and then nothing may proceed. ipl-lab calls this too, so both lanes
    report a bad config in the same shape.
    """
    for problem in problems:
        print(f"CONFIG ERROR: {problem}", file=sys.stderr)
    if problems:
        raise Fail(message)


def _engine_for_config(path: Path) -> str | None:
    """Which engine a rendered config belongs to, by filename.

    `config/squid.conf` and `lab/config/squid.test.conf` are both Squid, so
    both lanes validate with the same rules from one place.
    """
    stem = path.name.split(".")[0]
    return stem if stem in ENGINES else None


def sync_policies(config: PolicyConfig | None = None) -> list[Path]:
    """Regenerate the engine configs from config.toml; return what changed.

    Files whose contents already match are left alone, so a no-op `up`
    does not churn mtimes or the working tree.
    """
    return write_validated(render_policies(config), check_rendered_policies)


def write_validated(
    rendered: dict[Path, str], check: Callable[[dict[Path, str]], list[str]]
) -> list[Path]:
    """Validate rendered text, then write only what changed.

    Both lanes render templates and both must refuse to overwrite a
    reviewed, working policy with a broken one — so validation happens
    before anything reaches the disk, and files that already match are
    left alone so a no-op `up` does not churn mtimes or the working tree.
    ipl-lab passes its own `check`, which adds the superset rule.
    """
    fail_on(
        check(rendered),
        "refusing to write a policy that fails validation (fail closed)",
    )
    changed: list[Path] = []
    for path, text in sorted(rendered.items()):
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
            changed.append(path)
    return changed


def report_synced(changed: list[Path], source: str) -> None:
    """Name what a sync rewrote; quiet when everything was already current.

    Both lanes report a regeneration the same way, and each names its own
    source — `config.toml` for the operational lane, that plus the fixture
    spec for the lab one.
    """
    for path in changed:
        print(f"regenerated {path.relative_to(paths.workspace_root())} from {source}")
