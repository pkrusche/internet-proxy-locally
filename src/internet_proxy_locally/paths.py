"""Where everything is. The only module that answers that question.

There are two roots, and keeping them apart is the point of this file.

**The data root** holds what ships with the package and is read, never
written, at runtime: the Jinja templates, the service specs with their
pins, and the image build contexts. It lives inside the package so an
installed wheel is self-contained — `ipl setup` can build the Squid image
without a checkout to find the Dockerfile in.

**The workspace root** holds what a person edits or the tool generates:
`config.toml` (the allowlist), the rendered `config/` and `lab/config/`
that get bind-mounted into containers, `results/` and `docs/findings.md`.
None of it belongs in a wheel, and it is found by walking up from the
working directory looking for `config.toml` — which is what makes the CLI
work from anywhere inside a checkout, the way git does.

Both are overridable by environment variable. That is not a convenience
for users: it is how the test suite gets an isolated repository without
copying the code into it, and it is how `pin` is pointed at a checkout.

This replaces eight separate `REPO_ROOT = Path(__file__).resolve().parent`
lines that all had to stay in agreement about the layout.
"""

from __future__ import annotations

import importlib.resources
import os
from pathlib import Path

from internet_proxy_locally.errors import Fail


def data_root() -> Path:
    """Files that ship with the package: templates, service specs, images."""
    override = os.environ.get("IPL_DATA_ROOT")
    if override:
        return Path(override)
    root = importlib.resources.files("internet_proxy_locally") / "data"
    # `docker build` needs a real directory to use as a build context, so a
    # zipped install cannot work. uv installs unzipped; anything else is
    # unsupported the same way a bare interpreter is.
    if not isinstance(root, Path):
        raise Fail(
            "installed as a zip; internet-proxy-locally needs a real "
            "directory for image build contexts"
        )
    return root


def workspace_root() -> Path:
    """The checkout being operated on: config.toml and everything generated.

    Walks up from the working directory looking for `config.toml`, so the
    CLI works from any subdirectory. Falls back to the working directory
    itself, which is what makes the "no config.toml" error name a path the
    person can actually go and create.
    """
    override = os.environ.get("IPL_ROOT")
    if override:
        return Path(override)
    start = Path.cwd().resolve()
    for candidate in (start, *start.parents):
        if (candidate / "config.toml").is_file():
            return candidate
    return start


def writable_data_root() -> Path:
    """The data root, when recording a pin into it is legitimate.

    `pin` rewrites a service spec, and a spec is source: its whole purpose
    is to be reviewed in a diff and committed. Writing one into an
    installed wheel would edit site-packages and be silently lost on the
    next upgrade, so that fails loudly here instead.
    """
    if os.environ.get("IPL_DATA_ROOT"):
        return data_root()
    root = data_root()
    if len(root.parents) > 2 and (root.parents[2] / "pyproject.toml").is_file():
        return root
    raise Fail(
        "recording a pin edits a service spec, which is source: run "
        "`pin` in a checkout of the repository, review the change and "
        "commit it"
    )


# --- the data root ---------------------------------------------------------


def service_dir() -> Path:
    """The operational lane's service specs (pipelock, smokescreen, squid)."""
    return data_root() / "services"


def template_dir() -> Path:
    return data_root() / "templates"


def image_dir() -> Path:
    """Image build contexts for the engines this repository builds itself."""
    return data_root() / "images"


def squid_error_dir() -> Path:
    """The `ERR_IPL_*` denial pages baked into the Squid image."""
    return image_dir() / "squid" / "errors"


def lab_dir() -> Path:
    """The lab lane's specs: fixtures.toml, dnsfixture.toml, dnsfixture/."""
    return data_root() / "lab"


def fixture_file() -> Path:
    return lab_dir() / "fixtures.toml"


# --- the workspace root ----------------------------------------------------


def policy_file() -> Path:
    """config.toml — the allowlist, edited by a person, committed."""
    return workspace_root() / "config.toml"


def config_dir() -> Path:
    """Rendered operational engine configs, bind-mounted read-only."""
    return workspace_root() / "config"


def lab_config_dir() -> Path:
    """Rendered test configs and the fixture hosts file."""
    return workspace_root() / "lab" / "config"


def results_dir() -> Path:
    """Recorded check runs; docs/findings.md is generated from these."""
    return workspace_root() / "results"


def findings_file() -> Path:
    return workspace_root() / "docs" / "findings.md"
