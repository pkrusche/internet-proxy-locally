"""Where everything is. The only module that answers that question.

There are two roots, and keeping them apart is the point of this file.

**The data root** holds what ships with the package and is read, never
written, at runtime: the Jinja templates, the lab fixture's records, and
the image build contexts with their pins. It lives inside the package so an
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
copying the code into it.

This replaces eight separate `REPO_ROOT = Path(__file__).resolve().parent`
lines that all had to stay in agreement about the layout.
"""

from __future__ import annotations

import importlib.resources
import os
from pathlib import Path

from internet_proxy_locally.errors import Fail


def data_root() -> Path:
    """Files that ship with the package: templates, images, fixture data."""
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


# --- the data root ---------------------------------------------------------


def template_dir() -> Path:
    return data_root() / "templates"


def image_dir() -> Path:
    """Image build contexts — one directory per image, including the fixture."""
    return data_root() / "images"


def squid_error_dir() -> Path:
    """The `ERR_IPL_*` denial pages baked into the Squid image."""
    return image_dir() / "squid" / "errors"


def lab_dir() -> Path:
    """The lab lane's own data: fixtures.toml, what the fixture serves.

    How its image is built is in `data/images/dnsfixture/`, with every
    other build context; how it is run is in `spec.SERVICES`.
    """
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
