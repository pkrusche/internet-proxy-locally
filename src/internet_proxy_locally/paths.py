"""Resolve packaged data and workspace paths; see docs/development.md."""

from __future__ import annotations

import importlib.resources
import os
from pathlib import Path

from internet_proxy_locally.errors import Fail


def data_root() -> Path:
    """Files that ship with the package: templates and image build contexts."""
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


def template_dir() -> Path:
    return data_root() / "templates"


def image_dir() -> Path:
    """Image build contexts — one directory per image, including the fixture."""
    return data_root() / "images"


def squid_error_dir() -> Path:
    """The `ERR_IPL_*` denial pages baked into the Squid image."""
    return image_dir() / "squid" / "errors"


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


def ca_dir() -> Path:
    """The TLS-interception signing CA: generated, host-specific, gitignored.

    Unlike `config_dir()` and `lab_config_dir()`, nothing here is rendered
    from a reviewed source — it is generated once per checkout by `ipl ca
    init` and trusted by that checkout's sandboxes specifically, which is
    why it lives under `state/` rather than `config/` (see .gitignore).
    """
    return workspace_root() / "state" / "ca"
