#!/usr/bin/env python3
"""Fail closed when wheel/sdist members fall outside the release manifest."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

FORBIDDEN = ("/.git/", "/.jj/", "/.uv_cache/", "/.venv/", "/state/", "/dist/")
ROOT_ALLOWED = {
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "LICENSE",
    "pyproject.toml",
    "uv.lock",
    "config.toml",
    ".gitignore",
    "PKG-INFO",
}
PREFIXES = ("src/", "tests/", "scripts/", "docs/", "lab/", "config/")


def members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
    prefix = names[0].split("/", 1)[0] + "/"
    return [name.removeprefix(prefix) for name in names if name != prefix[:-1]]


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        raise SystemExit("usage: check-artifacts.py WHEEL SDIST")
    failed = False
    for raw in argv[1:]:
        path = Path(raw)
        names = members(path)
        bad = [n for n in names if any(f in "/" + n for f in FORBIDDEN)]
        if path.suffix != ".whl":
            bad += [
                n
                for n in names
                if n and n not in ROOT_ALLOWED and not n.startswith(PREFIXES)
            ]
        required = (
            "internet_proxy_locally/data/templates/",
            "internet_proxy_locally/data/images/",
        )
        missing = [p for p in required if not any(p in n for n in names)]
        if bad or missing:
            failed = True
            print(f"{path}: unexpected={bad[:20]} missing={missing}", file=sys.stderr)
        else:
            print(f"{path}: manifest OK ({len(names)} members)")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
