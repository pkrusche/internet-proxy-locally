"""Getting a pinned image onto the machine, and recording the pins.

Two halves that share one dispatch key. `prepare_engine` turns a spec into
a present image; `pin_*` is how that spec came to name something immutable
in the first place. Both branch on `ServiceSpec.pin_kind` rather than on
the engine name, which is what keeps "pull a digest", "build a commit" and
"build a package version" three cases instead of three engines.

Every path here fails closed on an unpinned spec and points at `pin`.
Nothing writes a pin for you: a pin that appeared on its own is a pin
nobody reviewed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.spec import ServiceSpec


def prepare_engine(backend: Backend, engine: str, rebuild: bool = False) -> None:
    """Pull or build one service's pinned image. Also used by ipl-lab.

    Dispatch is on `pin_kind` alone — what the service is pinned *by* —
    rather than on its name, so adding a fourth engine is a config-only
    change. `spec` is enough; nothing here needs to know which engine it
    is looking at.
    """
    spec = ServiceSpec.load(engine)
    SETUP_BY_PIN_KIND[spec.pin_kind](backend, spec, rebuild=rebuild)


def _setup_pulled_image(
    backend: Backend, spec: ServiceSpec, rebuild: bool = False
) -> None:
    """Pull an image pinned by OCI digest (Pipelock).

    `setup` never resolves a pin itself. It used to, for this one service:
    with no digest recorded it pulled the mutable tag, read a digest back
    and wrote it into the TOML — so a fresh checkout ran whatever the tag
    pointed at that day, recorded after the fact rather than reviewed
    before it. The other two services have always refused and pointed at
    `pin`, and `run_image_ref()` now gives all three the same message.
    """
    ref = spec.run_image_ref()  # raises, with the `pin` hint, when unpinned
    print(f"{spec.engine}: pulling pinned image {ref}")
    backend.pull(ref)


def _setup_source_image(
    backend: Backend, spec: ServiceSpec, rebuild: bool = False
) -> None:
    """Build an image from a pinned source commit (Smokescreen)."""
    tag = spec.run_image_ref()  # raises when the source ref is unpinned
    if backend.image_present(tag) and not rebuild:
        print(f"{spec.engine}: image {tag} already built")
        return
    print(f"{spec.engine}: building {tag} from {spec.source_repo}@{spec.source_ref}")
    build_args = dict(spec.build_args)
    build_args[f"{spec.engine.upper()}_REPO"] = spec.source_repo
    build_args[f"{spec.engine.upper()}_REF"] = spec.source_ref
    _build(backend, spec, tag, build_args)


def _setup_package_image(
    backend: Backend, spec: ServiceSpec, rebuild: bool = False
) -> None:
    """Build an image around a pinned distribution package — Squid, and the
    dnsmasq DNS fixture. The Dockerfile takes `<PACKAGE>_VERSION`."""
    tag = spec.run_image_ref()  # raises when any package is unpinned
    if backend.image_present(tag) and not rebuild:
        print(f"{spec.engine}: image {tag} already built")
        return
    pinned = ", ".join(
        f"{name}={version}" for name, version in sorted(spec.packages.items())
    )
    print(f"{spec.engine}: building {tag} from {spec.base_image} ({pinned})")
    _build(backend, spec, tag, spec.build_args)


def _build(
    backend: Backend, spec: ServiceSpec, tag: str, build_args: dict[str, str]
) -> None:
    """Build `spec`'s image from its own context directory.

    `image_context` for every service, including Smokescreen — which used
    to name `data/images/smokescreen` literally, so the property and the path
    it was supposed to describe could disagree.
    """
    context = spec.image_context
    backend.build(
        tag=tag,
        dockerfile=context / "Dockerfile",
        context=context,
        build_args=build_args,
    )
    print(f"{spec.engine}: built {tag}")


# Dispatch table for `prepare_engine`, keyed by `ServiceSpec.pin_kind`.
SETUP_BY_PIN_KIND = {
    "digest": _setup_pulled_image,
    "source": _setup_source_image,
    "package": _setup_package_image,
}


def _write_pin(toml_path: Path, key: str, value: str) -> None:
    """Rewrite one `key = "value"` line in a service spec.

    The single place a pin is written, and therefore the single place the
    "is this a checkout?" question is asked. A spec ships inside the
    package, so in an installed wheel this path is `site-packages` — where
    a recorded pin would be unreviewable and lost on the next upgrade.
    `writable_data_root()` refuses rather than let that happen quietly.
    """
    paths.writable_data_root()
    text = toml_path.read_text()
    new_text, count = re.subn(
        rf'^{key} = "[^"]*"$', f'{key} = "{value}"', text, count=1, flags=re.MULTILINE
    )
    if count != 1:
        raise Fail(
            f"could not update `{key}` in {toml_path}; edit it manually to {value!r}"
        )
    toml_path.write_text(new_text)


def pin_packages(spec: ServiceSpec, get_backend: callable, ref: str = "") -> None:
    """Record the apk versions `spec`'s base image would install.

    Shared with ipl-lab, which pins the DNS fixture exactly this way —
    the fixture is a `package` service like Squid, and the two copies of
    this loop were the only reason that was not obvious. `get_backend` is
    called only when a runtime is actually needed, so `--ref` still pins
    without one.
    """
    names = sorted(spec.packages)
    if ref:
        if len(names) != 1:
            raise Fail(
                f"--ref pins a single package, but {spec.engine} pins "
                f"{len(names)} ({', '.join(names)}); edit "
                f"{spec.toml_path} directly"
            )
        _write_pin(spec.toml_path, names[0], ref)
        print(f"pinned {spec.engine} {names[0]}={ref}")
        return

    base = spec.base_image
    if not base:
        raise Fail(
            f"{spec.toml_path}: [build] base_image is required to pin {spec.engine}"
        )
    print(f"asking {base} which versions of {', '.join(names)} it would install")
    output = get_backend().run_once(
        base,
        [
            "sh",
            "-c",
            f"apk update >/dev/null 2>&1 && apk list {' '.join(names)} 2>/dev/null",
        ],
    )
    for name in names:
        versions = re.findall(
            rf"^{re.escape(name)}-(\d[\w.]*-r\d+)\s", output, re.MULTILINE
        )
        if not versions:
            raise Fail(
                f"could not read a {name} version from {base}.\n"
                f"Check it by hand (`apk list {name}` in that image) and put it in "
                f"{spec.toml_path}"
            )
        resolved = max(versions)
        _write_pin(spec.toml_path, name, resolved)
        print(f"pinned {spec.engine} {name}={resolved} (from {base})")


def pin_digest(spec: ServiceSpec, get_backend: callable, ref: str = "") -> None:
    """Resolve `repository:tag` to its immutable manifest digest."""
    image = f"{spec.image_repository}:{ref or spec.image_tag}"
    print(f"pulling {image} to resolve its digest")
    backend = get_backend()
    backend.pull(image)
    digest = backend.image_digest(image)
    if not digest:
        raise Fail(
            f"could not resolve a digest for {image}; inspect the image manually"
        )
    _write_pin(spec.toml_path, "digest", digest)
    print(f"pinned {spec.engine} {spec.image_tag} @ {digest}")


def pin_source(spec: ServiceSpec, get_backend: callable, ref: str = "") -> None:
    """Resolve a git ref in the upstream repository to a full commit SHA."""
    git = shutil.which("git")
    if not git:
        raise Fail(f"git is required to pin {spec.engine}")
    target = ref or "HEAD"
    proc = subprocess.run(
        [git, "ls-remote", spec.source_repo, target],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise Fail(
            f"git ls-remote {spec.source_repo} {target} failed:\n{proc.stderr.strip()}"
        )
    sha = proc.stdout.split()[0]
    _write_pin(spec.toml_path, "ref", sha)
    print(f"pinned {spec.engine} {target} @ {sha}")


# Dispatch table for `pin`, keyed by `ServiceSpec.pin_kind` — the same key
# `prepare_engine` uses, because "how it is pinned" and "how it is set up"
# are the same question asked twice.
PIN_BY_KIND = {
    "digest": pin_digest,
    "source": pin_source,
    "package": pin_packages,
}
