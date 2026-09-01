"""The images this repository runs, and how to get one onto the machine.

Every image is named by a Dockerfile under `data/images/<name>/`, and every
pin those images depend on — a base image digest, an apk version, an
upstream commit SHA — is a literal in that Dockerfile. Nothing here
resolves a pin, writes one, or validates one: upgrading is editing the
Dockerfile, which is the file that has to be true anyway, and reviewing the
diff. That replaced a `pin` subcommand that pulled or cloned on a networked
machine and rewrote a TOML spec in place.

The constants below are the *only* thing Python knows about an image. They
carry one rule with them:

    **bump the tag when the Dockerfile's pins change.**

`prepare_image` skips a build when the tag is already present, so a
Dockerfile edited without a matching bump would leave the old image in
place and running. `--rebuild` is the manual escape hatch, and
`tests/test_runpy.py` asserts each tag still matches the pin its Dockerfile
names, so the mistake is a red test rather than a stale container.
"""

from __future__ import annotations

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend

# Pipelock is the one engine with a usable upstream image; its Dockerfile
# is a `FROM <digest>` and a CMD, so that "which image" has one answer for
# all four services. The tag is the upstream release it pins.
PIPELOCK_IMAGE = "internet-proxy-locally/pipelock:3.3.0"
# Built from a source commit — tagged with the first 12 characters of it.
SMOKESCREEN_IMAGE = "internet-proxy-locally/smokescreen:131fba29ce1e"
# Built around a pinned distribution package — tagged with its version.
SQUID_IMAGE = "internet-proxy-locally/squid:6.12-r0"
DNSFIXTURE_IMAGE = "internet-proxy-locally/dnsfixture:2.91-r1"

# Service name -> tag. The name is also the directory under data/images/
# holding that image's build context, which is what keeps `setup` from
# needing a per-service branch.
IMAGES = {
    "pipelock": PIPELOCK_IMAGE,
    "smokescreen": SMOKESCREEN_IMAGE,
    "squid": SQUID_IMAGE,
    "dnsfixture": DNSFIXTURE_IMAGE,
}


def prepare_image(backend: Backend, name: str, rebuild: bool = False) -> None:
    """Build `name`'s image from its Dockerfile unless it is already here.

    One path for every service, including Pipelock — which used to be
    pulled rather than built, and so needed its own setup branch, its own
    pin kind and its own way of being unpinned.
    """
    tag = IMAGES[name]
    if backend.image_present(tag) and not rebuild:
        print(f"{name}: image {tag} already built")
        return
    context = paths.image_dir() / name
    print(f"{name}: building {tag} from {context.name}/Dockerfile")
    backend.build(tag=tag, dockerfile=context / "Dockerfile", context=context)
    print(f"{name}: built {tag}")
