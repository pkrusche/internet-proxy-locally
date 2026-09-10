"""Build pinned service images; see docs/development.md for tag updates."""

from __future__ import annotations

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend

PIPELOCK_IMAGE = "internet-proxy-locally/pipelock:3.3.0"
# build1 adds the default CMD that loads the daemon config and egress ACL.
SMOKESCREEN_IMAGE = "internet-proxy-locally/smokescreen:131fba29ce1e-build1"
SQUID_IMAGE = "internet-proxy-locally/squid:6.12-r0-build1"
IRON_IMAGE = "internet-proxy-locally/iron:0.49.0-build1"
DNSFIXTURE_IMAGE = "internet-proxy-locally/dnsfixture:2.91-r1-build3"

IMAGES = {
    "pipelock": PIPELOCK_IMAGE,
    "smokescreen": SMOKESCREEN_IMAGE,
    "squid": SQUID_IMAGE,
    "iron": IRON_IMAGE,
    "dnsfixture": DNSFIXTURE_IMAGE,
}


def prepare_image(backend: Backend, name: str, rebuild: bool = False) -> None:
    """Build the service image unless its tag exists and rebuild is false."""
    tag = IMAGES[name]
    if backend.image_present(tag) and not rebuild:
        print(f"{name}: image {tag} already built")
        return
    context = paths.image_dir() / name
    print(f"{name}: building {tag} from {context.name}/Dockerfile")
    backend.build(tag=tag, dockerfile=context / "Dockerfile", context=context)
    print(f"{name}: built {tag}")
