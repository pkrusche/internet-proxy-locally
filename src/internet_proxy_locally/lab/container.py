"""The DNS fixture container: a resolver that lies, on purpose.

It answers the fixture names with the addresses `fixtures.toml` describes —
private ones, rebinding ones, a PTR claiming an allowlisted host — so that
`dns-mixed-answers`, `dns-rebinding` and `ptr-allowlist` are testing an
engine against a hostile resolver rather than against nothing.

That is also why it must never outlive the run that started it, and why the
operational lane sweeps its container — by the name in `spec.SERVICES`,
which it can read without knowing anything else about this module.
"""

from __future__ import annotations

from internet_proxy_locally import net
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import DNS_FIXTURE, HEALTH_WAIT_SECONDS
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lifecycle import ownership_labels, remove_owned
from internet_proxy_locally.spec import ServiceSpec


def fixture_spec() -> ServiceSpec:
    """The DNS fixture service.

    data/lab/fixtures.toml is the source of truth for the rebinding zone,
    the PTR claim and the public address, and the container gets them the
    same way it gets the records: rendered into lab/config/ and bind-mounted
    (`extra_config_file` here, `lab.render._render_fixture_env()`). They
    used to be folded into `[build]` and baked in as Dockerfile ARGs, which
    made them a property of the image rather than of the run — so an image
    built before an edit to fixtures.toml went on serving the old values.
    """
    return ServiceSpec.load(DNS_FIXTURE)


def start_dns_fixture(backend: Backend) -> str:
    """Start the dnsmasq fixture container and return its address.

    No host port is published: the fixture is reachable from the engine
    container and from nothing else.
    """
    spec = fixture_spec()
    image = spec.image
    if not backend.image_present(image):
        raise Fail(
            f"the DNS fixture image {image} is not built — run `ipl-lab setup`.\n"
            "`ipl-lab check` needs it to serve the mixed-answer records "
            "(docs/lab.md)."
        )
    remove_owned(backend, spec.container_name)
    backend.run_detached(
        name=spec.container_name,
        image=image,
        internal_port=spec.internal_port,
        mounts=spec.mounts(),
        labels=ownership_labels("lab-fixture"),
    )

    def addressed():
        """The fixture's address, "" if it died, None while still starting."""
        address = backend.container_ip(spec.container_name)
        if address:
            return address
        return None if backend.container_state(spec.container_name) == "running" else ""

    address = net.wait_until(addressed, HEALTH_WAIT_SECONDS)
    if address:
        return address
    logs = backend.tail_logs(spec.container_name)
    try:
        remove_owned(backend, spec.container_name)
    except Fail as cleanup:
        raise Fail(
            f"the DNS fixture did not report an address; cleanup failed: {cleanup}\n"
            f"--- bounded logs ---\n{logs}"
        ) from cleanup
    raise Fail(
        f"the DNS fixture container did not report an address\n"
        f"--- bounded logs ---\n{logs}"
    )
