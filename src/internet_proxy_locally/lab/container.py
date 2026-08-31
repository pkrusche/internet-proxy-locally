"""The DNS fixture container: a resolver that lies, on purpose.

It answers the fixture names with the addresses `fixtures.toml` describes —
private ones, rebinding ones, a PTR claiming an allowlisted host — so that
`dns-mixed-answers`, `dns-rebinding` and `ptr-allowlist` are testing an
engine against a hostile resolver rather than against nothing.

That is also why it must never outlive the run that started it, and why
the operational lane knows its container name (`FIXTURE_CONTAINER`) even
though it knows nothing else about this module.
"""

from __future__ import annotations

from internet_proxy_locally import net, paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import DNS_FIXTURE, HEALTH_WAIT_SECONDS
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lab.fixtures import LabConfig, load_lab_config
from internet_proxy_locally.spec import ServiceSpec


def fixture_spec(config: LabConfig | None = None) -> ServiceSpec:
    """The DNS fixture service, with what it serves folded into `[build]`.

    data/lab/fixtures.toml is the source of truth for the rebinding zone, the
    PTR claim and the public address. The container needs them too, and
    `ServiceSpec.build` is already passed through to the Dockerfile as
    uppercase ARGs — so they arrive there by construction instead of being
    restated as literals in data/lab/dnsfixture/rebind.py, where nothing outside
    the image could check them.
    """
    spec = ServiceSpec.load(DNS_FIXTURE, root=paths.lab_dir())
    fixture = (config or load_lab_config()).fixture
    spec.build.update(
        {
            "rebind_zone": fixture.rebind_zone,
            "ptr_address": fixture.ptr_address,
            "ptr_claims": fixture.ptr_claims,
            "public_answer": fixture.public_answer,
        }
    )
    return spec


def start_dns_fixture(backend: Backend) -> str:
    """Start the dnsmasq fixture container and return its address.

    No host port is published: the fixture is reachable from the engine
    container and from nothing else.
    """
    spec = fixture_spec()
    image = spec.run_image_ref()
    if not backend.image_present(image):
        raise Fail(
            f"the DNS fixture image {image} is not built — run `ipl-lab setup`.\n"
            "`ipl-lab check` needs it to serve the mixed-answer records "
            "(docs/lab.md)."
        )
    backend.remove_container(spec.container_name)
    backend.run_detached(
        name=spec.container_name,
        image=image,
        publish_host="",
        publish_port=0,
        internal_port=spec.internal_port,
        mounts=spec.mounts(),
        args=spec.args,
        publish=False,
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
    raise Fail(
        f"the DNS fixture container did not report an address\n"
        f"--- last container logs ---\n{logs}"
    )
