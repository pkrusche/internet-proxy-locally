"""Starting, finding and sweeping the containers this repository owns."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

from internet_proxy_locally import ca, net, paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import (
    DNS_FIXTURE,
    ENGINES,
    FIXTURE_NETWORK_NAME,
    FIXTURE_PRIVATE_NETWORK_NAME,
    HEALTH_WAIT_SECONDS,
)
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.instances import (
    LABEL,
    Endpoint,
    instance_spec,
    selected_container_names,
    selected_spec,
    workspace_id,
)
from internet_proxy_locally.net import (
    endpoint,
    endpoint_text,
    port_listening,
    probe_address,
    probe_proxy,
    validate_endpoint,
)
from internet_proxy_locally.spec import ServiceSpec


def all_specs() -> list[ServiceSpec]:
    return [ServiceSpec.load(engine) for engine in ENGINES]


def owned_containers(include_fixture: bool = True) -> list[str]:
    """Fixed lab/legacy names; operational endpoint cleanup is separate.

    Lab startup preserves the fixture it has just started. Actual removal
    always checks ownership labels, including the workspace identifier.
    """
    names = [spec.container_name for spec in all_specs()]
    if include_fixture:
        names.append(ServiceSpec.load(DNS_FIXTURE).container_name)
    return names


def ownership_labels(
    role: str = "operational", tls_interception: bool = False
) -> dict[str, str]:
    return {
        "io.internet-proxy-locally.managed": "true",
        "io.internet-proxy-locally.workspace": workspace_id(),
        "io.internet-proxy-locally.role": role,
        "io.internet-proxy-locally.tls-interception": "true"
        if tls_interception
        else "false",
    }


def remove_owned(backend: Backend, name: str) -> bool:
    state = backend.container_state(name)
    if state == "absent":
        return False
    labels = backend.container_labels(name)
    expected = ownership_labels()
    if (
        labels.get("io.internet-proxy-locally.managed") != "true"
        or labels.get("io.internet-proxy-locally.workspace")
        != expected["io.internet-proxy-locally.workspace"]
    ):
        raise Fail(
            f"refusing to remove foreign container {name}: ownership labels differ"
        )
    return backend.remove_container(name)


def running_engine(backend: Backend, binding: Endpoint | None = None) -> str | None:
    for spec in all_specs():
        if binding is not None:
            spec = selected_spec(backend, spec.engine, binding)
        if backend.container_state(spec.container_name) == "running":
            return spec.engine
    return None


def start_engine(
    backend: Backend,
    spec: ServiceSpec,
    config_path: Path,
    dns: str = "",
    keep_fixture: bool = False,
    tls_interception: bool = False,
    binding: Endpoint | None = None,
) -> None:
    """Recreate one engine container on `config_path` and health-check it."""
    if keep_fixture and backend.name != "docker":
        raise Fail("the lab requires Docker")
    engine = spec.engine
    host, port = binding if binding is not None else endpoint()
    if binding is not None:
        spec = replace(
            spec, container_name=instance_spec(engine, binding).container_name
        )
    connect_host = probe_address(host)
    image = spec.image
    if not backend.image_present(image):
        raise Fail(f"image {image} not built yet — run `ipl --engine {engine} setup`")

    mounts = spec.mounts(config_path)
    if tls_interception:
        if not spec.supports_tls_interception:
            raise Fail(
                f"{engine} does not support TLS interception "
                "(omit --tls-interception or switch to an engine that supports it)"
            )
        ca.validate_ca()
        mounts += spec.ca_mounts()

    if keep_fixture:
        mounts += [
            (paths.fixture_tls_dir() / "ca.pem", "/fixture/ca.pem"),
        ]

    # Recreate only this endpoint; fixed-name lab cleanup stays in its lane.
    if binding is None:
        names = owned_containers(include_fixture=not keep_fixture)
    else:
        names = selected_container_names(backend, binding)
    for name in dict.fromkeys(names):
        if remove_owned(backend, name):
            print(f"removed existing container {name}")

    if not keep_fixture and ServiceSpec.load(DNS_FIXTURE).container_name in names:
        backend.remove_lab_network(FIXTURE_NETWORK_NAME, ownership_labels())
        backend.remove_lab_network(FIXTURE_PRIVATE_NETWORK_NAME, ownership_labels())

    if port_listening(connect_host, port):
        raise Fail(
            f"{host}:{port} is already in use by something this repository does not own — "
            "refusing to start (shut down the other service or free the port)"
        )

    print(f"starting {engine} ({image}) on http://{endpoint_text(host, port)}")
    labels = ownership_labels(
        "lab" if keep_fixture else "operational", tls_interception=tls_interception
    )
    labels.update(
        {LABEL + "engine": engine, LABEL + "ip": host, LABEL + "port": str(port)}
    )
    backend.run_detached(
        name=spec.container_name,
        image=image,
        internal_port=spec.internal_port,
        mounts=mounts,
        publish=(host, port),
        dns=dns,
        lab_network=FIXTURE_NETWORK_NAME if keep_fixture else "",
        environment={"SSL_CERT_FILE": "/fixture/ca.pem"} if keep_fixture else None,
        user=spec.tls_startup_user if tls_interception else "",
        labels=labels,
    )

    def settled():
        """A verdict, or None while the engine is still coming up."""
        if port_listening(connect_host, port):
            healthy, detail, retryable = probe_proxy(connect_host, port)
            if healthy or not retryable:
                return healthy, detail
        if backend.container_state(spec.container_name) != "running":
            return False, "container exited during startup"
        return None

    healthy, detail = net.wait_until(settled, HEALTH_WAIT_SECONDS) or (
        False,
        "timed out waiting for the proxy to listen",
    )
    expected_binding = (host, port, spec.internal_port)
    actual_bindings = []
    for published_host, published_port, internal_port in backend.published_ports(
        spec.container_name
    ):
        try:
            canonical_host, canonical_port = validate_endpoint(
                published_host, published_port
            )
        except ValueError:
            continue
        actual_bindings.append((canonical_host, canonical_port, internal_port))
    if healthy and expected_binding not in actual_bindings:
        healthy = False
        detail = f"runtime did not honor requested publication {expected_binding}"
    if not healthy:
        logs = backend.tail_logs(spec.container_name)
        try:
            remove_owned(backend, spec.container_name)
        except Fail as cleanup:
            raise Fail(
                f"post-start health check failed: {detail}; cleanup also failed: {cleanup}\n"
                f"--- bounded container logs ---\n{logs}"
            ) from cleanup
        raise Fail(
            f"post-start health check failed: {detail}; created container removed\n"
            f"--- bounded container logs ---\n{logs}"
        )
    print(f"healthy: {detail}")


def egress_command(
    backend: Backend, engine: str | None, cli: str, binding: Endpoint | None = None
) -> list[str]:
    """The `checks.egress` invocation for whichever engine is running.

    Shared by `ipl check` and `ipl-lab check`, which differ only in
    the group they ask for and whether the DNS fixture is in the picture.
    Resolving "which engine is running" in one place is what stops the two
    lanes from disagreeing about what they just measured. `cli` names the
    calling entry point so each lane's errors quote the command that fixes
    them.
    """
    active = running_engine(backend, binding)
    if not active:
        raise Fail(f"no engine is running — `{cli} up` first")
    if engine and engine != active:
        raise Fail(
            f"--engine {engine} requested but {active} is running; "
            f"`{cli} --engine {engine} up` first"
        )
    spec = ServiceSpec.load(active)
    host, port = binding if binding is not None else endpoint()
    if binding is not None:
        spec = selected_spec(backend, active, binding)
    cmd = [
        sys.executable,
        "-m",
        "internet_proxy_locally.checks.egress",
        "--proxy",
        f"http://{endpoint_text(probe_address(host), port)}",
        "--engine",
        active,
        "--backend-bin",
        backend.bin,
        "--container",
        spec.container_name,
        "--image",
        spec.image,
    ]
    labels = backend.container_labels(spec.container_name)
    if labels.get("io.internet-proxy-locally.tls-interception") == "true":
        cmd.append("--tls-interception")
    return cmd
