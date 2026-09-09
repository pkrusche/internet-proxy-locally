"""Starting, finding and sweeping the containers this repository owns."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from internet_proxy_locally import ca, net, paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import (
    DNS_FIXTURE,
    ENGINES,
    FIXTURE_NETWORK_NAME,
    HEALTH_WAIT_SECONDS,
)
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.net import endpoint, port_listening, probe_proxy
from internet_proxy_locally.spec import ServiceSpec


def all_specs() -> list[ServiceSpec]:
    return [ServiceSpec.load(engine) for engine in ENGINES]


def owned_containers(include_fixture: bool = True) -> list[str]:
    """Every container name this repository is allowed to remove.

    One definition, because both lanes sweep this list and a container
    added to one copy and not the other would survive a `down`. The DNS
    fixture is in it even from the operational lane: a stale resolver must
    never be left running alongside a real policy. `include_fixture=False`
    is for `ipl-lab up`, which starts the fixture *before* the engine —
    it has to, the engine needs its address for `--dns`.

    The fixture's name is read from `spec.SERVICES` rather than restated:
    `spec` is shared, so naming it here is a lookup and not a lab import.
    """
    names = [spec.container_name for spec in all_specs()]
    if include_fixture:
        names.append(ServiceSpec.load(DNS_FIXTURE).container_name)
    return names


def ownership_labels(
    role: str = "operational", tls_interception: bool = False
) -> dict[str, str]:
    root = str(Path.cwd().resolve()).encode()
    return {
        "io.internet-proxy-locally.managed": "true",
        "io.internet-proxy-locally.workspace": hashlib.sha256(root).hexdigest()[:16],
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


def running_engine(backend: Backend) -> str | None:
    for spec in all_specs():
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
) -> None:
    """Recreate one engine container on `config_path` and health-check it."""
    if keep_fixture and backend.name != "docker":
        raise Fail("the lab requires Docker")
    engine = spec.engine
    host, port = endpoint()
    image = spec.image
    if not backend.image_present(image):
        raise Fail(f"image {image} not built yet — run `ipl --engine {engine} setup`")

    mounts = spec.mounts(config_path)
    if tls_interception:
        if not spec.supports_tls_interception:
            raise Fail(
                f"{engine} does not support TLS interception "
                "(pipelock and squid do; omit --tls-interception or switch engine)"
            )
        ca.validate_ca()
        mounts += spec.ca_mounts()

    if keep_fixture:
        mounts += [
            (paths.fixture_tls_dir() / "ca.pem", "/fixture/ca.pem"),
        ]

    # Engines share one endpoint; also remove stale fixtures from operational runs.
    for name in owned_containers(include_fixture=not keep_fixture):
        if remove_owned(backend, name):
            print(f"removed existing container {name}")

    if not keep_fixture:
        backend.remove_lab_network(FIXTURE_NETWORK_NAME, ownership_labels())

    if port_listening(host, port):
        raise Fail(
            f"{host}:{port} is already in use by something this repository does not own — "
            "refusing to start (choose down the other service or free the port)"
        )

    print(f"starting {engine} ({image}) on http://{host}:{port}")
    backend.run_detached(
        name=spec.container_name,
        image=image,
        internal_port=spec.internal_port,
        mounts=mounts,
        publish=(host, port),
        dns=dns,
        lab_network=FIXTURE_NETWORK_NAME if keep_fixture else "",
        environment={"SSL_CERT_FILE": "/fixture/ca.pem"} if keep_fixture else None,
        labels=ownership_labels(
            "lab" if keep_fixture else "operational", tls_interception=tls_interception
        ),
    )

    def settled():
        """A verdict, or None while the engine is still coming up."""
        if port_listening(host, port):
            healthy, detail, retryable = probe_proxy(host, port)
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
    if healthy and expected_binding not in backend.published_ports(spec.container_name):
        healthy = False
        detail = f"runtime did not honor loopback publication {expected_binding}"
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


def egress_command(backend: Backend, engine: str | None, cli: str) -> list[str]:
    """The `checks.egress` invocation for whichever engine is running.

    Shared by `ipl check` and `ipl-lab check`, which differ only in
    the group they ask for and whether the DNS fixture is in the picture.
    Resolving "which engine is running" in one place is what stops the two
    lanes from disagreeing about what they just measured. `cli` names the
    calling entry point so each lane's errors quote the command that fixes
    them.
    """
    active = running_engine(backend)
    if not active:
        raise Fail(f"no engine is running — `{cli} up` first")
    if engine and engine != active:
        raise Fail(
            f"--engine {engine} requested but {active} is running; "
            f"`{cli} --engine {engine} up` first"
        )
    spec = ServiceSpec.load(active)
    host, port = endpoint()
    cmd = [
        sys.executable,
        "-m",
        "internet_proxy_locally.checks.egress",
        "--proxy",
        f"http://{host}:{port}",
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
