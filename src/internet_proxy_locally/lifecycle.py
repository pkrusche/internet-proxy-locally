"""Starting, finding and sweeping the containers this repository owns.

`start_engine` is shared by both lanes: the operational one starts an
engine on the shipped policy, the lab one starts the same engine on the
test policy with the DNS fixture attached, and they differ only in
arguments. That is deliberate — an engine that starts differently under
test is an engine the test does not describe.
"""

from __future__ import annotations

import sys
from pathlib import Path

from internet_proxy_locally import net
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import (
    ENGINES,
    FIXTURE_CONTAINER,
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
    """
    names = [spec.container_name for spec in all_specs()]
    if include_fixture:
        names.append(FIXTURE_CONTAINER)
    return names


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
) -> None:
    """Recreate one engine container on `config_path` and health-check it.

    Shared by `ipl up` and `ipl-lab up`, which differ only in which
    policy they mount and whether a DNS fixture is in the picture. Keeping
    the recreate/publish/health sequence in one place is what stops the two
    lanes from drifting into two different startup contracts.

    The DNS fixture is swept along with the engines, so a stale resolver
    can never outlive the engine pointed at it. `keep_fixture` is the one
    exception: ipl-lab starts the fixture first — it has to, the engine
    needs its address for `--dns` — so sweeping it here would delete the
    resolver the engine is about to be pointed at.
    """
    engine = spec.engine
    host, port = endpoint()
    image = spec.image
    if not backend.image_present(image):
        raise Fail(f"image {image} not built yet — run `ipl --engine {engine} setup`")

    # Recreate: remove every container owned by this repository first —
    # every engine publishes the same endpoint, so they cannot coexist.
    # The DNS fixture goes too, even from the operational lane: a stale one
    # must never be left running alongside a real policy.
    for name in owned_containers(include_fixture=not keep_fixture):
        if backend.remove_container(name):
            print(f"removed existing container {name}")

    if port_listening(host, port):
        raise Fail(
            f"{host}:{port} is already in use by something this repository does not own — "
            "refusing to start (choose down the other service or free the port)"
        )

    print(f"starting {engine} ({image}) on http://{host}:{port}")
    backend.run_detached(
        name=spec.container_name,
        image=image,
        publish_host=host,
        publish_port=port,
        internal_port=spec.internal_port,
        mounts=spec.mounts(config_path),
        dns=dns,
    )

    def settled():
        """A verdict, or None while the engine is still coming up."""
        if port_listening(host, port):
            healthy, detail, retryable = probe_proxy(host, port)
            # A retryable failure is one the engine may still grow out of;
            # anything else is the answer, healthy or not.
            if healthy or not retryable:
                return healthy, detail
        if backend.container_state(spec.container_name) != "running":
            return False, "container exited during startup"
        return None

    healthy, detail = net.wait_until(settled, HEALTH_WAIT_SECONDS) or (
        False,
        "timed out waiting for the proxy to listen",
    )
    if not healthy:
        logs = backend.tail_logs(spec.container_name)
        raise Fail(
            f"post-start health check failed: {detail}\n"
            f"--- last container logs ---\n{logs}\n"
            f"(the container is left in place for debugging; `ipl down` removes it)"
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
    return [
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
        # Recorded in the JSON envelope so a result file states which
        # build it measured; `report` reads it back into the
        # conditions table in docs/findings.md.
        "--image",
        spec.image,
    ]
