"""Endpoint-specific service names and discovery across IPL workspaces."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, replace

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import ENGINES
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.net import validate_endpoint
from internet_proxy_locally.spec import ServiceSpec

LABEL = "io.internet-proxy-locally."
Endpoint = tuple[str, int]


def workspace_id() -> str:
    return hashlib.sha256(str(paths.workspace_root().resolve()).encode()).hexdigest()[
        :16
    ]


def endpoint_key(binding: Endpoint) -> str:
    host, port = validate_endpoint(*binding)
    address = ipaddress.ip_address(host)
    token = "ipv6-" + address.packed.hex() if address.version == 6 else host
    return f"{token}-{port}"


def instance_spec(engine: str, binding: Endpoint) -> ServiceSpec:
    spec = ServiceSpec.load(engine)
    return replace(
        spec, container_name=f"{spec.container_name}-{endpoint_key(binding)}"
    )


@dataclass(frozen=True)
class Instance:
    name: str
    engine: str
    binding: Endpoint | None
    workspace: str
    role: str
    state: str


def discover_instances(
    backend: Backend, *, running_only: bool = True
) -> list[Instance]:
    """Identify managed proxy containers using labels and actual publications.

    Inspect can return absent if a container disappears during enumeration.
    Legacy containers identify their engine by the established fixed name.
    """
    instances: list[Instance] = []
    for name in backend.container_names():
        labels = backend.container_labels(name)
        if labels.get(LABEL + "managed") != "true":
            continue
        engine = labels.get(LABEL + "engine", "")
        if not engine:
            engine = next(
                (
                    e
                    for e in ENGINES
                    if name == ServiceSpec.load(e).container_name
                    or name.startswith(ServiceSpec.load(e).container_name + "-")
                ),
                "",
            )
        workspace = labels.get(LABEL + "workspace", "")
        if engine not in ENGINES or not workspace:
            continue
        state = backend.container_state(name)
        if state == "absent" or (running_only and state != "running"):
            continue
        bindings: list[Endpoint] = []
        for host, port, internal in backend.published_ports(name):
            if internal != ServiceSpec.load(engine).internal_port:
                continue
            try:
                binding = validate_endpoint(host, port)
            except ValueError:
                continue
            if binding not in bindings:
                bindings.append(binding)
        if backend.container_state(name) != state:
            continue
        for binding in bindings or [None]:
            instances.append(
                Instance(
                    name,
                    engine,
                    binding,
                    workspace,
                    labels.get(LABEL + "role", "unknown"),
                    state,
                )
            )
    return instances


def selected_spec(backend: Backend, engine: str, binding: Endpoint) -> ServiceSpec:
    """Prefer the new name, falling back to a matching owned legacy container."""
    spec = instance_spec(engine, binding)
    if backend.container_state(spec.container_name) != "absent":
        labels = backend.container_labels(spec.container_name)
        if (
            labels.get(LABEL + "managed") != "true"
            or labels.get(LABEL + "workspace") != workspace_id()
        ):
            raise Fail(
                f"container {spec.container_name} belongs to another workspace or service"
            )
        return spec
    return matching_legacy_spec(backend, engine, binding) or spec


def matching_legacy_spec(
    backend: Backend, engine: str, binding: Endpoint
) -> ServiceSpec | None:
    legacy = ServiceSpec.load(engine)
    labels = backend.container_labels(legacy.container_name)
    if (
        labels.get(LABEL + "managed") == "true"
        and labels.get(LABEL + "workspace") == workspace_id()
    ):
        for host, port, internal in backend.published_ports(legacy.container_name):
            try:
                actual = validate_endpoint(host, port)
            except ValueError:
                continue
            if actual == binding and internal == legacy.internal_port:
                return legacy
    return None


def selected_container_names(backend: Backend, binding: Endpoint) -> list[str]:
    """Cleanup targets, including a matching legacy lab's private resources."""
    names = [instance_spec(engine, binding).container_name for engine in ENGINES]
    for engine in ENGINES:
        legacy = matching_legacy_spec(backend, engine, binding)
        if legacy is not None:
            names.append(legacy.container_name)
            if (
                backend.container_labels(legacy.container_name).get(LABEL + "role")
                == "lab"
            ):
                names.append(ServiceSpec.load("dnsfixture").container_name)
    return list(dict.fromkeys(names))
