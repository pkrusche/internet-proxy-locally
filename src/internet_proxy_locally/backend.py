"""The container runtime, behind one interface.

Docker and Apple `container` differ in argument spelling and, more
awkwardly, in the JSON they report state through — a container address is
under `NetworkSettings` in one and `status.networks[]` as a CIDR in the
other. Every one of those differences is absorbed here, so nothing above
this module has a runtime-shaped branch in it.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path

from internet_proxy_locally.constants import BACKENDS
from internet_proxy_locally.errors import Fail

COMMAND_TIMEOUT = 30
BUILD_TIMEOUT = 1800


class Backend:
    """Thin wrapper over the docker / Apple `container` CLIs.

    Only behavior available in both CLIs is used; anything backend-specific
    is isolated here so the security semantics stay identical (docs/lab.md).
    """

    def __init__(self, name: str):
        if name not in BACKENDS:
            raise Fail(f"unknown backend: {name}")
        self.name = name
        self.bin = name

    # -- low-level ----------------------------------------------------------

    def _run(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
        timeout: float = COMMAND_TIMEOUT,
    ) -> subprocess.CompletedProcess:
        cmd = [self.bin, *args]
        try:
            proc = subprocess.run(
                cmd, capture_output=capture, text=True, check=False, timeout=timeout
            )
        except subprocess.TimeoutExpired as exc:
            raise Fail(f"`{' '.join(cmd)}` timed out after {timeout:g}s") from exc
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise Fail(f"`{' '.join(cmd)}` failed:\n{detail}")
        return proc

    def available(self) -> bool:
        return shutil.which(self.bin) is not None

    def _inspect_entry(self, *args: str) -> dict:
        """The one object an `inspect` returns, or `{}` when there is none.

        Every reader below wants the same thing out of `inspect`: run it,
        tolerate a non-zero exit (the thing does not exist), parse JSON,
        and unwrap the single-element list both runtimes wrap it in. Doing
        that once means the guards cannot differ between readers — they
        did, and the copy in `container_state` was the one missing them.
        """
        proc = self._run(*args, check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            # Both supported CLIs use an empty diagnostic in some versions
            # for a genuinely absent object.
            missing = (
                not detail
                or "no such" in detail.lower()
                or "not found" in detail.lower()
            )
            if missing:
                return {}
            raise Fail(
                f"runtime inspect failed for {' '.join(args)}: {detail or 'unknown error'}"
            )
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise Fail(f"runtime returned malformed JSON for {' '.join(args)}")
        entry = (info[0] if isinstance(info, list) and info else info) or {}
        return entry if isinstance(entry, dict) else {}

    # -- containers ---------------------------------------------------------

    def container_state(self, name: str) -> str:
        """Return 'running', 'stopped', or 'absent'."""
        entry = self._inspect_entry("inspect", name)
        if not entry:
            return "absent"
        # docker:          {"State": {"Status": "running"}}
        # Apple container: {"status": {"state": "running", ...}}
        #                  (older shapes use a plain string for either key)
        status = ""
        for key in ("State", "status"):
            value = entry.get(key)
            if isinstance(value, str):
                status = value
            elif isinstance(value, dict):
                status = value.get("Status") or value.get("state") or ""
            if status:
                break
        return "running" if str(status).lower() == "running" else "stopped"

    def container_ip(self, name: str) -> str:
        """The container's address on the backend's own network.

        Only used to point an engine's resolver at the DNS fixture, which is
        why no host port is published for it. Docker reports it under
        `NetworkSettings`; Apple `container` under `status.networks[]` as a
        CIDR that has to be trimmed.
        """
        entry = self._inspect_entry("inspect", name)
        settings = entry.get("NetworkSettings")
        if isinstance(settings, dict):
            address = settings.get("IPAddress")
            if isinstance(address, str) and address:
                return address
            for network in (settings.get("Networks") or {}).values():
                address = (network or {}).get("IPAddress")
                if isinstance(address, str) and address:
                    return address
        networks = (entry.get("status") or {}).get("networks")
        if isinstance(networks, list):
            for network in networks:
                address = (network or {}).get("ipv4Address")
                if isinstance(address, str) and address:
                    return address.split("/", 1)[0]
        return ""

    def published_ports(self, name: str) -> list[tuple[str, int, int]]:
        """(host address, host port, container port) for each published port.

        The endpoint is supposed to be loopback-only, and `--publish
        ip:host:container` is the whole of that guarantee — a release that
        quietly ignored the address half would widen it to every interface
        with no error and no visible change. This reads the binding back out
        of the runtime so that ipl-verify loopback can assert it
        rather than trust it (docs/lab.md).

        Docker:          HostConfig.PortBindings {"8888/tcp": [{HostIp, HostPort}]}
        Apple container: configuration.publishedPorts [{hostAddress, hostPort,
                         containerPort}]
        """
        entry = self._inspect_entry("inspect", name)
        bindings: list[tuple[str, int, int]] = []
        published = (entry.get("configuration") or {}).get("publishedPorts")
        if isinstance(published, list):
            for item in published:
                if not isinstance(item, dict):
                    continue
                try:
                    bindings.append(
                        (
                            str(item.get("hostAddress", "")),
                            int(item["hostPort"]),
                            int(item["containerPort"]),
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    continue
        port_bindings = (entry.get("HostConfig") or {}).get("PortBindings") or {}
        if isinstance(port_bindings, dict):
            for spec, targets in port_bindings.items():
                container_port = int(str(spec).split("/", 1)[0] or 0)
                for target in targets or []:
                    if not isinstance(target, dict):
                        continue
                    try:
                        bindings.append(
                            (
                                str(target.get("HostIp", "")),
                                int(target["HostPort"]),
                                container_port,
                            )
                        )
                    except (KeyError, TypeError, ValueError):
                        continue
        return bindings

    def container_labels(self, name: str) -> dict[str, str]:
        entry = self._inspect_entry("inspect", name)
        candidates = [
            (entry.get("Config") or {}).get("Labels"),
            (entry.get("configuration") or {}).get("labels"),
        ]
        for value in candidates:
            if isinstance(value, dict):
                return {str(k): str(v) for k, v in value.items()}
        return {}

    def remove_container(self, name: str) -> bool:
        """Remove a container if present; returns True if something was removed."""
        if self.container_state(name) == "absent":
            return False
        if self.name == "docker":
            self._run("rm", "-f", name)
        else:
            self._run("stop", name)
            self._run("rm", name)
        if self.container_state(name) != "absent":
            raise Fail(f"runtime reported success but container {name} still exists")
        return True

    def run_detached(
        self,
        *,
        name: str,
        image: str,
        internal_port: int,
        mounts: list[tuple[Path, str]],
        # (host_ip, host_port), or None for no host port at all. The DNS
        # fixture is the latter: it is reachable from the engine container
        # and from nothing else, which is why this is one argument rather
        # than a host/port pair plus a flag saying to ignore them.
        publish: tuple[str, int] | None = None,
        dns: str = "",
        labels: dict[str, str] | None = None,
    ) -> None:
        cmd: list[str] = ["run", "--detach", "--name", name]
        for key, value in sorted((labels or {}).items()):
            cmd += ["--label", f"{key}={value}"]
        if publish is not None:
            publish_host, publish_port = publish
            cmd += ["--publish", f"{publish_host}:{publish_port}:{internal_port}"]
        if dns:
            # Both CLIs spell this `--dns <ip>`. Docker also has --add-host,
            # which would be a tidier way to inject a single record, but
            # Apple `container` has no equivalent and a hosts entry cannot
            # carry a multi-address answer anyway (docs/lab.md).
            cmd += ["--dns", dns]
        for src, dst in mounts:
            cmd += ["--volume", f"{src}:{dst}:ro"]
        # No trailing arguments: how a service is launched is its
        # image's business, and every one of them says so in its
        # Dockerfile's ENTRYPOINT/CMD (data/images/*/Dockerfile).
        cmd.append(image)
        self._run(*cmd)

    def logs(self, name: str, follow: bool) -> int:
        cmd = [self.bin, "logs"]
        if follow:
            cmd.append("--follow")
        cmd.append(name)
        return subprocess.run(cmd, check=False).returncode

    def tail_logs(self, name: str, lines: int = 40) -> str:
        proc = self._run("logs", "--tail", str(lines), name, check=False)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
        return "\n".join(out[-lines:])

    # -- images -------------------------------------------------------------

    def _image(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        # `image <verb>` works for both docker and Apple `container`.
        return self._run("image", *args, check=check)

    def image_present(self, ref: str) -> bool:
        proc = self._image("inspect", ref, check=False)
        return proc.returncode == 0

    def image_size(self, ref: str) -> int:
        """On-disk size of a local image in bytes; 0 when it cannot be read.

        Reported by `ipl-verify resilience` rather than enforced —
        image size is one of the operational numbers the engine choice is
        weighed on, and it was never collected. Docker puts it at `Size`;
        Apple `container` reports the manifest's layer sizes instead, so
        the two are summed to something comparable rather than equal.
        """
        entry = self._inspect_entry("image", "inspect", ref)
        for key in ("Size", "size", "VirtualSize"):
            value = entry.get(key)
            if isinstance(value, (int, float)) and value > 0:
                return int(value)
        variants = entry.get("variants") or entry.get("manifests") or []
        total = 0
        for variant in variants if isinstance(variants, list) else []:
            for layer in (variant or {}).get("layers") or []:
                value = (layer or {}).get("size")
                if isinstance(value, (int, float)):
                    total += int(value)
        return total

    def build(self, *, tag: str, dockerfile: Path, context: Path) -> None:
        """Build one image. No `--build-arg`: a Dockerfile that took one
        would have a pin Python could get wrong."""
        self._run(
            "build",
            "--tag",
            tag,
            "--file",
            str(dockerfile),
            str(context),
            capture=False,
            timeout=BUILD_TIMEOUT,
        )


def detect_backend(override: str | None) -> Backend:
    if override:
        backend = Backend(override)
        if not backend.available():
            raise Fail(f"requested backend `{override}` is not installed")
        return backend
    candidates = (
        [Backend("container"), Backend("docker")]
        if platform.system() == "Darwin"
        else [Backend("docker"), Backend("container")]
    )
    for backend in candidates:
        if backend.available():
            return backend
    raise Fail("no container backend found: install Docker or Apple `container`")
