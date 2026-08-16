#!/usr/bin/env python3
"""internet-proxy-locally — local containerized Internet filtering proxy.

One CLI for both Docker and Apple `container`. Exposes a single stable
host endpoint (http://127.0.0.1:18080) backed by either Pipelock or
Smokescreen, with a default-deny destination policy.

Stdlib only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

DEFAULT_ENDPOINT = "127.0.0.1:18080"
ENGINES = ("pipelock", "smokescreen")
DEFAULT_ENGINE = "pipelock"
BACKENDS = ("docker", "container")

HEALTH_WAIT_SECONDS = 15.0


class Fail(Exception):
    """Fatal, user-facing error."""


def endpoint() -> tuple[str, int]:
    """Host endpoint; IPL_ENDPOINT override exists for the test suite only."""
    raw = os.environ.get("IPL_ENDPOINT", DEFAULT_ENDPOINT)
    host, _, port = raw.rpartition(":")
    return host, int(port)


# ---------------------------------------------------------------------------
# Service specs (services/*.toml)
# ---------------------------------------------------------------------------


@dataclass
class ServiceSpec:
    engine: str
    image_repository: str
    image_tag: str = ""
    image_digest: str = ""
    source_repo: str = ""
    source_ref: str = ""
    go_image: str = ""
    runtime_image: str = ""
    container_name: str = ""
    internal_port: int = 0
    config_file: str = ""
    test_config_file: str = ""
    config_mount: str = ""
    args: list[str] = field(default_factory=list)

    @property
    def toml_path(self) -> Path:
        return REPO_ROOT / "services" / f"{self.engine}.toml"

    @classmethod
    def load(cls, engine: str) -> "ServiceSpec":
        path = REPO_ROOT / "services" / f"{engine}.toml"
        if not path.is_file():
            raise Fail(f"missing service definition: {path}")
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        image = data.get("image", {})
        source = data.get("source", {})
        build = data.get("build", {})
        container = data.get("container", {})
        spec = cls(
            engine=engine,
            image_repository=image.get("repository", ""),
            image_tag=image.get("tag", ""),
            image_digest=image.get("digest", ""),
            source_repo=source.get("repo", ""),
            source_ref=source.get("ref", ""),
            go_image=build.get("go_image", ""),
            runtime_image=build.get("runtime_image", ""),
            container_name=container.get("name", ""),
            internal_port=int(container.get("internal_port", 0)),
            config_file=container.get("config_file", ""),
            test_config_file=container.get("test_config_file", ""),
            config_mount=container.get("config_mount", ""),
            args=list(container.get("args", [])),
        )
        if not spec.image_repository or not spec.container_name or not spec.internal_port:
            raise Fail(f"{path}: image.repository, container.name and container.internal_port are required")
        if spec.image_tag == "latest":
            raise Fail(f"{path}: refusing to use a 'latest' tag; pin a release")
        if "--unsafe-allow-private-ranges" in spec.args or "--danger-allow-access-to-private-ranges" in spec.args:
            raise Fail(f"{path}: private-range blocking must never be disabled")
        return spec

    def run_image_ref(self) -> str:
        """Immutable image reference for `up`; fails closed when unpinned."""
        if self.engine == "pipelock":
            if not self.image_digest:
                raise Fail(
                    "pipelock image digest is not pinned in services/pipelock.toml.\n"
                    "Run `./run.py pin pipelock` (needs network), review, and commit."
                )
            return f"{self.image_repository}@{self.image_digest}"
        if not self.source_ref:
            raise Fail(
                "smokescreen source ref is not pinned in services/smokescreen.toml.\n"
                "Run `./run.py pin smokescreen` (needs network), review, commit, then `./run.py setup`."
            )
        return f"{self.image_repository}:{self.source_ref[:12]}"

    def config_path(self, test_policy: bool) -> Path:
        rel = self.test_config_file if test_policy else self.config_file
        if not rel:
            raise Fail(f"services/{self.engine}.toml: missing config_file")
        path = REPO_ROOT / rel
        if not path.is_file():
            raise Fail(f"missing config file: {path}")
        return path


# ---------------------------------------------------------------------------
# Container backends
# ---------------------------------------------------------------------------


class Backend:
    """Thin wrapper over the docker / Apple `container` CLIs.

    Only behavior available in both CLIs is used; anything backend-specific
    is isolated here so the security semantics stay identical (docs/backends.md).
    """

    def __init__(self, name: str):
        if name not in BACKENDS:
            raise Fail(f"unknown backend: {name}")
        self.name = name
        self.bin = name

    # -- low-level ----------------------------------------------------------

    def _run(self, *args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.bin, *args]
        proc = subprocess.run(cmd, capture_output=capture, text=True)
        if check and proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise Fail(f"`{' '.join(cmd)}` failed:\n{detail}")
        return proc

    def available(self) -> bool:
        return shutil.which(self.bin) is not None

    # -- containers ---------------------------------------------------------

    def container_state(self, name: str) -> str:
        """Return 'running', 'stopped', or 'absent'."""
        proc = self._run("inspect", name, check=False)
        if proc.returncode != 0:
            return "absent"
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return "absent"
        if not info:
            return "absent"
        entry = info[0] if isinstance(info, list) else info
        # docker: {"State": {"Status": "running"}}; Apple container: {"status": "running"}
        status = ""
        if isinstance(entry, dict):
            state = entry.get("State")
            if isinstance(state, dict):
                status = state.get("Status", "")
            elif isinstance(state, str):
                status = state
            else:
                status = entry.get("status", "")
        return "running" if status.lower() == "running" else "stopped"

    def remove_container(self, name: str) -> bool:
        """Remove a container if present; returns True if something was removed."""
        if self.container_state(name) == "absent":
            return False
        if self.name == "docker":
            self._run("rm", "-f", name, check=False)
        else:
            self._run("stop", name, check=False)
            self._run("rm", name, check=False)
        return True

    def run_detached(
        self,
        *,
        name: str,
        image: str,
        publish_host: str,
        publish_port: int,
        internal_port: int,
        mounts: list[tuple[Path, str]],
        args: list[str],
    ) -> None:
        cmd: list[str] = ["run", "--detach", "--name", name,
                          "--publish", f"{publish_host}:{publish_port}:{internal_port}"]
        for src, dst in mounts:
            cmd += ["--volume", f"{src}:{dst}:ro"]
        cmd.append(image)
        cmd += args
        self._run(*cmd)

    def logs(self, name: str, follow: bool) -> int:
        cmd = [self.bin, "logs"]
        if follow:
            cmd.append("--follow")
        cmd.append(name)
        return subprocess.run(cmd).returncode

    def tail_logs(self, name: str, lines: int = 40) -> str:
        proc = self._run("logs", name, check=False)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
        return "\n".join(out[-lines:])

    # -- images -------------------------------------------------------------

    def _image(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        # `image <verb>` works for both docker and Apple `container`.
        return self._run("image", *args, check=check)

    def pull(self, ref: str) -> None:
        if self.name == "docker":
            self._run("pull", ref, capture=False)
        else:
            self._run("image", "pull", ref, capture=False)

    def image_present(self, ref: str) -> bool:
        proc = self._image("inspect", ref, check=False)
        return proc.returncode == 0

    def image_digest(self, ref: str) -> str:
        """Best-effort immutable digest lookup for a local image."""
        proc = self._image("inspect", ref, check=False)
        if proc.returncode != 0:
            return ""
        try:
            info = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return ""
        entry = (info[0] if isinstance(info, list) and info else info) or {}
        if isinstance(entry, dict):
            for key in ("RepoDigests",):
                digests = entry.get(key)
                if isinstance(digests, list) and digests:
                    return str(digests[0]).rpartition("@")[2]
            # Apple `container image inspect` exposes the manifest digest directly.
            for key in ("digest", "Digest"):
                if entry.get(key):
                    return str(entry[key])
        return ""

    def build(self, *, tag: str, dockerfile: Path, context: Path, build_args: dict[str, str]) -> None:
        cmd = ["build", "--tag", tag, "--file", str(dockerfile)]
        for key, value in build_args.items():
            cmd += ["--build-arg", f"{key}={value}"]
        cmd.append(str(context))
        self._run(*cmd, capture=False)


def detect_backend(override: str | None) -> Backend:
    if override:
        backend = Backend(override)
        if not backend.available():
            raise Fail(f"requested backend `{override}` is not installed")
        return backend
    candidates = [Backend("container"), Backend("docker")] if platform.system() == "Darwin" \
        else [Backend("docker"), Backend("container")]
    for backend in candidates:
        if backend.available():
            return backend
    raise Fail("no container backend found: install Docker or Apple `container`")


# ---------------------------------------------------------------------------
# Policy validation (lightweight, stdlib-only)
# ---------------------------------------------------------------------------


def _yaml_list(text: str, key: str) -> list[str]:
    """Extract a top-level-ish `key:` sequence of scalar items."""
    match = re.search(rf"^(\s*){re.escape(key)}:\s*$", text, re.MULTILINE)
    if not match:
        return []
    indent = len(match.group(1))
    items: list[str] = []
    for line in text[match.end():].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        this_indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped.startswith("- ") and this_indent > indent:
            items.append(stripped[2:].strip().strip('"').strip("'"))
        elif this_indent <= indent:
            break
    return items


def _yaml_block(text: str, key: str) -> str:
    match = re.search(rf"^(\s*){re.escape(key)}:\s*$", text, re.MULTILINE)
    if not match:
        return ""
    indent = len(match.group(1))
    lines: list[str] = []
    for line in text[match.end():].splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            if len(line) - len(line.lstrip()) <= indent:
                break
        lines.append(line)
    return "\n".join(lines)


def _require(cond: bool, path: Path, message: str, problems: list[str]) -> None:
    if not cond:
        problems.append(f"{path}: {message}")


def validate_policy_file(engine: str, path: Path) -> list[str]:
    """Return a list of human-readable policy problems (empty = OK)."""
    text = path.read_text()
    problems: list[str] = []
    if engine == "pipelock":
        _require(re.search(r"^mode:\s*strict\b", text, re.M) is not None, path,
                 "must set `mode: strict`", problems)
        _require(re.search(r"^enforce:\s*true\b", text, re.M) is not None, path,
                 "must set `enforce: true`", problems)
        fp = _yaml_block(text, "forward_proxy")
        _require(bool(re.search(r"^\s*enabled:\s*true\b", fp, re.M)), path,
                 "forward_proxy.enabled must be true", problems)
        _require(bool(re.search(r"^\s*sni_verification:\s*true\b", fp, re.M)), path,
                 "forward_proxy.sni_verification must be true", problems)
        _require(bool(re.search(r"^\s*sni_require_tls:\s*true\b", fp, re.M)), path,
                 "forward_proxy.sni_require_tls must be true", problems)
        ti = _yaml_block(text, "tls_interception")
        _require(bool(re.search(r"^\s*enabled:\s*false\b", ti, re.M)), path,
                 "tls_interception.enabled must be false in v1", problems)
        _require(len(_yaml_list(text, "api_allowlist")) > 0, path,
                 "api_allowlist must not be empty (default deny needs explicit allows)", problems)
    elif engine == "smokescreen":
        _require(re.search(r"^version:\s*v1\b", text, re.M) is not None, path,
                 "must set `version: v1`", problems)
        _require(re.search(r"\baction:\s*open\b", text) is None, path,
                 "`action: open` is forbidden (no open proxy mode)", problems)
        default_block = _yaml_block(text, "default")
        _require(bool(re.search(r"^\s*action:\s*enforce\b", default_block, re.M)), path,
                 "default.action must be `enforce`", problems)
        _require(len(_yaml_list(default_block, "allowed_domains")) > 0, path,
                 "default.allowed_domains must not be empty", problems)
    else:
        raise Fail(f"unknown engine: {engine}")
    return problems


def policy_allowlist(engine: str, path: Path) -> set[str]:
    text = path.read_text()
    if engine == "pipelock":
        return set(_yaml_list(text, "api_allowlist"))
    return set(_yaml_list(_yaml_block(text, "default"), "allowed_domains"))


def check_allowlist_sync(test_policy: bool = False) -> list[str]:
    """Warn when the two engines' allowlists have drifted apart."""
    try:
        pl = ServiceSpec.load("pipelock")
        sm = ServiceSpec.load("smokescreen")
        a = policy_allowlist("pipelock", pl.config_path(test_policy))
        b = policy_allowlist("smokescreen", sm.config_path(test_policy))
    except Fail:
        return []
    warnings = []
    label = "test policy" if test_policy else "policy"
    for entry in sorted(a - b):
        warnings.append(f"{label}: `{entry}` is allowed in pipelock but not smokescreen")
    for entry in sorted(b - a):
        warnings.append(f"{label}: `{entry}` is allowed in smokescreen but not pipelock")
    return warnings


# ---------------------------------------------------------------------------
# Health probing
# ---------------------------------------------------------------------------


def port_listening(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_proxy(host: str, port: int, timeout: float = 4.0) -> tuple[bool, str]:
    """Ask the proxy for a guaranteed-non-allowlisted host.

    Healthy means: the proxy answers with an HTTP error (policy denial or
    resolution failure). A 2xx/3xx would mean the proxy is not enforcing at
    all, which we refuse to call healthy (fail closed).
    """
    request = (
        "GET http://ipl-health-probe.invalid/ HTTP/1.1\r\n"
        "Host: ipl-health-probe.invalid\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request.encode())
            data = sock.recv(4096)
    except OSError as exc:
        return False, f"no response from proxy: {exc}"
    line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace") if data else ""
    match = re.match(r"HTTP/\d\.\d\s+(\d{3})", line)
    if not match:
        return False, f"non-HTTP response: {line!r}"
    status = int(match.group(1))
    if status >= 400:
        return True, f"denies unknown destinations ({line.strip()})"
    return False, f"proxy allowed a non-allowlisted host ({line.strip()}) — NOT healthy"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def all_specs() -> list[ServiceSpec]:
    return [ServiceSpec.load(engine) for engine in ENGINES]


def running_engine(backend: Backend) -> str | None:
    for spec in all_specs():
        if backend.container_state(spec.container_name) == "running":
            return spec.engine
    return None


def cmd_setup(opts: argparse.Namespace) -> int:
    if sys.version_info < (3, 11):
        raise Fail(f"Python 3.11+ required (found {platform.python_version()})")
    print(f"python: {platform.python_version()} — OK")

    for name in BACKENDS:
        state = "available" if Backend(name).available() else "not installed"
        print(f"backend {name}: {state}")
    backend = detect_backend(opts.backend)
    print(f"selected backend: {backend.name}")

    problems: list[str] = []
    for engine in ENGINES:
        spec = ServiceSpec.load(engine)
        for test_policy in (False, True):
            try:
                path = spec.config_path(test_policy)
            except Fail as exc:
                problems.append(str(exc))
                continue
            problems += validate_policy_file(engine, path)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("configuration validation failed")
    print("configs: valid")
    for warning in check_allowlist_sync(False) + check_allowlist_sync(True):
        print(f"WARNING: {warning}")

    engines = ENGINES if opts.engine == "all" else (opts.engine,)
    for engine in engines:
        spec = ServiceSpec.load(engine)
        if engine == "pipelock":
            _setup_pipelock(backend, spec)
        else:
            _setup_smokescreen(backend, spec, rebuild=opts.rebuild)
    print("setup complete")
    return 0


def _setup_pipelock(backend: Backend, spec: ServiceSpec) -> None:
    if spec.image_digest:
        ref = f"{spec.image_repository}@{spec.image_digest}"
        print(f"pipelock: pulling pinned image {ref}")
        backend.pull(ref)
        return
    ref = f"{spec.image_repository}:{spec.image_tag}"
    print(f"pipelock: no digest pinned yet; pulling {ref} to record one")
    backend.pull(ref)
    digest = backend.image_digest(ref)
    if not digest:
        raise Fail(
            "could not determine the image digest automatically.\n"
            f"Find it (e.g. `docker image inspect {ref}` → RepoDigests) and put it in services/pipelock.toml"
        )
    _write_pin(spec.toml_path, "digest", digest)
    print(f"pipelock: recorded digest {digest} in services/pipelock.toml — review and commit it")


def _setup_smokescreen(backend: Backend, spec: ServiceSpec, rebuild: bool = False) -> None:
    if not spec.source_ref:
        raise Fail(
            "smokescreen source ref is not pinned.\n"
            "Run `./run.py pin smokescreen` (needs network), review and commit, then re-run setup."
        )
    tag = spec.run_image_ref()
    if backend.image_present(tag) and not rebuild:
        print(f"smokescreen: image {tag} already built")
        return
    print(f"smokescreen: building {tag} from {spec.source_repo}@{spec.source_ref}")
    build_args = {"SMOKESCREEN_REPO": spec.source_repo, "SMOKESCREEN_REF": spec.source_ref}
    if spec.go_image:
        build_args["GO_IMAGE"] = spec.go_image
    if spec.runtime_image:
        build_args["RUNTIME_IMAGE"] = spec.runtime_image
    context = REPO_ROOT / "images" / "smokescreen"
    backend.build(tag=tag, dockerfile=context / "Dockerfile", context=context, build_args=build_args)
    print(f"smokescreen: built {tag}")


def _write_pin(toml_path: Path, key: str, value: str) -> None:
    text = toml_path.read_text()
    new_text, count = re.subn(rf'^{key} = "[^"]*"$', f'{key} = "{value}"', text, count=1, flags=re.M)
    if count != 1:
        raise Fail(f"could not update `{key}` in {toml_path}; edit it manually to {value!r}")
    toml_path.write_text(new_text)


def cmd_pin(opts: argparse.Namespace) -> int:
    engine = opts.target
    spec = ServiceSpec.load(engine)
    if engine == "pipelock":
        backend = detect_backend(opts.backend)
        ref = f"{spec.image_repository}:{spec.image_tag}"
        print(f"pulling {ref} to resolve its digest")
        backend.pull(ref)
        digest = backend.image_digest(ref)
        if not digest:
            raise Fail(f"could not resolve a digest for {ref}; inspect the image manually")
        _write_pin(spec.toml_path, "digest", digest)
        print(f"pinned pipelock {spec.image_tag} @ {digest}")
    else:
        git = shutil.which("git")
        if not git:
            raise Fail("git is required to pin smokescreen")
        target = opts.ref or "HEAD"
        proc = subprocess.run([git, "ls-remote", spec.source_repo, target],
                              capture_output=True, text=True)
        if proc.returncode != 0 or not proc.stdout.strip():
            raise Fail(f"git ls-remote {spec.source_repo} {target} failed:\n{proc.stderr.strip()}")
        sha = proc.stdout.split()[0]
        _write_pin(spec.toml_path, "ref", sha)
        print(f"pinned smokescreen {target} @ {sha}")
    print("review the change and commit it; then run `./run.py setup`")
    return 0


def cmd_up(opts: argparse.Namespace) -> int:
    engine = opts.engine or DEFAULT_ENGINE
    spec = ServiceSpec.load(engine)
    backend = detect_backend(opts.backend)
    host, port = endpoint()

    config_path = spec.config_path(opts.test_policy)
    problems = validate_policy_file(engine, config_path)
    if problems:
        for problem in problems:
            print(f"CONFIG ERROR: {problem}", file=sys.stderr)
        raise Fail("refusing to start with an invalid policy (fail closed)")
    for warning in check_allowlist_sync(opts.test_policy):
        print(f"WARNING: {warning}")
    if opts.test_policy:
        print("NOTE: starting with the TEST policy (extra DNS fixture domains). "
              "Run `./run.py up` again without --test-policy for normal operation.")

    image = spec.run_image_ref()
    if engine == "smokescreen" and not backend.image_present(image):
        raise Fail(f"image {image} not built yet — run `./run.py --engine smokescreen setup`")

    # `up` recreates: remove every container owned by this repository first
    # (both engines publish the same endpoint, so they cannot coexist).
    for owned in all_specs():
        if backend.remove_container(owned.container_name):
            print(f"removed existing container {owned.container_name}")

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
        mounts=[(config_path, spec.config_mount)],
        args=spec.args,
    )

    deadline = time.monotonic() + HEALTH_WAIT_SECONDS
    healthy, detail = False, "timed out waiting for the proxy to listen"
    while time.monotonic() < deadline:
        if port_listening(host, port):
            healthy, detail = probe_proxy(host, port)
            break
        if backend.container_state(spec.container_name) != "running":
            detail = "container exited during startup"
            break
        time.sleep(0.5)
    if not healthy:
        logs = backend.tail_logs(spec.container_name)
        raise Fail(
            f"post-start health check failed: {detail}\n"
            f"--- last container logs ---\n{logs}\n"
            f"(the container is left in place for debugging; `./run.py down` removes it)"
        )
    print(f"healthy: {detail}")
    print(f"clients: export HTTP_PROXY=http://{host}:{port} HTTPS_PROXY=http://{host}:{port}")
    return 0


def cmd_down(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    removed = False
    for spec in all_specs():
        if backend.remove_container(spec.container_name):
            print(f"removed {spec.container_name}")
            removed = True
    if not removed:
        print("nothing to remove")
    return 0


def cmd_restart(opts: argparse.Namespace) -> int:
    cmd_down(opts)
    return cmd_up(opts)


def cmd_status(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    host, port = endpoint()
    active = running_engine(backend)
    print(f"backend:  {backend.name}")
    print(f"endpoint: http://{host}:{port}")
    for spec in all_specs():
        state = backend.container_state(spec.container_name)
        pin = spec.image_digest if spec.engine == "pipelock" else (spec.source_ref or "(unpinned)")
        marker = " (active)" if spec.engine == active else ""
        print(f"{spec.engine}: {state}{marker}")
        print(f"  container: {spec.container_name}")
        print(f"  image:     {spec.image_repository}:{spec.image_tag or spec.source_ref[:12] or '?'}")
        print(f"  pin:       {pin or '(unpinned)'}")
    if active:
        healthy, detail = probe_proxy(host, port) if port_listening(host, port) \
            else (False, "endpoint not listening")
        print(f"proxy check: {'OK' if healthy else 'FAILED'} — {detail}")
        return 0 if healthy else 1
    print("proxy check: skipped (no engine running)")
    return 0


def cmd_logs(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    engine = opts.engine or running_engine(backend)
    if not engine:
        raise Fail("no engine is running; pass --engine to view a stopped container's logs")
    spec = ServiceSpec.load(engine)
    if backend.container_state(spec.container_name) == "absent":
        raise Fail(f"no container {spec.container_name} exists")
    return backend.logs(spec.container_name, follow=opts.follow)


def cmd_check(opts: argparse.Namespace) -> int:
    backend = detect_backend(opts.backend)
    active = running_engine(backend)
    if not active:
        raise Fail("no engine is running — `./run.py up` first")
    engine = opts.engine or active
    if engine != active:
        raise Fail(f"--engine {engine} requested but {active} is running; `./run.py --engine {engine} up` first")
    host, port = endpoint()
    cmd = [sys.executable, str(REPO_ROOT / "checks" / "egress.py"),
           "--proxy", f"http://{host}:{port}", "--engine", engine]
    cmd.append("--full" if opts.full else "--quick")
    if opts.json:
        cmd.append("--json")
    return subprocess.run(cmd).returncode


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Local containerized Internet filtering proxy (Pipelock or Smokescreen) "
                    f"on http://{DEFAULT_ENDPOINT}",
    )
    parser.add_argument("--engine", choices=ENGINES, default=None,
                        help=f"proxy engine (default: {DEFAULT_ENGINE}; status-dependent for logs/check)")
    parser.add_argument("--backend", choices=BACKENDS, default=None,
                        help="container backend (default: Apple `container` on macOS when installed, else docker)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="validate prerequisites, pull/build pinned images")
    p_setup.add_argument("--rebuild", action="store_true", help="rebuild the smokescreen image even if present")
    p_setup.set_defaults(func=cmd_setup)

    p_up = sub.add_parser("up", help="(re)create the proxy container and health-check it")
    p_up.add_argument("--test-policy", action="store_true",
                      help="use config/<engine>.test.yaml (DNS fixture domains for `check --full`)")
    p_up.set_defaults(func=cmd_up)

    p_restart = sub.add_parser("restart", help="explicit teardown then up")
    p_restart.add_argument("--test-policy", action="store_true")
    p_restart.set_defaults(func=cmd_restart)

    sub.add_parser("down", help="remove containers owned by this repository").set_defaults(func=cmd_down)
    sub.add_parser("status", help="show engine/backend/pin/endpoint state").set_defaults(func=cmd_status)

    p_logs = sub.add_parser("logs", help="show engine logs")
    p_logs.add_argument("--follow", "-f", action="store_true")
    p_logs.set_defaults(func=cmd_logs)

    p_check = sub.add_parser("check", help="run the egress security test suite")
    mode = p_check.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="ordinary allow/deny behavior (default)")
    mode.add_argument("--full", action="store_true", help="include SSRF and CONNECT-abuse fixtures")
    p_check.add_argument("--json", action="store_true", help="machine-readable results")
    p_check.set_defaults(func=cmd_check)

    p_pin = sub.add_parser("pin", help="record immutable pins in services/*.toml (needs network)")
    p_pin.add_argument("target", choices=ENGINES)
    p_pin.add_argument("--ref", help="smokescreen: pin a specific tag/branch instead of HEAD")
    p_pin.set_defaults(func=cmd_pin)

    # `setup` prepares one engine by default; allow all.
    p_setup.add_argument("--all", dest="engine_all", action="store_true",
                         help="prepare both engines")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    opts = parser.parse_args(argv)
    if opts.command == "setup":
        opts.engine = "all" if getattr(opts, "engine_all", False) else (opts.engine or DEFAULT_ENGINE)
    try:
        return opts.func(opts)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
