#!/usr/bin/env python3
"""Re-confirm that the host endpoint is bound to loopback and nothing else.

`run.py` publishes the endpoint as `--publish 127.0.0.1:18080:<port>`. That
one argument is the entire reason a proxy holding an allowlist for this
machine is not also an open proxy for the network the machine is on. Both
backends currently honour the address half — and a release that stopped
honouring it would widen the endpoint to every interface with no error, no
warning and no visible change in `run.py`'s output. So it is re-checked
against each installed runtime rather than assumed, and re-checked again
after a backend upgrade.

Two independent pieces of evidence, because either alone can lie:

  structural — the runtime reports the binding it actually made
               (`publishedPorts[].hostAddress` on Apple `container`,
               `HostConfig.PortBindings[].HostIp` on Docker);
  behavioral — the endpoint answers on 127.0.0.1 and refuses on every
               non-loopback address this host has. A host firewall could
               produce that refusal on its own, which is why the structural
               check is here too; a runtime that reports a loopback binding
               while listening everywhere is what the behavioral check is
               here for.

**If a release fails this, do not widen the binding to make it pass.** The
endpoint staying loopback-only is the invariant; a backend that cannot
express it is a backend this repository cannot use (docs/lab.md).

    scripts/verify_loopback.py                 # every installed backend
    scripts/verify_loopback.py --backend docker
    scripts/verify_loopback.py --port 18081    # leave a running proxy alone
    scripts/verify_loopback.py --running       # check the proxy that is up now

Stdlib only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Reporter, engine_up, load_run_module, run_py_down  # noqa: E402

run_mod = load_run_module()


def local_addresses() -> list[str]:
    """Every non-loopback IPv4 address this host answers on.

    Parsed from `ifconfig`/`ip` rather than resolved from the hostname:
    the hostname often resolves to 127.0.0.1 alone, which would make the
    behavioral check vacuous — it would prove the endpoint is unreachable
    from an address nothing is bound to.
    """
    for cmd in (["ip", "-4", "-o", "addr"], ["ifconfig", "-a"]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        found = []
        for token in re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", proc.stdout):
            address = ipaddress.ip_address(token)
            if not address.is_loopback and token not in found:
                found.append(token)
        if found:
            return found
    return []


def reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def backend_release(backend: "run_mod.Backend") -> str:
    """The runtime's own version string — the thing this check is pinned to.

    docs/lab.md records which release was verified; a result recorded
    against no version cannot be re-checked after an upgrade.
    """
    for args in (["--version"], ["version", "--format", "{{.Server.Version}}"]):
        try:
            proc = subprocess.run([backend.bin, *args], capture_output=True,
                                  text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip().splitlines()[0]
    return "unknown"


def verify(backend_name: str, engine: str, port: int, report: Reporter,
           running: bool = False) -> None:
    backend = run_mod.Backend(backend_name)
    release = backend_release(backend)
    report.note(f"{backend_name}: {release}")

    env = dict(os.environ, IPL_ENDPOINT=f"127.0.0.1:{port}")
    if running:
        # Check the proxy that is already up, rather than replacing it. The
        # binding is a property of the release and the `--publish` argument,
        # not of when the container started, so this is the same result —
        # and it is the mode to use on a machine whose sandbox is currently
        # served by that proxy.
        engine = run_mod.running_engine(backend) or ""
        if not engine:
            raise run_mod.Fail(
                f"--running was given but no engine is up on {backend_name}. "
                "Start one, or drop --running to have this script start one.")
        spec = run_mod.ServiceSpec.load(engine)
        published = backend.published_ports(spec.container_name)
        port = published[0][1] if published else port
        report.note(f"{backend_name}: checking the running {engine} on port {port}")
    else:
        spec = run_mod.ServiceSpec.load(engine)
        engine_up(backend_name, engine, port, test_policy=False, env=env)
    try:
        bindings = backend.published_ports(spec.container_name)
        report.check(
            bool(bindings),
            f"{backend_name}: the runtime reports a published port",
            f"`{backend.bin} inspect {spec.container_name}` reported no port "
            "bindings at all, so the structural half of this check cannot run. "
            "If the shape changed, teach Backend.published_ports() about it.")
        for host_ip, host_port, container_port in bindings:
            report.check(
                host_ip == "127.0.0.1",
                f"{backend_name}: {host_port} is bound to 127.0.0.1 "
                f"(container {container_port})",
                f"the runtime bound host port {host_port} to "
                f"`{host_ip or 'every interface'}`, not 127.0.0.1. This release "
                "does not honour `--publish ip:host:container`. Do NOT widen the "
                "binding to work around it — the endpoint must stay loopback-only.")

        report.check(
            reachable("127.0.0.1", port),
            f"{backend_name}: the endpoint answers on 127.0.0.1:{port}",
            "nothing answered on loopback, so the negative results below prove "
            "nothing. Is the engine running?")

        addresses = local_addresses()
        if not addresses:
            report.note(f"{backend_name}: this host has no non-loopback IPv4 "
                        "address, so the behavioral half is vacuous here; the "
                        "structural check above is the whole result.")
        for address in addresses:
            report.check(
                not reachable(address, port, timeout=1.0),
                f"{backend_name}: the endpoint refuses {address}:{port}",
                f"the endpoint answered on {address}, a non-loopback address of "
                "this host. Anything that can route to this machine can use the "
                "proxy. Do NOT widen the binding — fix or replace the backend.")
    finally:
        if not running:
            run_py_down(backend_name, env=env)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--backend", choices=run_mod.BACKENDS, default=None,
                        help="one backend (default: every installed one)")
    parser.add_argument("--engine", choices=run_mod.ENGINES,
                        default=run_mod.DEFAULT_ENGINE,
                        help="engine to publish the endpoint with; the binding is "
                             "run.py's, not the engine's, so this rarely matters")
    parser.add_argument("--port", type=int, default=18080,
                        help="host port to publish (default: 18080; pick another to "
                             "leave a running proxy alone)")
    parser.add_argument("--running", action="store_true",
                        help="check the engine that is already up instead of "
                             "starting and removing one — the mode to use when the "
                             "proxy under test is the one serving this machine")
    opts = parser.parse_args(argv)

    names = [opts.backend] if opts.backend else \
        [name for name in run_mod.BACKENDS if run_mod.Backend(name).available()]
    if not names:
        print("error: no container backend is installed", file=sys.stderr)
        return 1

    report = Reporter("loopback-only endpoint")
    for name in names:
        if not run_mod.Backend(name).available():
            print(f"error: backend `{name}` is not installed", file=sys.stderr)
            return 1
        try:
            verify(name, opts.engine, opts.port, report, running=opts.running)
        except run_mod.Fail as exc:
            report.check(False, f"{name}: the engine started", str(exc))
    report.note("Record the outcome, with the release string above, in "
                "docs/lab.md's parity checklist.")
    return report.finish()


if __name__ == "__main__":
    sys.exit(main())
