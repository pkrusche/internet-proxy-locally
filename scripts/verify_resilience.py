#!/usr/bin/env -S uv run --quiet python
"""Does the service fail closed when it breaks, and survive being restarted?

docs/security.md asserts two things that follow from the design and had
never been observed:

  * **Crash → fail closed.** If the engine dies, nothing listens on the
    endpoint, so a sandbox pointed at it loses the Internet rather than
    gaining unfiltered access. That is the good failure mode, and the one
    worth checking is the *other* one: a dying proxy must never start
    accepting and forwarding.
  * **`restart` is safe.** Recreating the container drops in-flight
    connections, which is expected. What must not happen is a window
    during which the endpoint answers *and* forwards something the policy
    denies — a half-started engine that accepts connections before its
    configuration is loaded would be exactly that.

Both are measured here under continuous load, because both are about a
transition and a quiet proxy is the easy case. A load generator runs
throughout: one thread asking for an allowlisted host, one asking for a
host that must always be refused. The allowed stream is expected to break
and recover — that is what a restart does. The denied stream is the
assertion: **not one of its requests may ever succeed**, before, during or
after the transition.

It also records the operational numbers nobody had collected — startup
time to first healthy probe, and image size — which are reported, not
graded: they are inputs to a judgement, not a pass or a fail.

    scripts/verify_resilience.py --backend docker --port 18081
    scripts/verify_resilience.py --backend docker --all --port 18081

Run through uv (see the shebang). No third-party imports of its own.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
from pathlib import Path

# The repository root, so `scripts.harness` and `run` resolve by name.
# See the comment in scripts/harness.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.harness import Reporter, engine_up, run_cli, run_py_down, run  # noqa: E402

# A host that must never be reachable, whichever policy is mounted. The
# load generator asks for it continuously; a single success is a finding.
DENIED_HOST = "example.com"
ALLOWED_HOST = "pypi.org"
SETTLE = 0.05


class Load:
    """Two request streams against the endpoint, running until stopped.

    The denied stream is the safety assertion and the allowed stream is
    the liveness one; keeping both running across the same transition is
    what makes "it came back" and "it never leaked" the same measurement
    rather than two separate runs.
    """

    def __init__(self, port: int):
        self.port = port
        self.stop = threading.Event()
        self.allowed_ok = 0
        self.allowed_failed = 0
        self.denied_refused = 0
        self.denied_leaked: list[str] = []
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def _request(self, host: str) -> "tuple[int | None, str]":
        payload = (f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: ipl-resilience\r\nConnection: close\r\n\r\n")
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=4) as sock:
                sock.settimeout(4)
                sock.sendall(payload.encode())
                data = sock.recv(4096)
        except OSError as exc:
            return None, f"{type(exc).__name__}: {exc}"
        line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        for token in line.split():
            if token.isdigit() and len(token) == 3:
                return int(token), line
        return None, line or "(no data)"

    def _drive(self, host: str, denied: bool) -> None:
        while not self.stop.is_set():
            status, line = self._request(host)
            with self._lock:
                if denied:
                    # Anything that is not a refusal is a leak: a 2xx/3xx
                    # means the proxy forwarded a request the policy denies.
                    if status is not None and status < 400:
                        self.denied_leaked.append(line)
                    else:
                        self.denied_refused += 1
                elif status is not None and status < 400:
                    self.allowed_ok += 1
                else:
                    self.allowed_failed += 1
            time.sleep(SETTLE)

    def __enter__(self) -> "Load":
        for host, denied in ((ALLOWED_HOST, False), (DENIED_HOST, True)):
            thread = threading.Thread(target=self._drive, args=(host, denied),
                                      daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def __exit__(self, *exc) -> None:
        self.stop.set()
        for thread in self._threads:
            thread.join(timeout=10)

    def summary(self) -> str:
        return (f"allowed {self.allowed_ok} ok / {self.allowed_failed} failed; "
                f"denied {self.denied_refused} refused / "
                f"{len(self.denied_leaked)} leaked")


def _wait(condition, seconds: float) -> bool:
    """Poll `condition` until it holds or the budget runs out."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return condition()


def accepts(port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def measure_startup(backend_name: str, engine: str, port: int,
                    env: dict) -> "tuple[float, str]":
    """Seconds from `up` returning to the endpoint answering as a proxy."""
    start = time.monotonic()
    engine_up(backend_name, engine, port, test_policy=False, env=env)
    elapsed = time.monotonic() - start
    _, detail, _ = run.probe_proxy("127.0.0.1", port)
    return elapsed, detail


def image_size(backend: "run.Backend", ref: str) -> str:
    size = backend.image_size(ref)
    return f"{size / 1e6:.0f} MB" if size else "unknown"


def verify(engine: str, port: int, report: Reporter, backend_name: str) -> None:
    backend = run.Backend(backend_name)
    spec = run.ServiceSpec.load(engine)
    env = dict(os.environ, IPL_ENDPOINT=f"127.0.0.1:{port}")

    try:
        elapsed, detail = measure_startup(backend_name, engine, port, env)
        report.note(f"{engine}: up to healthy in {elapsed:.1f}s — {detail}")
        report.note(f"{engine}: image {spec.run_image_ref()} — "
                    f"{image_size(backend, spec.run_image_ref())}")

        with Load(port) as load:
            # Wait for the stream rather than assuming a fixed warm-up. A
            # cold engine's first request can take seconds — Squid's does,
            # resolving the destination before it can serve anything — and
            # a fixed sleep here measured that race instead of the
            # property.
            flowing = _wait(lambda: load.allowed_ok > 0, 20.0)
            report.check(flowing,
                         f"{engine}: the allowed stream is flowing before the test",
                         f"nothing succeeded against {ALLOWED_HOST} within 20s, so "
                         "the recovery check below could not tell a restart from an "
                         f"already-broken proxy ({load.summary()}).")

            # -- crash -------------------------------------------------
            report.note(f"{engine}: removing the container mid-load")
            backend.remove_container(spec.container_name)
            time.sleep(2.0)
            report.check(
                not accepts(port),
                f"{engine}: nothing listens on the endpoint once the engine dies",
                "the endpoint still accepts connections after the container was "
                "removed. Something other than this repository is bound to it, and "
                "a sandbox pointed there is talking to something unknown.")
            crashed_leaks = len(load.denied_leaked)
            report.check(
                crashed_leaks == 0,
                f"{engine}: a dying engine refused rather than forwarded "
                f"({load.summary()})",
                f"a request for {DENIED_HOST} succeeded while the engine was going "
                "down. That is the failure this property exists to exclude: the "
                f"proxy must lose the Internet, not open it.\n"
                + "\n".join(load.denied_leaked[:3]))

            # -- restart under load ------------------------------------
            report.note(f"{engine}: `restart` under continuous load")
            before_ok = load.allowed_ok
            proc = run_cli(["--backend", backend_name, "--engine", engine, "restart"],
                           env=env, check=False)
            report.check(proc.returncode == 0,
                         f"{engine}: `restart` succeeded under load",
                         f"exit {proc.returncode}:\n{proc.stderr.strip()}")
            recovered = _wait(lambda: load.allowed_ok > before_ok, 20.0)
            report.check(
                recovered,
                f"{engine}: the allowed stream recovered after the restart",
                "no request to an allowlisted host succeeded within 20s of "
                f"`restart` returning ({load.summary()}). The proxy came back "
                "unhealthy.")
            report.check(
                not load.denied_leaked,
                f"{engine}: nothing leaked across the whole run "
                f"({load.summary()})",
                "a request for a denied host succeeded at some point during the "
                "crash or the restart. A half-started engine that accepts "
                "connections before its policy is loaded looks exactly like "
                "this.\n" + "\n".join(load.denied_leaked[:3]))
        report.note(f"{engine}: final — {load.summary()}")
    finally:
        run_py_down(backend_name, env=env)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", choices=run.ENGINES, default=None)
    parser.add_argument("--all", action="store_true",
                        help="run against every engine in turn")
    parser.add_argument("--backend", choices=run.BACKENDS, default=None)
    parser.add_argument("--port", type=int, default=18080,
                        help="host port to publish (default: 18080; pick another to "
                             "leave a running proxy alone)")
    opts = parser.parse_args(argv)

    backend_name = opts.backend or run.detect_backend(None).name
    engines = run.ENGINES if opts.all else (opts.engine or run.DEFAULT_ENGINE,)
    report = Reporter("fail-closed on crash, and restart under load")
    for engine in engines:
        try:
            verify(engine, opts.port, report, backend_name)
        except (run.Fail, RuntimeError) as exc:
            report.check(False, f"{engine}: the run completed", str(exc))
    report.note("Record the outcome in docs/security.md's fail-closed properties.")
    return report.finish()


if __name__ == "__main__":
    sys.exit(main())
