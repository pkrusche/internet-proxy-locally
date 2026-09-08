"""End-to-end verification of one container backend, fixture included.

The unit suite drives a fake backend: it pins down the CLI arguments
`ipl` emits and the JSON shapes it parses, but it cannot tell whether a
real runtime *acts* on them. One place that gap is load-bearing is the DNS
fixture. `ipl-lab up` starts a resolver container, reads its address
out of `inspect` — Docker reports it under `NetworkSettings`, Apple
`container` under `status.networks[]` as a CIDR — and hands it to the
engine as `--dns`. Both shapes are parsed and unit-tested; parsing the
right field and having the engine actually resolve through that address are
different claims, and only the second one makes `dns-mixed-answers`,
`dns-rebinding` and `ptr-allowlist` mean anything.

So this script asserts the whole chain on a real backend:

  * the engine image builds or pulls, and the engine starts;
  * the endpoint is published to loopback and nothing else;
  * the fixture container runs and reports an address in this backend's own
    JSON shape, and `up` announced that same address;
  * the engine resolves *through* it — proved by the fixture-dependent
    checks producing verdicts instead of skipping, which they can only do
    when the fixture answers the engine's queries;
  * `down` removes the fixture as well as the engine, so a resolver that
    answers private addresses for allowlisted names cannot outlive the run
    that started it.

    ipl-verify backend --backend docker
    ipl-verify backend --backend docker --engine squid --port 18081

Reached as `uv run ipl-verify backend`. Stdlib only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys

from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import BACKENDS, DEFAULT_ENGINE, ENGINES
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lab.container import fixture_spec
from internet_proxy_locally.net import port_listening
from internet_proxy_locally.spec import ServiceSpec
from internet_proxy_locally.verify.harness import Reporter, engine_up, run_cli, teardown

# The checks that can only produce a verdict when the fixture container is
# answering the engine's DNS queries. If `--dns` were ignored, the engine
# would resolve these names upstream, get NXDOMAIN for the `.test` ones and
# no answer at all for the rebinding zone, and every one of these rows
# would skip or fail its control probe.
FIXTURE_DEPENDENT = ("dns-mixed-answers", "dns-rebinding", "ptr-allowlist")


def verify(backend_name: str, engine: str, port: int, report: Reporter) -> None:
    backend = Backend(backend_name)
    spec = ServiceSpec.load(engine)
    fixture = fixture_spec()
    env = dict(os.environ, IPL_ENDPOINT=f"127.0.0.1:{port}")

    proc = None
    try:
        proc = engine_up(backend_name, engine, port, test_policy=True, env=env)
        report.check(
            backend.container_state(spec.container_name) == "running",
            f"{engine} is running on {backend_name}",
            f"`{backend.bin} inspect {spec.container_name}` does not report it "
            "running, although `up` reported success.",
        )

        # -- the endpoint -----------------------------------------------
        bindings = backend.published_ports(spec.container_name)
        report.check(
            bool(bindings) and all(ip == "127.0.0.1" for ip, _, _ in bindings),
            f"the endpoint is published to loopback only ({bindings})",
            "the runtime did not bind the endpoint to 127.0.0.1. Do NOT widen "
            "the binding; see ipl-verify loopback.",
        )
        report.check(
            port_listening("127.0.0.1", port, timeout=2.0),
            f"the endpoint answers on 127.0.0.1:{port}",
        )

        # -- the fixture ------------------------------------------------
        report.check(
            backend.container_state(fixture.container_name) == "running",
            f"the DNS fixture is running on {backend_name}",
            "`ipl-lab up` did not leave the fixture container running, so "
            "the fixture-dependent checks below have nothing to answer them.",
        )

        address = backend.container_ip(fixture.container_name)
        parsed = None
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            pass
        report.check(
            parsed is not None,
            f"the fixture's address parsed out of {backend_name}'s inspect JSON "
            f"({address!r})",
            f"Backend.container_ip() returned {address!r}. This backend reports "
            "the container address in a shape `backend.py` does not parse — which is "
            "exactly the failure this script exists to catch. Teach "
            "Backend.container_ip() the new shape.",
        )
        report.check(
            bool(parsed) and parsed.is_private,
            "the fixture's address is on the backend's private network",
            f"{address} is not a private address; a fixture reachable from "
            "outside this machine is not a fixture.",
        )
        report.check(
            bool(proc and address and address in proc.stdout),
            f"`up` announced the fixture at {address}",
            f"`up` printed:\n{proc.stdout.strip()}\nwhich does not name the "
            "address `inspect` reports, so the two do not agree on what the "
            "engine was pointed at.",
        )

        # -- the engine actually resolves through it --------------------
        checked = run_cli(
            ["--backend", backend_name, "check", "--json"],
            cli="ipl-lab",
            env=env,
            check=False,
        )
        try:
            document = json.loads(checked.stdout)
        except json.JSONDecodeError:
            report.check(
                False,
                "`check --full --json` produced results",
                f"exit {checked.returncode}; stderr:\n{checked.stderr.strip()}",
            )
            return
        rows = {row["name"]: row for row in document["results"]}
        for name in FIXTURE_DEPENDENT:
            row = rows.get(name, {})
            report.check(
                row.get("outcome") not in (None, "skip", "error"),
                f"`{name}` produced a verdict ({row.get('outcome')}) — the engine "
                "resolved through the fixture",
                f"the row is `{row.get('outcome')}`: {row.get('detail')}\n"
                "A skip here means the engine did not resolve the fixture names, "
                "so `--dns` was passed but not honoured — the one genuinely "
                "backend-specific dependency in this repository.",
            )
        skipped = [n for n, row in rows.items() if row["outcome"] == "skip"]
        report.check(
            not skipped,
            "no check skipped for want of a fixture",
            f"skipped: {', '.join(skipped)}",
        )
        report.note(
            "check --full: "
            + ", ".join(f"{n}={row['outcome']}" for n, row in rows.items())
        )
        report.note(f"check --full exit code: {checked.returncode}")
    finally:
        teardown(backend_name, env=env)

    # -- teardown -------------------------------------------------------
    for name, what in (
        (spec.container_name, engine),
        (fixture.container_name, "the DNS fixture"),
    ):
        report.check(
            backend.container_state(name) == "absent",
            f"`down` removed {what}",
            f"{name} still exists after `down`. The fixture in particular must "
            "never outlive the run: it answers allowlisted names with private "
            "addresses.",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--backend", choices=BACKENDS, required=True)
    parser.add_argument(
        "--engine",
        choices=ENGINES,
        default=DEFAULT_ENGINE,
        help=f"engine to verify the backend with (default: {DEFAULT_ENGINE})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18080,
        help="host port to publish (default: 18080; pick another to "
        "leave a running proxy alone)",
    )
    opts = parser.parse_args(argv)

    if not Backend(opts.backend).available():
        print(f"error: backend `{opts.backend}` is not installed", file=sys.stderr)
        return 1

    report = Reporter(
        f"{opts.backend} backend, end to end, with the DNS fixture ({opts.engine})"
    )
    try:
        verify(opts.backend, opts.engine, opts.port, report)
    except (Fail, RuntimeError) as exc:
        report.check(False, "the lifecycle ran to completion", str(exc))
    report.note("Record the outcome in docs/lab.md's parity checklist.")
    return report.finish()


if __name__ == "__main__":
    sys.exit(main())
