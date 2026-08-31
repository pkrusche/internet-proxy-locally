#!/usr/bin/env -S uv run --quiet python
"""Is a sandbox on this machine actually routed through this proxy?

docs/security.md draws `project-sandbox` sending its egress to
`http://127.0.0.1:18080` behind an iptables default-DROP. That picture has
two halves owned by two repositories, and only one of them is here:

  * **This repository owns the endpoint.** That it exists, that it refuses
    everything not allowlisted, and that it is bound to loopback are
    checked by `scripts/verify_loopback.py` and `./run.py check`.
  * **`project-sandbox` owns the routing.** Whether a sandbox sets
    `HTTP_PROXY`/`HTTPS_PROXY` to that endpoint, and whether its firewall
    drops everything else, is decided entirely in that tool.

The second half was carried as "unverified" for a long time, which framed
it as a test nobody had run. It is not: it is a fact about the installed
tool, and this script reads it off the installation rather than assuming
it either way. The distinction matters, because "unverified" quietly
implies "probably fine", and an integration that is simply absent is not
fine — it means the diagram describes an intention, and an agent's egress
is governed by whatever `project-sandbox` does on its own.

**Measured 2026-08-28** against project-sandbox as installed here: it
neither sets the proxy variables nor mentions the endpoint. It filters
egress with its own iptables/ipset domain allowlist instead. So nothing
on this machine routes through this proxy unless something sets
`HTTP_PROXY` by hand, and the wiring, if it is wanted, belongs in
`project-sandbox`.

`--run-sandbox` executes the in-sandbox half — the four assertions that
matter once the routing exists — and is opt-in because it builds images
and starts containers in the caller's environment. It refuses to run when
the routing is absent, since it would then only measure project-sandbox's
own filtering and could easily be misread as measuring this proxy's.

    scripts/verify_sandbox.py
    scripts/verify_sandbox.py --run-sandbox   # needs the routing to exist

Run through uv (see the shebang). No third-party imports of its own.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Reporter, load_run_module  # noqa: E402

run_mod = load_run_module()

PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")

# What the in-sandbox half asserts, once something routes a sandbox here.
# Written out even though it cannot run today, because the list is the
# specification of the integration and belongs next to the detection that
# says whether it exists.
SANDBOX_SCRIPT = r"""
set -u
fail() { echo "SANDBOX-FAIL $*"; }
pass() { echo "SANDBOX-PASS $*"; }

# 1. the proxy variables point at the documented endpoint
case "${HTTP_PROXY:-}" in
  http://127.0.0.1:18080|http://localhost:18080) pass proxy-env "$HTTP_PROXY" ;;
  *) fail proxy-env "HTTP_PROXY=${HTTP_PROXY:-unset}" ;;
esac

# 2. an allowlisted host is reachable *through* the proxy
if curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
     --proxy "${HTTP_PROXY:-}" http://pypi.org/ | grep -Eq '^(2|3)'; then
  pass allowlisted-through-proxy
else
  fail allowlisted-through-proxy
fi

# 3. a non-allowlisted host is refused *by* the proxy
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
        --proxy "${HTTP_PROXY:-}" http://example.com/ || echo 000)
case "$code" in
  4*|5*) pass blocked-through-proxy "$code" ;;
  *) fail blocked-through-proxy "$code" ;;
esac

# 4. direct egress, bypassing the proxy, is dropped by the firewall.
#    This is the half that makes the proxy the *only* way out; without it
#    the allowlist is advice.
if curl -sS -o /dev/null --max-time 8 --noproxy '*' http://pypi.org/ 2>/dev/null; then
  fail direct-egress-reachable
else
  pass direct-egress-dropped
fi

# 5. DNS straight out is dropped too, or a name can be resolved past the
#    policy even when connections cannot.
if timeout 5 getent hosts example.com >/dev/null 2>&1; then
  fail direct-dns-resolves
else
  pass direct-dns-dropped
fi
"""


def sandbox_tool() -> str:
    return shutil.which("project-sandbox") or ""


def _package_root(tool: str) -> Path | None:
    """Where the installed tool's Python package lives, if it is one."""
    try:
        first = Path(tool).read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return None
    if not first.startswith("#!"):
        return None
    interpreter = Path(first[2:].strip())
    for candidate in interpreter.parent.parent.glob("lib/*/site-packages/project_sandbox"):
        return candidate
    return None


def routing_evidence(tool: str) -> "tuple[bool, list[str]]":
    """Does the installed tool route a sandbox at this repository's endpoint?

    Read off the installation rather than inferred: the endpoint string and
    the proxy environment variables either appear in the tool that would
    have to set them, or they do not.
    """
    host, port = run_mod.endpoint()
    endpoint = f"{host}:{port}"
    notes: list[str] = []
    root = _package_root(tool)
    if root is None:
        notes.append(f"could not locate the package behind {tool}; "
                     "detection is inconclusive")
        return False, notes

    found_endpoint, found_env = [], []
    for path in root.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if endpoint in text or str(port) in text:
            found_endpoint.append(path.name)
        if any(name in text for name in PROXY_ENV):
            found_env.append(path.name)
    notes.append(f"package: {root}")
    notes.append(f"names the endpoint ({endpoint}): "
                 + (", ".join(sorted(set(found_endpoint))) or "no file"))
    notes.append("sets HTTP_PROXY/HTTPS_PROXY: "
                 + (", ".join(sorted(set(found_env))) or "no file"))
    return bool(found_endpoint and found_env), notes


def endpoint_contract(report: Reporter) -> bool:
    """The half this repository owns: the endpoint a sandbox would use."""
    host, port = run_mod.endpoint()
    listening = run_mod.port_listening(host, port)
    if not report.check(listening, f"the endpoint {host}:{port} is serving",
                        "no proxy is running, so the contract a sandbox depends on "
                        "cannot be checked. `./run.py up` first."):
        return False
    healthy, detail, _ = run_mod.probe_proxy(host, port)
    return report.check(
        healthy, f"the endpoint refuses a non-allowlisted host ({detail})",
        "the endpoint answered but did not deny an unknown destination. A sandbox "
        "pointed here would be pointed at something that is not enforcing.")


def run_sandbox(report: Reporter, project: Path) -> None:
    """Execute the in-sandbox assertions through `project-sandbox --agent bash`."""
    tool = sandbox_tool()
    proc = subprocess.run(
        [tool, str(project), "--agent", "bash", "--prompt-text", SANDBOX_SCRIPT,
         "--timeout", "300"],
        capture_output=True, text=True)
    output = proc.stdout + proc.stderr
    seen = {line.split()[1] for line in output.splitlines()
            if line.startswith(("SANDBOX-PASS ", "SANDBOX-FAIL ")) and len(line.split()) > 1}
    if not seen:
        report.check(False, "the sandbox ran the assertions",
                     f"exit {proc.returncode}; no SANDBOX-PASS/FAIL lines came "
                     f"back:\n{output[-2000:]}")
        return
    for line in output.splitlines():
        if line.startswith("SANDBOX-PASS "):
            report.check(True, f"in-sandbox: {line[len('SANDBOX-PASS '):]}")
        elif line.startswith("SANDBOX-FAIL "):
            report.check(False, f"in-sandbox: {line[len('SANDBOX-FAIL '):]}",
                         "the sandbox's egress does not match the contract in "
                         "docs/security.md.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-sandbox", action="store_true",
                        help="also run the in-sandbox assertions (builds images and "
                             "starts containers; refuses unless the routing exists)")
    parser.add_argument("--project", type=Path, default=Path.cwd(),
                        help="project directory to hand to project-sandbox")
    opts = parser.parse_args(argv)

    report = Reporter("project-sandbox integration")
    endpoint_contract(report)

    tool = sandbox_tool()
    if not tool:
        report.note("project-sandbox is not installed here, so the routing half "
                    "cannot be inspected on this machine.")
        return report.finish()

    report.note(f"project-sandbox: {tool}")
    routed, notes = routing_evidence(tool)
    for note in notes:
        report.note(note)
    # Deliberately a note, not a failed check: this repository does not own
    # the routing, and a red line here would be this suite failing for
    # another tool's design decision. What it must not do is stay silent.
    if routed:
        report.note("the installed project-sandbox routes sandboxes at this "
                    "endpoint; run with --run-sandbox to check the four in-sandbox "
                    "properties.")
    else:
        report.note("FINDING: the installed project-sandbox does NOT route "
                    "sandboxes through this proxy — it sets no proxy variables and "
                    "does not name the endpoint. It filters egress with its own "
                    "iptables/ipset domain allowlist. The topology in "
                    "docs/security.md is therefore an intended integration, not "
                    "a description of this machine; wiring it means setting "
                    "HTTP_PROXY/HTTPS_PROXY in project-sandbox and allowing the "
                    "endpoint through its firewall.")

    if opts.run_sandbox:
        if not routed:
            report.check(False, "the in-sandbox assertions could run",
                         "--run-sandbox was given, but nothing routes a sandbox "
                         "through this proxy. The run would measure "
                         "project-sandbox's own filtering and read like a result "
                         "about this one. Wire the routing first.")
        else:
            run_sandbox(report, opts.project)
    return report.finish()


if __name__ == "__main__":
    sys.exit(main())
