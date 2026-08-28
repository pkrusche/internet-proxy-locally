#!/usr/bin/env python3
"""Does an engine forward the request it was given, or rewrite it?

The question this answers is a specific one. `allowed-http` — a plain-HTTP
GET to `pypi.org` — returns **200** through Pipelock and **301** through
Smokescreen and Squid. That was attributed to CDN variation, and a 200 over
plain HTTP from a Fastly-fronted host is unusual enough that the other
explanation — the proxy quietly rewriting the request, most plausibly
upgrading it to HTTPS — was worth ruling out rather than dismissing.

**What it found (2026-08-28).** Neither. The request is forwarded
unchanged, and the CDN attribution was also wrong: **Pipelock follows the
redirect**. pypi.org's edge answers plain HTTP with `301 Location:
https://pypi.org/…`; Smokescreen and Squid hand that 301 to the client,
and Pipelock fetches the target and hands back *its* response — which for
`/` is the origin's 200. Its own log says so, once you ask it for a path
that cannot be cached into looking ordinary:

    {"event":"redirect","message":"redirect followed","hop":1,
     "original_url":"http://pypi.org/<probe>?ipl=<probe>",
     "redirect_url":"https://pypi.org/<probe>"}
    {"event":"forward_http","url":"http://pypi.org/<probe>?ipl=<probe>",
     "status_code":404}

The `forward_http` line quotes the request target exactly as sent, query
string included, so nothing was normalized; the difference is entirely in
what Pipelock does with the *answer*. See docs/engines.md, "Pipelock
follows redirects".

What this script can and cannot establish, stated plainly, because the
difference matters more than the verdict:

  * **Can**: that the request *target* survives the proxy byte for byte. A
    probe path and query string are echoed back by any redirect the
    destination issues, so a rewritten path or a dropped query is visible.
  * **Can**: that the response was produced upstream rather than by the
    proxy, from the destination's own tier headers (`Server`,
    `X-Served-By`, `Via`, `X-Cache`) — a proxy answering by itself has no
    way to forge a Fastly cache node name that changes per request.
  * **Can**: that the difference is a property of the *destination*, not of
    the proxy, by issuing the identical request directly from this host and
    against several allowlisted hosts.
  * **Cannot**: prove that no request *header* was added, removed or
    reordered. That needs an upstream that echoes what it received, and
    this policy allowlists no such host by design — every allowlisted
    destination is a real package or code registry. The engine's own log
    line for the request is captured instead, which is the proxy stating
    what it forwarded rather than the destination confirming it.
  * **Can**, with `--redirect-authz`: whether a followed redirect's
    *target* is re-authorized against the allowlist — the question the
    finding above raises. It needs an allowlisted host that redirects
    somewhere the policy forbids, and since every entry in
    `[policy].allow` is a registry that redirects only to itself, the
    policy is what gets narrowed instead: `github.com` redirects to
    `raw.githubusercontent.com`, so the engine runs once on a policy that
    allows both (the control, which must fetch the file) and once on a
    policy that allows only the source (which must not). **Measured
    2026-08-28: Pipelock re-authorizes.** The narrowed half answers `403`
    and logs `redirect blocked: domain not in allowlist:
    raw.githubusercontent.com`.

    scripts/upstream_fidelity.py --running        # the engine that is up now
    scripts/upstream_fidelity.py --engine pipelock --port 18081
    scripts/upstream_fidelity.py --all --port 18081   # all three, in turn
    scripts/upstream_fidelity.py --engine pipelock --redirect-authz --port 18081

Stdlib only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import Reporter, engine_up, load_run_module, run_cli, run_py_down  # noqa: E402

run_mod = load_run_module()

# Allowlisted hosts that answer plain HTTP. More than one, because the
# claim under test is about the *destination* deciding: if the split were
# the proxy's doing it would not depend on which host is asked.
PROBE_HOSTS = ("pypi.org", "files.pythonhosted.org", "github.com")

# Headers that identify which tier produced the response. A proxy that
# answered the request itself, or that fetched it over a different scheme,
# does not reproduce these.
TIER_HEADERS = ("Server", "Via", "X-Served-By", "X-Cache", "Location",
                "Strict-Transport-Security")
TIMEOUT = 8.0


class Response:
    def __init__(self, status: int | None, headers: dict[str, str], body: str,
                 first_line: str):
        self.status = status
        self.headers = headers
        self.body = body
        self.first_line = first_line

    def header(self, name: str) -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return ""

    def tier(self) -> str:
        parts = [f"{name}={self.header(name)!r}" for name in TIER_HEADERS
                 if self.header(name)]
        return "; ".join(parts) or "(no tier headers)"


def _read(sock: socket.socket) -> bytes:
    data = b""
    while len(data) < 65536:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data and len(data) > 2048:
            break
    return data


def _parse(data: bytes) -> Response:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    first = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip()] = value.strip()
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", first)
    return Response(int(match.group(1)) if match else None, headers,
                    body.decode("latin-1", "replace"), first)


def request(target: tuple[str, int], request_target: str, host: str) -> Response:
    """One GET, with identical headers whether it goes to a proxy or an origin.

    Only the request-target form differs, and it has to: HTTP requires
    absolute-form to a proxy and origin-form to an origin. Everything else
    — method, version, Host, User-Agent, Connection — is byte-identical, so
    a difference in the answer cannot be attributed to a difference in what
    was asked.
    """
    payload = (
        f"GET {request_target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: internet-proxy-locally-upstream-fidelity\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection(target, timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendall(payload.encode())
            data = _read(sock)
    except OSError as exc:
        return Response(None, {}, "", f"connection error: {exc}")
    return _parse(data)


def probe(host: str, token: str, proxy: tuple[str, int]) -> tuple[Response, Response]:
    """The same request, once straight at the origin and once via the proxy."""
    path = f"/{token}/probe?ipl={token}"
    direct = request((host, 80), path, host)
    proxied = request(proxy, f"http://{host}{path}", host)
    return direct, proxied


def echoes(response: Response, token: str) -> bool:
    """Did the destination hand our request target back to us?

    A redirect echoes it in `Location`; an error page usually echoes it in
    the body. Either proves the path and query reached the destination as
    written, which is the half of request fidelity that is observable from
    outside.
    """
    return token in response.header("Location") or token in response.body


REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def engine_lines(backend: str, engine: str, token: str) -> list[str]:
    """The engine's own log lines naming this probe.

    All three engines log the request target they forwarded — Pipelock as
    `forward_http.url`, Squid in its access log, Smokescreen in its
    canonical decision line — so the proxy states what it sent even where
    the destination will not echo it.
    """
    logs = run_cli(["--backend", backend, "--engine", engine, "logs"], check=False)
    return [line.strip() for line in (logs.stdout + logs.stderr).splitlines()
            if token in line]


def verify(engine: str, port: int, report: Reporter, backend: str) -> None:
    proxy = ("127.0.0.1", port)
    report.note(f"engine under test: {engine} on 127.0.0.1:{port}")
    follows_redirects = False
    witnesses: list[str] = []
    for host in PROBE_HOSTS:
        token = f"ipl-{uuid.uuid4().hex[:12]}"
        direct, proxied = probe(host, token, proxy)
        report.note(f"{host}: direct   {direct.first_line} | {direct.tier()}")
        report.note(f"{host}: proxied  {proxied.first_line} | {proxied.tier()}")
        lines = engine_lines(backend, engine, token)
        for line in lines:
            report.note(f"{host}: engine log  {line[:220]}")

        if proxied.status is None:
            report.check(False, f"{host}: the proxy answered at all",
                         f"{proxied.first_line}")
            continue

        # -- 1. was the request itself changed? -------------------------
        # Two independent witnesses, either of which settles it: the
        # destination handing the target back, or the engine logging what
        # it forwarded.
        echoed = echoes(proxied, token)
        logged = bool(lines)
        if echoed or logged:
            witnesses.append(host)
            report.note(f"{host}: the request target reached the destination as "
                        "written (" + ("the destination echoed it back"
                                       if echoed else "the engine logged it") + ").")
        else:
            # Not a finding: some destinations answer without quoting the
            # target, and some engines log the host but not the path. This
            # host simply contributes no evidence for this engine.
            report.note(f"{host}: neither the destination nor the engine's log "
                        "quotes the request target, so this host says nothing "
                        "about request fidelity here.")

        # -- 2. did the *proxy* produce the answer? ---------------------
        report.check(
            proxied.tier() != "(no tier headers)",
            f"{host}: the response came from the destination, not from the proxy",
            "the proxied response carries no Server/Via/X-Served-By header at "
            "all, which is what a proxy answering by itself looks like.")

        # -- 3. is any difference from the direct baseline explained? ---
        if direct.status is None:
            report.note(f"{host}: no direct answer ({direct.first_line}); this "
                        "host has no baseline from here.")
            continue
        if direct.status == proxied.status:
            report.note(f"{host}: direct {direct.status} == proxied "
                        f"{proxied.status}; the proxy changed nothing this "
                        "destination reacted to.")
            continue

        redirected = direct.status in REDIRECT_STATUSES and direct.header("Location")
        followed = redirected and proxied.status not in REDIRECT_STATUSES
        if followed:
            follows_redirects = True
        report.check(
            bool(followed),
            f"{host}: the direct/proxied difference ({direct.status} vs "
            f"{proxied.status}) is explained",
            f"direct answered {direct.status} and the proxy returned "
            f"{proxied.status}, and the direct answer was not a redirect the "
            "proxy could have followed. That is an unexplained proxy-side "
            "difference and is worth chasing.")
        if followed:
            report.note(
                f"{host}: the destination answered {direct.status} with "
                f"`Location: {direct.header('Location')}`, and the proxy "
                f"returned {proxied.status} from a different tier — so the "
                "proxy followed the redirect and handed back the response to "
                "the *target*, rather than rewriting the request.")

    report.check(
        bool(witnesses),
        f"{engine}: the request target survives the proxy unchanged "
        f"(witnessed on {', '.join(witnesses) or 'nothing'})",
        "no destination echoed the probe path and the engine logged no line "
        "naming it, so this run establishes nothing about request fidelity for "
        f"{engine}. Re-run when the probe hosts are reachable.")
    report.note(
        f"{engine}: " + ("follows redirects on the plain-HTTP path — the client "
                         "is answered from the redirect target, which is why its "
                         "`allowed-http` status can differ from every other "
                         "engine's without any request being rewritten."
                         if follows_redirects else
                         "returns the destination's own first answer, redirects "
                         "included."))


# ---------------------------------------------------------------------------
# Is a followed redirect's target re-authorized?
# ---------------------------------------------------------------------------
#
# The question the finding above raises, and the one that decides whether
# redirect-following is a convenience or a hole in the allowlist. It needs
# an allowlisted host that redirects to one the policy forbids, and every
# entry in `[policy].allow` is a registry that only redirects to itself —
# so the redirect is real and the *policy* is what has to be narrowed.
#
# `github.com/<o>/<r>/raw/<ref>/<path>` redirects to
# `raw.githubusercontent.com`, a different host. Under a policy that allows
# `github.com` and **not** `*.githubusercontent.com`, an engine that
# re-authorizes each hop must refuse before fetching the file, and one that
# does not will hand the file back. There is no ambiguity in the outcome:
# either the bytes arrive or they do not.
#
# The narrowed policy exists only inside this experiment — it is rendered
# to a temporary file and mounted read-only. config.toml is never touched.
REDIRECT_SOURCE_HOST = "github.com"
REDIRECT_SOURCE_PATH = "/octocat/Hello-World/raw/master/README"
REDIRECT_TARGET_HOST = "raw.githubusercontent.com"
# A string from the file itself, so "did the bytes arrive" is decided by
# the content rather than by a status code the proxy could also produce.
REDIRECT_TARGET_MARKER = "Hello World"


def _experiment_policy(tmp: Path, engine: str, allow_target: bool) -> Path:
    """Render an engine policy for one half of the experiment.

    `allow_target=True` is the control: the same request under a policy
    that permits the redirect target. Without it a refusal proves nothing —
    the request could have failed for any number of reasons that have
    nothing to do with authorization.
    """
    allow = [REDIRECT_SOURCE_HOST, f"*.{REDIRECT_SOURCE_HOST}"]
    if allow_target:
        allow.append(f"*.{REDIRECT_TARGET_HOST.split('.', 1)[1]}")
    config = run_mod.PolicyConfig(allow=tuple(allow), allow_test=())
    rendered = run_mod.render_policies(config)
    spec = run_mod.ServiceSpec.load(engine)
    text = rendered[run_mod.REPO_ROOT / spec.config_file]
    permits = REDIRECT_TARGET_HOST.split(".", 1)[1] in text
    if permits is not allow_target:
        raise RuntimeError(f"the rendered policy {'permits' if permits else 'refuses'} "
                           f"{REDIRECT_TARGET_HOST}, which is not what this half of "
                           "the experiment needs")
    path = tmp / f"{'control-' if allow_target else 'narrowed-'}{Path(spec.config_file).name}"
    path.write_text(text, encoding="utf-8")
    return path


def verify_redirect_authorization(engine: str, port: int, report: Reporter,
                                  backend_name: str) -> None:
    import tempfile

    backend = run_mod.Backend(backend_name)
    spec = run_mod.ServiceSpec.load(engine)
    tmp = Path(tempfile.mkdtemp(prefix="ipl-redirect-authz-"))
    report.note(f"{engine}: {REDIRECT_SOURCE_HOST}{REDIRECT_SOURCE_PATH} redirects "
                f"to {REDIRECT_TARGET_HOST}, a different host")

    def run_half(allow_target: bool) -> Response:
        """Start the engine on one of the two policies and make the request."""
        config = _experiment_policy(tmp, engine, allow_target)
        backend.remove_container(spec.container_name)
        backend.run_detached(
            name=spec.container_name, image=spec.run_image_ref(),
            publish_host="127.0.0.1", publish_port=port,
            internal_port=spec.internal_port,
            mounts=[(config, spec.config_mount)], args=spec.args)
        healthy, detail = False, "timed out"
        deadline = time.monotonic() + run_mod.HEALTH_WAIT_SECONDS
        while time.monotonic() < deadline:
            healthy, detail, retryable = run_mod.probe_proxy("127.0.0.1", port)
            if healthy or not retryable:
                break
            time.sleep(0.5)
        half = "control" if allow_target else "narrowed"
        if not report.check(healthy, f"{engine} started on the {half} policy",
                            f"{detail}\n{backend.tail_logs(spec.container_name)}"):
            return Response(None, {}, "", "engine did not start")
        return request(("127.0.0.1", port),
                       f"http://{REDIRECT_SOURCE_HOST}{REDIRECT_SOURCE_PATH}",
                       REDIRECT_SOURCE_HOST)

    try:
        # Control first. It has to *succeed* — if the target's bytes cannot
        # arrive even when the policy permits them, the refusal below is
        # not evidence of authorization, only of something being broken.
        report.note(f"{engine}: control — policy allows both hosts")
        control = run_half(allow_target=True)
        report.note(f"{engine}: control answered {control.first_line}")
        followed = REDIRECT_TARGET_MARKER in control.body
        if not report.check(
                followed,
                f"{engine}: control — the redirect was followed and "
                f"{REDIRECT_TARGET_HOST}'s bytes arrived",
                f"the control body does not contain {REDIRECT_TARGET_MARKER!r}, so "
                "this engine does not follow redirects at all (Smokescreen and Squid "
                "do not) or the chain has changed upstream. Either way the narrowed "
                "half below cannot distinguish re-authorization from not following."):
            return

        report.note(f"{engine}: narrowed — policy allows {REDIRECT_SOURCE_HOST} but "
                    f"NOT {REDIRECT_TARGET_HOST}")
        narrowed = run_half(allow_target=False)
        report.note(f"{engine}: narrowed answered {narrowed.first_line}")
        arrived = REDIRECT_TARGET_MARKER in narrowed.body
        report.check(
            not arrived,
            f"{engine}: a redirect to the non-allowlisted "
            f"{REDIRECT_TARGET_HOST} was refused — each hop is authorized",
            f"the response body contains {REDIRECT_TARGET_MARKER!r}, so the proxy "
            f"fetched {REDIRECT_TARGET_HOST} — a host this policy does not "
            "allowlist — because an allowlisted host told it to. That makes every "
            "allowlisted host an open redirector and is a full bypass of the "
            "destination allowlist.")
        for line in engine_lines(backend_name, engine, "githubusercontent")[-4:]:
            report.note(f"{engine}: engine log  {line[:220]}")
    finally:
        backend.remove_container(spec.container_name)
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", choices=run_mod.ENGINES, default=None)
    parser.add_argument("--all", action="store_true",
                        help="run against every engine in turn")
    parser.add_argument("--redirect-authz", action="store_true",
                        help="run the redirect re-authorization experiment: start "
                             "the engine on a policy that allows the redirect "
                             "source and not its target, and see whether the "
                             "target's bytes come back")
    parser.add_argument("--running", action="store_true",
                        help="probe the engine that is already up instead of "
                             "starting one")
    parser.add_argument("--backend", choices=run_mod.BACKENDS, default=None)
    parser.add_argument("--port", type=int, default=18080,
                        help="endpoint port (default: 18080)")
    opts = parser.parse_args(argv)

    backend_name = opts.backend or run_mod.detect_backend(None).name
    backend = run_mod.Backend(backend_name)
    report = Reporter("upstream request fidelity")

    if opts.running:
        engine = run_mod.running_engine(backend)
        if not engine:
            print("error: --running was given but no engine is up", file=sys.stderr)
            return 1
        spec = run_mod.ServiceSpec.load(engine)
        published = backend.published_ports(spec.container_name)
        port = published[0][1] if published else opts.port
        verify(engine, port, report, backend_name)
        return report.finish()

    engines = run_mod.ENGINES if opts.all else (opts.engine or run_mod.DEFAULT_ENGINE,)
    env = dict(os.environ, IPL_ENDPOINT=f"127.0.0.1:{opts.port}")
    try:
        for engine in engines:
            if opts.redirect_authz:
                verify_redirect_authorization(engine, opts.port, report, backend_name)
                continue
            engine_up(backend_name, engine, opts.port, test_policy=False, env=env)
            verify(engine, opts.port, report, backend_name)
    finally:
        run_py_down(backend_name, env=env)
    return report.finish()


if __name__ == "__main__":
    sys.exit(main())
