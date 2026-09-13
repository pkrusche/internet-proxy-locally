"""Tests for the operational lane (`ipl`) against a fake backend shim.

A stand-in `docker` executable records every CLI invocation and emulates
just enough state (containers, images) for the lifecycle commands. When it
"starts" a container it actually spawns tests/mock_proxy.py on the test
endpoint, so the post-start health check and `check` run for real.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

REPO_ROOT = Path(__file__).resolve().parent.parent
# The package data the CLI ships with, copied into each test's isolated
# repository and pointed at with IPL_DATA_ROOT.
PACKAGE_DATA = REPO_ROOT / "src" / "internet_proxy_locally" / "data"

# The names each test reaches for, imported from the module that now
# owns them. `run.X` for all of it was one flat namespace; these
# import lines are what the split looks like from outside.
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.constants import DNS_FIXTURE, ENGINES
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.images import IMAGES
from internet_proxy_locally.net import probe_proxy
from internet_proxy_locally.policy.config import PolicyConfig, load_policy_config
from internet_proxy_locally.policy.render import (
    _squid_wild,
    _yaml_scalar,
    render_policies,
)
from internet_proxy_locally.spec import SERVICES, ServiceSpec


def dockerfile(name: str) -> Path:
    """The Dockerfile that defines `name`'s image — and, since the pins
    moved out of Python, every pin it depends on."""
    return PACKAGE_DATA / "images" / name / "Dockerfile"


FAKE_BACKEND = r"""#!/usr/bin/env bash
set -u
echo "$*" >> "$FAKE_LOG"
cmd="${1:-}"; shift || true
case "$cmd" in
  network)
    sub="$1"; shift
    case "$sub" in
      inspect)
        f="$FAKE_STATE/network-$1"
        if [ -f "$f" ]; then cat "$f"; else exit 1; fi
        ;;
      create)
        prev=""; managed=""; workspace=""; role=""; subnet=""; internal=false
        for a in "$@"; do
          if [ "$prev" = "--subnet" ]; then subnet="$a"; fi
          if [ "$a" = "--internal" ]; then internal=true; fi
          if [ "$prev" = "--label" ]; then
            case "$a" in
              io.internet-proxy-locally.managed=*) managed="${a#*=}";;
              io.internet-proxy-locally.workspace=*) workspace="${a#*=}";;
              io.internet-proxy-locally.role=*) role="${a#*=}";;
            esac
          fi
          prev="$a"
        done
        printf '[{"Internal":%s,"IPAM":{"Config":[{"Subnet":"%s"}]},"Labels":{"io.internet-proxy-locally.managed":"%s","io.internet-proxy-locally.workspace":"%s","io.internet-proxy-locally.role":"%s","io.internet-proxy-locally.tls-interception":"false"}}]\n' "$internal" "$subnet" "$managed" "$workspace" "$role" > "$FAKE_STATE/network-$prev"
        ;;
      rm) rm -f "$FAKE_STATE/network-$1" ;;
    esac
    ;;
  inspect)
    f="$FAKE_STATE/container-$1"
    if [ -f "$f" ]; then
      meta="$FAKE_STATE/meta-$1"
      if [ -f "$meta" ]; then cat "$meta"; else
        printf '[{"State": {"Status": "%s"}, "NetworkSettings": {"IPAddress": "172.17.0.9"}}]\n' "$(cat "$f")"
      fi
    else
      exit 1
    fi
    ;;
  image)
    sub="$1"; shift
    case "$sub" in
      inspect)
        key=$(printf '%s' "$1" | tr '/:@' '___')
        f="$FAKE_STATE/image-$key"
        if [ -f "$f" ]; then cat "$f"; else exit 1; fi
        ;;
      *) : ;;
    esac
    ;;
  pull|build|stop) : ;;
  logs)
    if [ "${!#}" = "internet-proxy-dnsfixture" ]; then echo "IPL-FIXTURE ready"; fi
    n_file="$FAKE_STATE/logcalls"
    n=$(( $(cat "$n_file" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$n_file"
    i=1
    while [ "$i" -le "$n" ]; do echo "fake engine log line $i"; i=$((i+1)); done
    ;;
  rm)
    for a in "$@"; do
      [ "$a" = "-f" ] && continue
      p="$FAKE_STATE/pid-$a"
      if [ -f "$p" ]; then kill "$(cat "$p")" 2>/dev/null; rm -f "$p"; fi
      rm -f "$FAKE_STATE/container-$a"
      rm -f "$FAKE_STATE/meta-$a"
    done
    ;;
  run)
    name=""; prev=""; published=""; label_managed=""; label_workspace=""; label_tls="false"; builtin_network=""; custom_network=""
    for a in "$@"; do
      if [ "$prev" = "--network" ]; then
        case "$a" in bridge|host|none) builtin_network=1;; *) custom_network=1;; esac
      fi
      if [ "$prev" = "--name" ]; then name="$a"; fi
      if [ "$a" = "--publish" ]; then published=1; fi
      if [ "$prev" = "--publish" ]; then publication="$a"; fi
      if [ "$prev" = "--label" ]; then
        case "$a" in io.internet-proxy-locally.managed=*) label_managed="${a#*=}";; io.internet-proxy-locally.workspace=*) label_workspace="${a#*=}";; io.internet-proxy-locally.tls-interception=*) label_tls="${a#*=}";; esac
      fi
      prev="$a"
    done
    if [ -n "$builtin_network" ] && [ -n "$custom_network" ]; then
      echo "conflicting options: cannot attach both user-defined and non-user-defined network-modes" >&2
      exit 1
    fi
    echo running > "$FAKE_STATE/container-$name"
    if [ -n "$published" ]; then
      host="${publication%%:*}"; rest="${publication#*:}"; hostport="${rest%%:*}"; containerport="${rest##*:}"
      printf '[{"State":{"Status":"running"},"Config":{"Labels":{"io.internet-proxy-locally.managed":"%s","io.internet-proxy-locally.workspace":"%s","io.internet-proxy-locally.tls-interception":"%s"}},"NetworkSettings":{"IPAddress":"172.17.0.9"},"HostConfig":{"PortBindings":{"%s/tcp":[{"HostIp":"%s","HostPort":"%s"}]}}}]\n' "$label_managed" "$label_workspace" "$label_tls" "$containerport" "$host" "$hostport" > "$FAKE_STATE/meta-$name"
    else
      printf '[{"State":{"Status":"running"},"Config":{"Labels":{"io.internet-proxy-locally.managed":"%s","io.internet-proxy-locally.workspace":"%s","io.internet-proxy-locally.tls-interception":"%s"}},"NetworkSettings":{"IPAddress":"172.17.0.9"}}]\n' "$label_managed" "$label_workspace" "$label_tls" > "$FAKE_STATE/meta-$name"
    fi
    # Only the engine publishes a port; the DNS fixture must not also try
    # to bind the test endpoint.
    if [ -n "${FAKE_PROXY_SPAWN:-}" ] && [ -n "$published" ]; then
      extra=""
      if [ -n "${FAKE_PROXY_CERT:-}" ]; then
        extra="--cert $FAKE_PROXY_CERT --key $FAKE_PROXY_KEY"
      fi
      "$FAKE_PYTHON" "$FAKE_PROXY_SPAWN" --port "$FAKE_PROXY_PORT" --mode strict $extra >/dev/null 2>&1 &
      echo $! > "$FAKE_STATE/pid-$name"
    fi
    echo fakecontainerid
    ;;
  *) : ;;
esac
exit 0
"""


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RunPyCliFixture(unittest.TestCase):
    """Fake-backend setup shared by the operational and lab CLI tests."""

    certdir: Path | None = None

    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl:
            cls.certdir = Path(tempfile.mkdtemp(prefix="ipl-cert-"))
            subprocess.run(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(cls.certdir / "key.pem"),
                    "-out",
                    str(cls.certdir / "cert.pem"),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=mock-proxy.test",
                ],
                check=True,
                capture_output=True,
            )

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.certdir:
            shutil.rmtree(cls.certdir, ignore_errors=True)

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ipl-runpy-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # An isolated repository, made of the two roots paths.py defines:
        # the code under test is the checkout's, but everything it reads or
        # writes is here. That is what lets a test edit a pin, or let `up`
        # regenerate config/, without touching the working tree.
        #
        # The data root carries the templates, the fixture records and the
        # image contexts. data/images/ is not optional: a rendered squid.conf is
        # only valid if every `deny_info` page it names exists in
        # data/images/squid/errors.
        shutil.copytree(PACKAGE_DATA, self.tmp / "data")
        # The workspace root carries config.toml and the rendered configs
        # that `setup` and `up` regenerate from it.
        shutil.copy(REPO_ROOT / "config.toml", self.tmp / "config.toml")
        shutil.copytree(REPO_ROOT / "config", self.tmp / "config")
        # No image is present until a test says so: `up` fails closed on an
        # image that has not been built, and that is what the fail-closed
        # tests below turn on.

        bindir = self.tmp / "bin"
        bindir.mkdir()
        shim = bindir / "docker"
        shim.write_text(FAKE_BACKEND)
        shim.chmod(0o755)

        self.state = self.tmp / "state"
        self.state.mkdir()
        # Registered after the rmtree cleanup above, so it runs before it:
        # the pid files it reads live under self.tmp.
        self.addCleanup(self.reap_spawned_proxies)
        self.log = self.tmp / "backend.log"
        self.log.touch()
        self.port = free_port()
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{bindir}:{self.env['PATH']}",
                "FAKE_LOG": str(self.log),
                "FAKE_STATE": str(self.state),
                "FAKE_PROXY_PORT": str(self.port),
                "FAKE_PROXY_SPAWN": str(REPO_ROOT / "tests" / "mock_proxy.py"),
                "FAKE_PYTHON": os.fspath(Path(sys.executable)),
                "IPL_ENDPOINT": f"127.0.0.1:{self.port}",
                "IPL_ROOT": str(self.tmp),
                "IPL_DATA_ROOT": str(self.tmp / "data"),
            }
        )
        if self.certdir:
            self.env["FAKE_PROXY_CERT"] = str(self.certdir / "cert.pem")
            self.env["FAKE_PROXY_KEY"] = str(self.certdir / "key.pem")

    def run_cli(self, *args: str) -> CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "internet_proxy_locally.cli.run",
                # Auto-detection on macOS can select the host's real Apple
                # runtime instead of the isolated Docker shim.
                "--backend",
                "docker",
                *args,
            ],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=120,
            check=False,
        )

    def fake_image(self, ref: str) -> None:
        """Mark an image as present in the shim's state (its `build` is a no-op)."""
        key = ref.translate(str.maketrans("/:@", "___"))
        (self.state / f"image-{key}").write_text("[{}]\n")

    def build_engine(self, engine: str = "pipelock") -> str:
        """Pretend `setup` has built `engine`'s image, and return its tag.

        Every engine is built from a Dockerfile now, so this replaced three
        different ways of saying "this one is pinned" — a digest written
        into a TOML, a source SHA, an apk version.
        """
        self.fake_image(IMAGES[engine])
        return IMAGES[engine]

    def backend_log(self) -> str:
        return self.log.read_text()

    def reap_spawned_proxies(self) -> None:
        """Kill every mock_proxy the shim spawned for this test.

        The shim kills a container's proxy on `rm`, so a test that ends in
        `down` already cleans up after itself. Most tests deliberately leave
        a container running instead — that is the state they assert on — and
        the spawned proxy is reparented to init when the shim exits, so
        without this it outlives the whole run and holds its port until the
        machine reboots. A full suite leaked upwards of a hundred.
        """
        for pid_file in sorted(self.state.glob("pid-*")):
            try:
                pid = int(pid_file.read_text().strip())
            except (OSError, ValueError):
                continue
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass  # already gone, or never ours
            pid_file.unlink(missing_ok=True)


class RunPyCliTest(RunPyCliFixture):
    """End-to-end operational CLI behavior against the fake backend."""

    # -- fail-closed behavior ----------------------------------------------

    def test_up_refuses_an_engine_whose_image_is_not_built(self) -> None:
        """One rule for all three, where there used to be three.

        Pipelock was pulled by digest and the other two built, so "not
        ready to start" had a different shape and a different message per
        engine. Every image is built from a Dockerfile now.
        """
        for engine in ENGINES:
            with self.subTest(engine=engine):
                self.log.write_text("")
                proc = self.run_cli("--backend", "docker", "--engine", engine, "up")
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("not built yet", proc.stderr)
                self.assertIn(f"--engine {engine} setup", proc.stderr)
                self.assertIn(IMAGES[engine], proc.stderr)
                self.assertNotIn("run --detach", self.backend_log())

    def test_up_regenerates_a_hand_edited_policy(self) -> None:
        """`up` renders config/ from config.toml before mounting it, so a
        hand edit cannot reach a running container."""
        self.build_engine()
        policy = self.tmp / "config" / "pipelock.yaml"
        policy.write_text(
            policy.read_text(encoding="utf-8").replace(
                "  - github.com\n", "  - github.com\n  - evil.example\n"
            ),
            encoding="utf-8",
        )
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("evil.example", policy.read_text(encoding="utf-8"))

    def test_up_is_quiet_when_the_configs_are_current(self) -> None:
        self.build_engine()
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("regenerated", proc.stdout)

    def test_up_propagates_a_new_domain_to_the_engine_config(self) -> None:
        self.build_engine()
        config_toml = self.tmp / "config.toml"
        config_toml.write_text(
            config_toml.read_text(encoding="utf-8").replace(
                '    "github.com",', '    "github.com",\n    "*.example.test",'
            ),
            encoding="utf-8",
        )
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            '  - "*.example.test"',
            (self.tmp / "config" / "pipelock.yaml").read_text(encoding="utf-8"),
        )
        self.assertIn(
            r"dstdom_regex -i \.example\.test$",
            (self.tmp / "config" / "squid.conf").read_text(encoding="utf-8"),
        )
        self.assertIn(
            '    - "*.example.test"',
            (self.tmp / "config" / "smokescreen.yaml").read_text(encoding="utf-8"),
        )

    def test_up_refuses_a_bad_config_toml_and_starts_nothing(self) -> None:
        """A malformed allowlist entry must stop `up` before any container
        runs, and must not damage the configs already on disk."""
        self.build_engine()
        config_toml = self.tmp / "config.toml"
        before = (self.tmp / "config" / "squid.conf").read_text(encoding="utf-8")
        config_toml.write_text(
            config_toml.read_text(encoding="utf-8").replace(
                '    "github.com",', '    "1.2.3.4",'
            ),
            encoding="utf-8",
        )
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("1.2.3.4", proc.stderr)
        self.assertIn("address", proc.stderr)
        self.assertNotIn("run --detach", self.backend_log())
        self.assertEqual(
            (self.tmp / "config" / "squid.conf").read_text(encoding="utf-8"), before
        )

    def test_policy_command_is_unavailable(self) -> None:
        proc = self.run_cli("policy")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid choice", proc.stderr)

    def test_up_refuses_occupied_port(self) -> None:
        self.build_engine()
        self.env["FAKE_PROXY_SPAWN"] = ""  # backend won't serve the port
        with socket.socket() as blocker:
            blocker.bind(("127.0.0.1", self.port))
            blocker.listen(1)
            proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("already in use", proc.stderr)

    def test_up_fails_when_proxy_never_listens(self) -> None:
        self.build_engine()
        self.env["FAKE_PROXY_SPAWN"] = ""
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("health check failed", proc.stderr)

    # -- lifecycle ----------------------------------------------------------

    def test_up_status_check_down_lifecycle(self) -> None:
        self.build_engine()
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn("healthy", up.stdout)

        log = self.backend_log()
        run_line = next(l for l in log.splitlines() if l.startswith("run "))
        self.assertIn("--name internet-proxy-pipelock", run_line)
        self.assertIn(f"--publish 127.0.0.1:{self.port}:8888", run_line)
        self.assertIn(IMAGES["pipelock"], run_line)
        self.assertIn(":/config/pipelock.yaml:ro", run_line)
        self.assertNotIn(":latest", run_line)
        # How the engine is launched is the image's business now — the
        # `run` line ends at the image, with no trailing arguments, and
        # `--listen 0.0.0.0:8888` is a CMD in its Dockerfile.
        self.assertTrue(
            run_line.rstrip().endswith(IMAGES["pipelock"]),
            f"run line carries arguments after the image: {run_line}",
        )

        status = self.run_cli("--backend", "docker", "status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("pipelock: running (active)", status.stdout)
        self.assertIn("proxy check: OK", status.stdout)

        check = self.run_cli("--backend", "docker", "check")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertIn("summary:", check.stdout)

        down = self.run_cli("--backend", "docker", "down")
        self.assertEqual(down.returncode, 0)
        self.assertIn("removed internet-proxy-pipelock", down.stdout)
        self.assertFalse((self.state / "container-internet-proxy-pipelock").exists())

    def test_check_wires_engine_log_capture(self) -> None:
        # `check` should pass --backend-bin/--container through to
        # `checks.egress` so each result's `engine_logs` is populated
        # from the running container's own log stream (docs/security.md,
        # "The adversarial suite").
        self.build_engine()
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)

        check = self.run_cli("--backend", "docker", "check", "--json")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        payload = json.loads(check.stdout)
        results = payload["results"]
        self.assertTrue(results)
        for r in results:
            self.assertTrue(
                r["engine_logs"], f"{r['name']}: expected non-empty engine_logs"
            )
            self.assertTrue(
                all(
                    line.startswith("fake engine log line") for line in r["engine_logs"]
                )
            )

    def test_up_mounts_smokescreen_daemon_config(self) -> None:
        # allow_missing_role has no CLI flag; without this mount every request
        # is rejected before the ACL's `default` rule is reached.
        self.build_engine("smokescreen")
        up = self.run_cli("--backend", "docker", "--engine", "smokescreen", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        run_line = next(
            l for l in self.backend_log().splitlines() if l.startswith("run ")
        )
        self.assertIn(":/etc/smokescreen/acl.yaml:ro", run_line)
        self.assertIn(":/etc/smokescreen/config.yaml:ro", run_line)
        # `--config-file /etc/smokescreen/config.yaml` is a CMD in the
        # image now (asserted in RunPyUnitTest); what this lane still owns
        # is the mount underneath it.
        self.assertTrue(
            run_line.rstrip().endswith(IMAGES["smokescreen"]),
            f"run line carries arguments after the image: {run_line}",
        )

    def test_up_squid_mounts_policy_over_the_stock_config(self) -> None:
        # Squid's whole policy is the bind-mounted file; the image ships no
        # squid.conf, so a mount that did not land would fail closed rather
        # than run a permissive default.
        image = self.build_engine("squid")
        up = self.run_cli("--backend", "docker", "--engine", "squid", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        run_line = next(
            l for l in self.backend_log().splitlines() if l.startswith("run ")
        )
        self.assertIn("--name internet-proxy-squid", run_line)
        self.assertIn(f"--publish 127.0.0.1:{self.port}:3128", run_line)
        self.assertIn(image, run_line)
        self.assertIn(":/etc/squid/squid.conf:ro", run_line)
        self.assertNotIn(":latest", run_line)

    # -- TLS interception (opt-in; docs/tls-interception.md) -----------------

    def test_iron_lifecycle_and_check_identify_engine_and_tls_mode(self) -> None:
        self.build_engine("iron")
        self.assertEqual(self.run_cli("ca", "init").returncode, 0)
        for enabled in (True, False):
            self.log.write_text("")
            args = ["--backend", "docker", "--engine", "iron", "restart"]
            if enabled:
                args.append("--tls-interception")
            up = self.run_cli(*args)
            self.assertEqual(up.returncode, 0, up.stderr)
            text = (self.tmp / "config/iron.yaml").read_text()
            self.assertIn("mode: mitm" if enabled else "mode: sni-only", text)
            run_line = next(
                l for l in self.backend_log().splitlines() if l.startswith("run ")
            )
            self.assertIn(f"--publish 127.0.0.1:{self.port}:1080", run_line)
            self.assertIn(":/config/iron.yaml:ro", run_line)
            self.assertEqual(":/config/ca-key.pem:ro" in run_line, enabled)
            self.assertNotIn("SSL_CERT_FILE", run_line)
            check = self.run_cli("--backend", "docker", "check", "--json")
            self.assertEqual(check.returncode, 0, check.stderr)
            payload = json.loads(check.stdout)
            self.assertEqual(payload["engine"], "iron")
            self.assertEqual(payload["tls_interception"], enabled)
            status = self.run_cli("--backend", "docker", "status")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn("iron: running (active)", status.stdout)
            self.assertEqual(self.run_cli("--backend", "docker", "logs").returncode, 0)
        down = self.run_cli("--backend", "docker", "down")
        self.assertEqual(down.returncode, 0, down.stderr)
        self.assertIn("removed internet-proxy-iron", down.stdout)

    def test_up_fails_closed_on_smokescreen_with_tls_interception(self) -> None:
        self.build_engine("smokescreen")
        self.assertEqual(self.run_cli("ca", "init").returncode, 0)
        proc = self.run_cli(
            "--backend", "docker", "--engine", "smokescreen", "up", "--tls-interception"
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("does not support TLS interception", proc.stderr)
        self.assertNotIn("run --detach", self.backend_log())

    def test_up_fails_closed_with_tls_interception_and_no_ca(self) -> None:
        for engine in ("squid", "iron"):
            with self.subTest(engine=engine):
                self.build_engine(engine)
                proc = self.run_cli(
                    "--backend",
                    "docker",
                    "--engine",
                    engine,
                    "up",
                    "--tls-interception",
                )
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("no CA exists", proc.stderr)
                self.assertNotIn("run --detach", self.backend_log())

    def test_up_mounts_ca_files_when_tls_interception_is_on(self) -> None:
        for engine, cert_mount, key_mount in (
            ("pipelock", "/config/ca.pem", "/config/ca-key.pem"),
            ("squid", "/etc/squid/ca.pem", "/etc/squid/ca-key.pem"),
            ("iron", "/config/ca.pem", "/config/ca-key.pem"),
        ):
            with self.subTest(engine=engine):
                self.log.write_text("")
                self.build_engine(engine)
                self.assertEqual(self.run_cli("ca", "init").returncode, 0)
                proc = self.run_cli(
                    "--backend",
                    "docker",
                    "--engine",
                    engine,
                    "up",
                    "--tls-interception",
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                run_line = next(
                    l for l in self.backend_log().splitlines() if l.startswith("run ")
                )
                self.assertIn(f":{cert_mount}:ro", run_line)
                self.assertIn(f":{key_mount}:ro", run_line)
                self.assertEqual("--user 0:0" in run_line, engine == "squid")
                key = self.tmp / "state/ca/ca-key.pem"
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                self.assertEqual(key.stat().st_uid, os.getuid())

    def test_check_reports_whether_tls_interception_was_on(self) -> None:
        self.build_engine("squid")
        self.assertEqual(self.run_cli("ca", "init").returncode, 0)
        for enabled in (True, False):
            self.log.write_text("")
            args = ["--backend", "docker", "--engine", "squid", "up"]
            if enabled:
                args.append("--tls-interception")
            up = self.run_cli(*args)
            self.assertEqual(up.returncode, 0, up.stderr)
            self.assertEqual("--user 0:0" in self.backend_log(), enabled)

            check = self.run_cli("--backend", "docker", "check", "--json")
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            payload = json.loads(check.stdout)
            self.assertEqual(payload["tls_interception"], enabled)

    def test_restart_without_switch_restores_tunnel_mode(self) -> None:
        self.build_engine("squid")
        self.assertEqual(self.run_cli("ca", "init").returncode, 0)
        for enabled in (True, False):
            self.log.write_text("")
            args = ["--engine", "squid", "restart"]
            if enabled:
                args.append("--tls-interception")
            proc = self.run_cli(*args)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            policy = (self.tmp / "config" / "squid.conf").read_text()
            self.assertEqual("ssl_bump bump bumpable" in policy, enabled)
            self.assertEqual(":/etc/squid/ca-key.pem:ro" in self.backend_log(), enabled)

    def test_ca_init_status_rotate_export(self) -> None:
        status = self.run_cli("ca", "status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("absent", status.stdout)

        init = self.run_cli("ca", "init")
        self.assertEqual(init.returncode, 0, init.stderr)
        self.assertIn("generated", init.stdout)
        cert_path = self.tmp / "state" / "ca" / "ca.pem"
        key_path = self.tmp / "state" / "ca" / "ca-key.pem"
        self.assertTrue(cert_path.is_file())
        self.assertTrue(key_path.is_file())
        first_key = key_path.read_bytes()

        again = self.run_cli("ca", "init")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("already present", again.stdout)
        self.assertEqual(key_path.read_bytes(), first_key)

        status2 = self.run_cli("ca", "status")
        self.assertEqual(status2.returncode, 0, status2.stderr)
        self.assertIn("present", status2.stdout)
        self.assertIn("subject", status2.stdout)

        rebuilt = self.run_cli("ca", "init", "--rebuild")
        self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
        self.assertNotEqual(key_path.read_bytes(), first_key)

        before_rotate = key_path.read_bytes()
        rotate = self.run_cli("ca", "rotate")
        self.assertEqual(rotate.returncode, 0, rotate.stderr)
        self.assertNotEqual(key_path.read_bytes(), before_rotate)

        out = self.tmp / "exported-ca.pem"
        export = self.run_cli("ca", "export", "--out", str(out))
        self.assertEqual(export.returncode, 0, export.stderr)
        self.assertEqual(out.read_bytes(), cert_path.read_bytes())
        self.assertNotEqual(out.read_bytes(), key_path.read_bytes())

    def test_ca_rotation_requires_proxy_down(self) -> None:
        init = self.run_cli("ca", "init")
        self.assertEqual(init.returncode, 0, init.stderr)
        ca_dir = self.tmp / "state" / "ca"
        before = {
            name: (ca_dir / name).read_bytes() for name in ("ca.pem", "ca-key.pem")
        }
        for engine in ENGINES:
            state = self.state / f"container-internet-proxy-{engine}"
            state.write_text("running")
            try:
                for args in (("ca", "rotate"), ("ca", "init", "--rebuild")):
                    with self.subTest(engine=engine, args=args):
                        result = self.run_cli(*args)
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertIn("run `ipl down` first", result.stderr)
                        for name, contents in before.items():
                            self.assertEqual((ca_dir / name).read_bytes(), contents)
            finally:
                state.unlink()

    def test_ca_export_fails_with_no_ca(self) -> None:
        proc = self.run_cli("ca", "export", "--out", str(self.tmp / "out.pem"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no CA exists", proc.stderr)

    def fake_dns_fixture_image(self) -> None:
        self.fake_image(IMAGES[DNS_FIXTURE])

    def test_check_requires_running_engine(self) -> None:
        proc = self.run_cli("--backend", "docker", "check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no engine is running", proc.stderr)

    def test_setup_builds_each_engine_from_its_own_dockerfile(self) -> None:
        """One build path for all three, and nothing pulled.

        Pipelock used to be pulled by digest, and with no digest recorded
        `setup` pulled the mutable tag, read a digest back out and wrote it
        into the TOML — so a fresh checkout ran whatever `3.3.0` pointed at
        that day, recorded after the fact rather than reviewed before it.
        There is no pin for `setup` to resolve any more: the digest is a
        literal in data/images/pipelock/Dockerfile.
        """
        proc = self.run_cli("--backend", "docker", "setup", "--all")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        log = self.backend_log()
        self.assertNotIn("pull", log)
        for engine in ENGINES:
            with self.subTest(engine=engine):
                context = self.tmp / "data" / "images" / engine
                self.assertIn(
                    f"build --tag {IMAGES[engine]} "
                    f"--file {context / 'Dockerfile'} {context}",
                    log,
                )
                self.assertNotIn("--build-arg", log)


class RunPyUnitTest(unittest.TestCase):
    """In-process unit tests for rendering and backend parsing."""

    def _serve_once(self, handler) -> int:
        """Run a one-shot TCP server on a free port; return the port."""
        import threading

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def run() -> None:
            try:
                conn, _ = srv.accept()
                with conn:
                    handler(conn)
            except OSError:
                pass
            finally:
                srv.close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2.0)
        self.addCleanup(srv.close)
        return port

    def test_probe_marks_silent_close_retryable(self) -> None:
        """Docker publishes the port before the engine listens behind it.

        Such a probe is accepted and then closed with no reply. Treating
        that as a verdict failed `up` on a healthy proxy; it must be
        retried instead (see `probe_proxy`'s own docstring for why an
        answering-but-permissive proxy is never retryable).
        """
        port = self._serve_once(lambda conn: conn.close())
        healthy, _, retryable = probe_proxy("127.0.0.1", port, timeout=2.0)
        self.assertFalse(healthy)
        self.assertTrue(retryable)

    def test_probe_marks_permissive_proxy_not_retryable(self) -> None:
        """A proxy that answers and *allows* the probe is enforcing nothing.

        Waiting cannot fix that, so it must fail immediately rather than
        burn the health deadline.
        """

        def handler(conn: socket.socket) -> None:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        port = self._serve_once(handler)
        healthy, detail, retryable = probe_proxy("127.0.0.1", port, timeout=2.0)
        self.assertFalse(healthy)
        self.assertFalse(retryable)
        self.assertIn("NOT healthy", detail)

    def test_probe_accepts_denial_as_healthy(self) -> None:
        def handler(conn: socket.socket) -> None:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

        port = self._serve_once(handler)
        healthy, _, retryable = probe_proxy("127.0.0.1", port, timeout=2.0)
        self.assertTrue(healthy)
        self.assertFalse(retryable)

    def test_probe_recognizes_smokescreen_policy_denial(self) -> None:
        for host in ("ipl-health-probe.invalid", "ipl-health-probe.invalid:80"):
            with self.subTest(host=host):
                reason = (
                    f"Egress proxying is denied to host '{host}': "
                    "default rule policy used."
                )

                def handler(conn: socket.socket, reason: str = reason) -> None:
                    import time

                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
                    # Headers can arrive in a later TCP read than the status.
                    time.sleep(0.02)
                    conn.sendall(
                        f"x-smokescreen-error: {reason}\r\n"
                        "Content-Length: 0\r\n\r\n".encode()
                    )

                port = self._serve_once(handler)
                healthy, detail, retryable = probe_proxy("127.0.0.1", port)
                self.assertTrue(healthy, detail)
                self.assertFalse(retryable)

    def test_probe_rejects_non_policy_errors(self) -> None:
        policy_reason = (
            "Egress proxying is denied to host 'ipl-health-probe.invalid': "
            "default rule policy used."
        )
        for status, reason in (
            (407, ""),
            (407, "Proxy authentication required"),
            (
                407,
                "Egress proxying is denied to host 'ipl-health-probe.invalid': missing role.",
            ),
            (407, policy_reason.replace("ipl-health-probe.invalid", "other.invalid")),
            (502, "Failed to resolve remote hostname: no such host"),
            (502, policy_reason),
        ):
            with self.subTest(status=status, reason=reason):

                def handler(
                    conn: socket.socket, status: int = status, reason: str = reason
                ) -> None:
                    conn.recv(4096)
                    conn.sendall(
                        f"HTTP/1.1 {status} Error\r\n"
                        f"X-Smokescreen-Error: {reason}\r\n"
                        "Content-Length: 0\r\n\r\n".encode()
                    )

                port = self._serve_once(handler)
                healthy, detail, retryable = probe_proxy("127.0.0.1", port)
                self.assertFalse(healthy)
                self.assertFalse(retryable)
                self.assertIn("non-policy error", detail)

    def test_every_declared_entry_point_resolves(self) -> None:
        """The docs say `uv run ipl ...`, so every name they say has to exist.

        These used to be shebang scripts, and this test asserted the
        shebang was `uv run` rather than `python3` — with the latter they
        would have picked up whatever interpreter was on PATH, no Jinja,
        and the failure would have landed on whoever was least
        equipped to read it. uv still resolves both the interpreter
        (.python-version) and the dependencies (pyproject.toml); what it
        resolves them for is now `[project.scripts]`, so that is what has
        to be checked. A console script naming a module that does not
        import fails at `uv sync` time for a user and never here.
        """
        import importlib
        import tomllib

        with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
            scripts = tomllib.load(fh)["project"]["scripts"]
        self.assertIn("ipl", scripts, "the operational lane must stay `ipl`")
        for name, target in sorted(scripts.items()):
            module_name, _, attr = target.partition(":")
            module = importlib.import_module(module_name)
            self.assertTrue(
                callable(getattr(module, attr, None)),
                f"{name} = {target}: not callable",
            )

    # --- config.toml -> config/* generation --------------------------------

    def policy_config(self, allow):
        """A config.toml on disk holding the given lists."""
        tmp = Path(tempfile.mkdtemp(prefix="ipl-config-toml-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "config.toml"
        # TOML literal strings: the bad-entry cases include backslashes,
        # which a basic string would reject before the loader sees them.
        body = "[policy]\nallow = [\n"
        body += "".join(f"    '{entry}',\n" for entry in allow)
        body += "]\n"
        path.write_text(body)
        return path

    def test_shipped_configs_match_config_toml(self) -> None:
        """The committed configs must be exactly what config.toml renders.

        This is the guard that makes the generator the source of truth: a
        hand edit to config/, or a config.toml change committed without
        regenerating, fails here rather than silently shipping a policy
        nobody reviewed.
        """
        for path, body in sorted(render_policies().items()):
            rel = path.relative_to(REPO_ROOT)
            self.assertTrue(path.is_file(), f"{rel} is missing")
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                body,
                f"{rel} is stale — run `ipl up` and commit the result",
            )

    def test_config_rejects_old_tls_setting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                '[policy]\nallow = ["github.com"]\ntls_interception = true\n'
            )
            with self.assertRaisesRegex(Fail, "unknown.*tls_interception"):
                load_policy_config(path)

    def test_generated_policies_include_tls_interception_recipe(self) -> None:
        rendered = render_policies(tls_interception=True)
        pipelock_text = rendered[REPO_ROOT / "config" / "pipelock.yaml"]
        self.assertIn("enabled: true", pipelock_text)
        squid_text = rendered[REPO_ROOT / "config" / "squid.conf"]
        self.assertIn("ssl_bump peek step1 bumpable", squid_text)
        self.assertIn("ssl_bump bump bumpable", squid_text)

    def test_the_peek_is_gated_by_the_floors_it_sits_below(self) -> None:
        """Only destinations `http_access` would allow may be peeked."""
        squid_text = render_policies(tls_interception=True)[
            REPO_ROOT / "config" / "squid.conf"
        ]
        gate = "bumpable TLS_ports !metadata_ip !private_ip !ip_literal"
        self.assertIn(f"ssl_bump peek step1 {gate}", squid_text)
        self.assertIn(f"ssl_bump bump {gate}", squid_text)
        # The fallback must be an ordinary tunnel, which http_access denies
        # with a page — never `terminate`, which aborts just like a peek.
        rules = [l for l in squid_text.splitlines() if l.startswith("ssl_bump ")]
        self.assertEqual(rules[-1], "ssl_bump splice all")

    def test_squid_wildcard_filter_renders_an_anchored_suffix(self) -> None:
        pattern = re.compile(_squid_wild("*.github.com"))
        for hostname in ("api.github.com", "nested.api.github.com"):
            with self.subTest(hostname=hostname):
                self.assertIsNotNone(pattern.search(hostname))
        for hostname in ("github.com", "notgithub.com", "github.com.example"):
            with self.subTest(hostname=hostname):
                self.assertIsNone(pattern.search(hostname))

    def test_yaml_scalar_quotes_wildcards(self) -> None:
        # A bare leading `*` is a YAML alias, not a string.
        self.assertEqual(_yaml_scalar("*.github.com"), '"*.github.com"')
        self.assertEqual(_yaml_scalar("github.com"), "github.com")

    def test_config_toml_rejects_bad_entries(self) -> None:
        """Every rejection here is a policy that would otherwise be wrong in a
        way no engine would complain about."""
        cases = {
            # Address-form entries are what `http_access deny ip_literal`
            # exists to refuse; this policy allowlists by name only.
            "1.2.3.4": "address",
            # `.d` is Squid's own form and covers the apex too — silently
            # wider than the `*.d` the shared policy means.
            ".github.com": "allowlist form",
            # A hand-written regex would be emitted verbatim into squid.conf
            # and read back as drift by every other engine.
            r"\.github\.com$": "allowlist form",
            "*github.com": "allowlist form",
            "localhost": "allowlist form",  # single label; `dns_defnames off`
            "github.com:443": "allowlist form",
            "https://github.com": "allowlist form",
            "*.github.com/path": "allowlist form",
        }
        for entry, expected in cases.items():
            path = self.policy_config([entry])
            with self.assertRaises(Fail, msg=f"{entry} was accepted") as ctx:
                load_policy_config(path)
            self.assertIn(expected, str(ctx.exception), entry)

    def test_config_toml_rejects_an_empty_allowlist(self) -> None:
        path = self.policy_config([])
        with self.assertRaises(Fail) as ctx:
            load_policy_config(path)
        self.assertIn("must not be empty", str(ctx.exception))

    def test_config_toml_rejects_duplicates_and_typos(self) -> None:
        dupe = self.policy_config(["github.com", "github.com"])
        with self.assertRaises(Fail) as ctx:
            load_policy_config(dupe)
        self.assertIn("twice", str(ctx.exception))

        # `allows = [...]` would otherwise render an empty allowlist.
        typo = self.policy_config(["github.com"])
        typo.write_text(typo.read_text().replace("[policy]\nallow", "[policy]\nallows"))
        with self.assertRaises(Fail) as ctx:
            load_policy_config(typo)
        self.assertIn("unknown key", str(ctx.exception))

    def test_generation_survives_a_new_domain(self) -> None:
        """An added domain must reach all three engines in the right form."""
        config = PolicyConfig(allow=("github.com", "*.example.test"))
        rendered = render_policies(config)
        squid = rendered[REPO_ROOT / "config" / "squid.conf"]
        self.assertIn(r"acl allowlist_wild dstdom_regex -i \.example\.test$", squid)
        self.assertIn("acl allowlist_exact dstdomain github.com", squid)
        self.assertIn(
            '  - "*.example.test"', rendered[REPO_ROOT / "config" / "pipelock.yaml"]
        )
        self.assertIn(
            '    - "*.example.test"',
            rendered[REPO_ROOT / "config" / "smokescreen.yaml"],
        )

    def test_container_ip_parses_docker_and_apple_shapes(self) -> None:

        def fake(payload, returncode=0):
            backend = Backend("docker")
            backend._run = lambda *a, **k: CompletedProcess(  # ty: ignore[invalid-assignment]
                a, returncode, stdout=payload, stderr=""
            )
            return backend

        docker_flat = json.dumps([{"NetworkSettings": {"IPAddress": "172.17.0.4"}}])
        docker_named = json.dumps(
            [
                {
                    "NetworkSettings": {
                        "IPAddress": "",
                        "Networks": {"bridge": {"IPAddress": "172.18.0.7"}},
                    }
                }
            ]
        )
        # Apple `container` reports a CIDR, which has to be trimmed.
        apple = json.dumps(
            [{"status": {"networks": [{"ipv4Address": "192.168.64.38/24"}]}}]
        )
        self.assertEqual(fake(docker_flat).container_ip("x"), "172.17.0.4")
        self.assertEqual(fake(docker_named).container_ip("x"), "172.18.0.7")
        self.assertEqual(fake(apple).container_ip("x"), "192.168.64.38")
        self.assertEqual(fake("", returncode=1).container_ip("x"), "")

    def test_published_ports_parses_docker_and_apple_shapes(self) -> None:
        """The loopback binding is one `--publish` argument, and reading it
        back lets startup confirm the runtime honored it."""

        def fake(payload, returncode=0):
            backend = Backend("docker")
            backend._run = lambda *a, **k: CompletedProcess(  # ty: ignore[invalid-assignment]
                a, returncode, stdout=payload, stderr=""
            )
            return backend

        docker = json.dumps(
            [
                {
                    "HostConfig": {
                        "PortBindings": {
                            "8888/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]
                        }
                    }
                }
            ]
        )
        apple = json.dumps(
            [
                {
                    "configuration": {
                        "publishedPorts": [
                            {
                                "containerPort": 8888,
                                "hostAddress": "127.0.0.1",
                                "hostPort": 18080,
                                "proto": "tcp",
                            }
                        ]
                    }
                }
            ]
        )
        # The shape this exists to catch: bound to every interface.
        wide = json.dumps(
            [
                {
                    "HostConfig": {
                        "PortBindings": {
                            "8888/tcp": [{"HostIp": "", "HostPort": "18080"}]
                        }
                    }
                }
            ]
        )
        self.assertEqual(
            fake(docker).published_ports("x"), [("127.0.0.1", 18080, 8888)]
        )
        self.assertEqual(fake(apple).published_ports("x"), [("127.0.0.1", 18080, 8888)])
        self.assertEqual(fake(wide).published_ports("x"), [("", 18080, 8888)])
        self.assertEqual(fake("", returncode=1).published_ports("x"), [])
        self.assertEqual(fake(json.dumps([{}])).published_ports("x"), [])

    # -- pins, which live in the Dockerfiles --------------------------------

    def test_every_image_has_a_build_context(self) -> None:
        """Every service `SERVICES` names is built from data/images/<name>/.

        This is what `prepare_image` assumes instead of branching per
        service, and what makes "which image" have one answer.
        """
        self.assertEqual(set(IMAGES), set(SERVICES))
        for name, spec in SERVICES.items():
            with self.subTest(name=name):
                self.assertEqual(spec.image, IMAGES[name])
                self.assertTrue(dockerfile(name).is_file(), f"no Dockerfile for {name}")

    def test_every_from_line_is_pinned(self) -> None:
        """No floating base images, and no `latest`.

        `up` used to refuse an unpinned service spec at run time. The pins
        are literals in the Dockerfiles now, so this is where that
        guarantee lives — and it covers the base images too, which the
        run-time check never did.
        """
        pinned = re.compile(
            r"^[\w./-]+"
            r"(@sha256:[0-9a-f]{64}"  # a digest, or
            r"|:[\w][\w.-]*)$"  # an explicit non-latest tag
        )
        for name in IMAGES:
            for line in dockerfile(name).read_text().splitlines():
                if not line.startswith("FROM "):
                    continue
                with self.subTest(name=name, line=line):
                    ref = line.split()[1]
                    self.assertNotIn("${", ref, "FROM must not take a build arg")
                    self.assertNotIn(":latest", ref)
                    self.assertRegex(ref, pinned)

    def test_every_apk_package_is_pinned(self) -> None:
        """`apk add pkg` installs whatever the index says today.

        The Dockerfiles used to guard this themselves, with a `grep -Eq`
        over a build arg. There is no build arg left to check, so the
        check moved here — where it reads the line that actually runs.
        """
        version = re.compile(r"^[\w.+-]+=\d[\w.]*-r\d+$")
        # The base image's own build tooling, not part of what the proxy is:
        # these carry no version and are not what an upgrade is about.
        unversioned = {"ca-certificates", "git"}
        found = 0
        for name in IMAGES:
            for line in dockerfile(name).read_text().splitlines():
                # Instructions only — "apk add" appears in the prose above
                # them too, and a comment installs nothing.
                if line.lstrip().startswith("#") or "apk add" not in line:
                    continue
                packages = line.split("apk add", 1)[1].replace('"', "").split()
                for package in packages:
                    if package.startswith("-") or package in ("&&", "\\"):
                        continue
                    if package in unversioned:
                        continue
                    with self.subTest(name=name, package=package):
                        self.assertRegex(package, version)
                    found += 1
        self.assertTrue(found, "no pinned apk package found in any Dockerfile")

    def test_image_tags_match_the_pins_they_name(self) -> None:
        """The tag constant is what `setup` skips a rebuild on, so a
        Dockerfile edited without bumping it would leave the old image
        running. This is that mistake, as a red test."""
        for image, package in (("squid", "squid"), (DNS_FIXTURE, "dnsmasq")):
            with self.subTest(image=image):
                tag = IMAGES[image].rpartition(":")[2]
                match = re.fullmatch(r"([\w.]+-r\d+)(?:-build\d+)?", tag)
                self.assertIsNotNone(match, f"invalid apk-based image tag: {tag!r}")
                assert match is not None
                self.assertIn(
                    f'"{package}={match.group(1)}"', dockerfile(image).read_text()
                )

        smokescreen = dockerfile("smokescreen").read_text()
        sha = re.search(r"checkout --detach ([0-9a-f]{40})", smokescreen)
        self.assertIsNotNone(sha, "no pinned commit in the smokescreen Dockerfile")
        assert sha is not None
        self.assertEqual(
            IMAGES["smokescreen"].rpartition(":")[2], sha.group(1)[:12] + "-build1"
        )

        pipelock = dockerfile("pipelock").read_text()
        self.assertIn(f"# pipelock {IMAGES['pipelock'].rpartition(':')[2]}", pipelock)

    def test_smokescreen_setup_rebuilds_when_only_pre_cmd_image_exists(self) -> None:
        from unittest.mock import Mock

        from internet_proxy_locally.images import prepare_image

        backend = Mock(spec=Backend)
        backend.image_present.side_effect = lambda tag: (
            tag == "internet-proxy-locally/smokescreen:131fba29ce1e"
        )
        prepare_image(backend, "smokescreen")
        backend.build.assert_called_once_with(
            tag=IMAGES["smokescreen"],
            dockerfile=dockerfile("smokescreen"),
            context=dockerfile("smokescreen").parent,
        )

    def test_no_dockerfile_disables_private_range_blocking(self) -> None:
        """The launch arguments moved from the service specs into CMD, and
        the guard that refused these two flags moved with them."""
        for name in IMAGES:
            with self.subTest(name=name):
                text = dockerfile(name).read_text()
                self.assertNotIn("--unsafe-allow-private-ranges", text)
                self.assertNotIn("--danger-allow-access-to-private-ranges", text)

    def test_the_engines_are_launched_by_their_images(self) -> None:
        """`run_detached` passes no trailing arguments, so every engine has
        to carry its own command."""
        for engine in ENGINES:
            with self.subTest(engine=engine):
                text = dockerfile(engine).read_text()
                self.assertTrue(
                    "ENTRYPOINT" in text or "CMD" in text,
                    f"{engine}: nothing launches the process",
                )
        self.assertIn("--egress-acl-file", dockerfile("smokescreen").read_text())
        self.assertIn("--listen", dockerfile("pipelock").read_text())

    # -- [fixture] in config.toml -------------------------------------------

    def test_container_state_parses_docker_and_apple_shapes(self) -> None:

        def fake(payload, returncode=0):
            backend = Backend("docker")
            backend._run = lambda *a, **k: CompletedProcess(  # ty: ignore[invalid-assignment]
                a, returncode, stdout=payload, stderr=""
            )
            return backend

        docker_shape = json.dumps([{"State": {"Status": "running"}}])
        apple_shape = json.dumps([{"status": "running", "configuration": {}}])
        stopped = json.dumps([{"State": {"Status": "exited"}}])
        self.assertEqual(fake(docker_shape).container_state("x"), "running")
        self.assertEqual(fake(apple_shape).container_state("x"), "running")
        self.assertEqual(fake(stopped).container_state("x"), "stopped")
        self.assertEqual(fake("", returncode=1).container_state("x"), "absent")

    def test_every_engine_has_a_shipped_config(self) -> None:
        for engine in ENGINES:
            spec = ServiceSpec.load(engine)
            self.assertTrue(spec.config_path().is_file())
            # The `.test` variant belongs to the other lane and must not be
            # reachable from a service definition any more.
            self.assertFalse(hasattr(spec, "test_config_file"))

    def test_an_unknown_service_fails_loudly(self) -> None:
        with self.assertRaises(Fail):
            ServiceSpec.load("nginx")


if __name__ == "__main__":
    unittest.main()
