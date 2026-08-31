"""Tests for run.py using a fake container-backend shim.

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
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

REPO_ROOT = Path(__file__).resolve().parent.parent

# Run from the repository root (`python -m unittest discover -s tests -t .`),
# so everything imports by name. See the comment in scripts/harness.py.
import run  # noqa: E402
from tests import quiet  # noqa: E402

FAKE_BACKEND = r"""#!/usr/bin/env bash
set -u
echo "$*" >> "$FAKE_LOG"
cmd="${1:-}"; shift || true
case "$cmd" in
  inspect)
    f="$FAKE_STATE/container-$1"
    if [ -f "$f" ]; then
      printf '[{"State": {"Status": "%s"}, "NetworkSettings": {"IPAddress": "172.17.0.9"}}]\n' "$(cat "$f")"
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
    done
    ;;
  run)
    name=""; prev=""; published=""
    for a in "$@"; do
      if [ "$prev" = "--name" ]; then name="$a"; fi
      if [ "$a" = "--publish" ]; then published=1; fi
      prev="$a"
    done
    echo running > "$FAKE_STATE/container-$name"
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


class RunPyCliTest(unittest.TestCase):
    """End-to-end CLI behavior against the fake backend."""

    certdir: Path | None = None

    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl:
            cls.certdir = Path(tempfile.mkdtemp(prefix="ipl-cert-"))
            subprocess.run(
                [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(cls.certdir / "key.pem"),
                 "-out", str(cls.certdir / "cert.pem"), "-days", "1",
                 "-subj", "/CN=mock-proxy.test"],
                check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.certdir:
            shutil.rmtree(cls.certdir, ignore_errors=True)

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ipl-runpy-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # Minimal repo copy so pins can be edited without touching the checkout.
        shutil.copy(REPO_ROOT / "run.py", self.tmp / "run.py")
        # config.toml and templates/ come too: `setup` and `up` regenerate
        # config/ from them, so a copy missing either would fail before it
        # reached the behavior under test.
        shutil.copy(REPO_ROOT / "config.toml", self.tmp / "config.toml")
        # images/ comes too: a rendered squid.conf is only valid if every
        # `deny_info` page it names exists in images/squid/errors.
        for sub in ("services", "config", "templates", "images"):
            shutil.copytree(REPO_ROOT / sub, self.tmp / sub)
        # Start from unpinned service specs regardless of what the checkout
        # currently pins, so the fail-closed tests stay meaningful and the
        # tests that need a pin set one explicitly.
        self.unpin("pipelock", "digest")
        self.unpin("smokescreen", "ref")
        self.unpin("squid", "squid")
        (self.tmp / "checks").mkdir()
        shutil.copy(REPO_ROOT / "checks" / "egress.py", self.tmp / "checks" / "egress.py")

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
        self.env.update({
            "PATH": f"{bindir}:{self.env['PATH']}",
            "FAKE_LOG": str(self.log),
            "FAKE_STATE": str(self.state),
            "FAKE_PROXY_PORT": str(self.port),
            "FAKE_PROXY_SPAWN": str(REPO_ROOT / "tests" / "mock_proxy.py"),
            "FAKE_PYTHON": os.fspath(Path(os.sys.executable)),
            "IPL_ENDPOINT": f"127.0.0.1:{self.port}",
        })
        if self.certdir:
            self.env["FAKE_PROXY_CERT"] = str(self.certdir / "cert.pem")
            self.env["FAKE_PROXY_KEY"] = str(self.certdir / "key.pem")

    def run_cli(self, *args: str) -> CompletedProcess:
        return subprocess.run(
            [os.sys.executable, str(self.tmp / "run.py"), *args],
            capture_output=True, text=True, env=self.env, timeout=120)

    def unpin(self, engine: str, key: str) -> None:
        toml = self.tmp / "services" / f"{engine}.toml"
        text, count = re.subn(rf'^{key} = ".*"$', f'{key} = ""',
                              toml.read_text(), count=1, flags=re.M)
        if count != 1:
            raise AssertionError(f"no `{key}` pin found in services/{engine}.toml")
        toml.write_text(text)

    def pin_pipelock(self, digest: str = "sha256:" + "ab" * 32) -> None:
        toml = self.tmp / "services" / "pipelock.toml"
        toml.write_text(re.sub(r'^digest = ""$', f'digest = "{digest}"',
                               toml.read_text(), flags=re.M))

    def fake_image(self, ref: str) -> None:
        """Mark an image as present in the shim's state (its `build` is a no-op)."""
        key = ref.translate(str.maketrans("/:@", "___"))
        (self.state / f"image-{key}").write_text("[{}]\n")

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

    # -- fail-closed behavior ----------------------------------------------

    def test_up_refuses_unpinned_pipelock(self) -> None:
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("pin pipelock", proc.stderr)
        self.assertNotIn("run --detach", self.backend_log())

    def test_up_refuses_unpinned_smokescreen(self) -> None:
        proc = self.run_cli("--backend", "docker", "--engine", "smokescreen", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("pin smokescreen", proc.stderr)

    def test_up_refuses_unpinned_squid(self) -> None:
        proc = self.run_cli("--backend", "docker", "--engine", "squid", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("pin squid", proc.stderr)
        self.assertNotIn("run --detach", self.backend_log())

    def test_up_regenerates_a_hand_edited_policy(self) -> None:
        """`up` renders config/ from config.toml before mounting it, so a
        hand edit cannot reach a running container."""
        self.pin_pipelock()
        policy = self.tmp / "config" / "pipelock.yaml"
        policy.write_text(policy.read_text(encoding="utf-8")
                          .replace("  - github.com\n", "  - github.com\n  - evil.example\n"),
                          encoding="utf-8")
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("regenerated config/pipelock.yaml", proc.stdout)
        self.assertNotIn("evil.example", policy.read_text(encoding="utf-8"))

    def test_up_is_quiet_when_the_configs_are_current(self) -> None:
        self.pin_pipelock()
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("regenerated", proc.stdout)

    def test_up_propagates_a_new_domain_to_the_engine_config(self) -> None:
        self.pin_pipelock()
        config_toml = self.tmp / "config.toml"
        config_toml.write_text(
            config_toml.read_text(encoding="utf-8")
            .replace('    "github.com",', '    "github.com",\n    "*.example.test",'),
            encoding="utf-8")
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('  - "*.example.test"',
                      (self.tmp / "config" / "pipelock.yaml").read_text(encoding="utf-8"))
        self.assertIn(r"dstdom_regex -i \.example\.test$",
                      (self.tmp / "config" / "squid.conf").read_text(encoding="utf-8"))
        self.assertIn('    - "*.example.test"',
                      (self.tmp / "config" / "smokescreen.yaml").read_text(encoding="utf-8"))

    def test_up_refuses_a_bad_config_toml_and_starts_nothing(self) -> None:
        """A malformed allowlist entry must stop `up` before any container
        runs, and must not damage the configs already on disk."""
        self.pin_pipelock()
        config_toml = self.tmp / "config.toml"
        before = (self.tmp / "config" / "squid.conf").read_text(encoding="utf-8")
        config_toml.write_text(
            config_toml.read_text(encoding="utf-8")
            .replace('    "github.com",', '    "1.2.3.4",'), encoding="utf-8")
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("1.2.3.4", proc.stderr)
        self.assertIn("address", proc.stderr)
        self.assertNotIn("run --detach", self.backend_log())
        self.assertEqual((self.tmp / "config" / "squid.conf").read_text(encoding="utf-8"),
                         before)

    def test_policy_check_reports_drift_without_writing(self) -> None:
        policy = self.tmp / "config" / "squid.conf"
        policy.write_text(policy.read_text(encoding="utf-8") + "\n# stray edit\n",
                          encoding="utf-8")
        proc = self.run_cli("policy", "--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("STALE", proc.stderr)
        self.assertIn("stray edit", proc.stdout)  # shown as a diff
        self.assertIn("# stray edit", policy.read_text(encoding="utf-8"))

        proc = self.run_cli("policy")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("# stray edit", policy.read_text(encoding="utf-8"))
        self.assertEqual(self.run_cli("policy", "--check").returncode, 0)

    def test_up_refuses_occupied_port(self) -> None:
        self.pin_pipelock()
        self.env["FAKE_PROXY_SPAWN"] = ""  # backend won't serve the port
        with socket.socket() as blocker:
            blocker.bind(("127.0.0.1", self.port))
            blocker.listen(1)
            proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("already in use", proc.stderr)

    def test_up_fails_when_proxy_never_listens(self) -> None:
        self.pin_pipelock()
        self.env["FAKE_PROXY_SPAWN"] = ""
        proc = self.run_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("health check failed", proc.stderr)

    # -- lifecycle ----------------------------------------------------------

    def test_up_status_check_down_lifecycle(self) -> None:
        self.pin_pipelock()
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn("healthy", up.stdout)

        log = self.backend_log()
        run_line = next(l for l in log.splitlines() if l.startswith("run "))
        self.assertIn("--name internet-proxy-pipelock", run_line)
        self.assertIn(f"--publish 127.0.0.1:{self.port}:8888", run_line)
        self.assertIn("@sha256:", run_line)
        self.assertIn(":/config/pipelock.yaml:ro", run_line)
        self.assertIn("--listen 0.0.0.0:8888", run_line)
        self.assertNotIn(":latest", run_line)

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
        # checks/egress.py so each result's `engine_logs` is populated
        # from the running container's own log stream (docs/security.md,
        # "The adversarial suite").
        self.pin_pipelock()
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)

        check = self.run_cli("--backend", "docker", "check", "--json")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        payload = json.loads(check.stdout)
        results = payload["results"]
        self.assertTrue(results)
        for r in results:
            self.assertTrue(r["engine_logs"], f"{r['name']}: expected non-empty engine_logs")
            self.assertTrue(all(line.startswith("fake engine log line") for line in r["engine_logs"]))

    def test_up_mounts_smokescreen_daemon_config(self) -> None:
        # allow_missing_role has no CLI flag; without this mount every request
        # is rejected before the ACL's `default` rule is reached.
        sha = "c" * 40
        toml = self.tmp / "services" / "smokescreen.toml"
        toml.write_text(re.sub(r'^ref = ""$', f'ref = "{sha}"',
                               toml.read_text(), flags=re.M))
        self.fake_image(f"internet-proxy-locally/smokescreen:{sha[:12]}")
        up = self.run_cli("--backend", "docker", "--engine", "smokescreen", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        run_line = next(l for l in self.backend_log().splitlines() if l.startswith("run "))
        self.assertIn(":/etc/smokescreen/acl.yaml:ro", run_line)
        self.assertIn(":/etc/smokescreen/config.yaml:ro", run_line)
        self.assertIn("--config-file /etc/smokescreen/config.yaml", run_line)

    def test_up_squid_mounts_policy_over_the_stock_config(self) -> None:
        # Squid's whole policy is the bind-mounted file; the image ships no
        # squid.conf, so a mount that did not land would fail closed rather
        # than run a permissive default.
        version = "6.12-r0"
        toml = self.tmp / "services" / "squid.toml"
        toml.write_text(re.sub(r'^squid = ""$', f'squid = "{version}"',
                               toml.read_text(), flags=re.M))
        self.fake_image(f"internet-proxy-locally/squid:{version}")
        up = self.run_cli("--backend", "docker", "--engine", "squid", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        run_line = next(l for l in self.backend_log().splitlines() if l.startswith("run "))
        self.assertIn("--name internet-proxy-squid", run_line)
        self.assertIn(f"--publish 127.0.0.1:{self.port}:3128", run_line)
        self.assertIn(f"internet-proxy-locally/squid:{version}", run_line)
        self.assertIn(":/etc/squid/squid.conf:ro", run_line)
        self.assertNotIn(":latest", run_line)

    def test_up_squid_refuses_unbuilt_image(self) -> None:
        toml = self.tmp / "services" / "squid.toml"
        toml.write_text(re.sub(r'^squid = ""$', 'squid = "6.12-r0"',
                               toml.read_text(), flags=re.M))
        proc = self.run_cli("--backend", "docker", "--engine", "squid", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not built yet", proc.stderr)
        self.assertIn("--engine squid setup", proc.stderr)

    def fake_dns_fixture_image(self) -> None:
        self.fake_image("internet-proxy-locally/dnsfixture:2.91-r1")

    def test_check_requires_running_engine(self) -> None:
        proc = self.run_cli("--backend", "docker", "check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no engine is running", proc.stderr)


    def test_setup_is_fail_closed_for_every_pin_kind(self) -> None:
        """`setup` never resolves a pin itself, whatever the pin is.

        It used to, for Pipelock alone: with no digest recorded it pulled
        the mutable tag, read a digest back out and wrote it into the
        TOML. So a fresh checkout ran whatever `3.3.0` pointed at that
        day, recorded after the fact rather than reviewed before it, while
        the other two refused and pointed at `pin`. Now all three refuse,
        and each says how to pin the thing it is pinned by.
        """
        # setUp() blanks all three; the key is what each is pinned *by*.
        for engine, key in (("pipelock", "digest"), ("smokescreen", "ref"),
                            ("squid", "squid")):
            with self.subTest(engine=engine):
                proc = self.run_cli("--engine", engine, "setup")
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                combined = proc.stdout + proc.stderr
                self.assertIn("not pinned", combined)
                self.assertIn(f"./run.py pin {engine}", combined)
                # And nothing was written back into the pin file.
                text = (self.tmp / "services" / f"{engine}.toml").read_text()
                self.assertIn(f'{key} = ""', text,
                              f"setup recorded a {engine} pin instead of refusing")

class RunPyUnitTest(unittest.TestCase):
    """In-process unit tests for policy validation and backend parsing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.run_mod = run

    def write(self, text: str) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="ipl-policy-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "policy.yaml"
        path.write_text(text)
        return path

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
        healthy, _, retryable = self.run_mod.probe_proxy("127.0.0.1", port, timeout=2.0)
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
        healthy, detail, retryable = self.run_mod.probe_proxy("127.0.0.1", port, timeout=2.0)
        self.assertFalse(healthy)
        self.assertFalse(retryable)
        self.assertIn("NOT healthy", detail)

    def test_probe_accepts_denial_as_healthy(self) -> None:
        def handler(conn: socket.socket) -> None:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

        port = self._serve_once(handler)
        healthy, _, retryable = self.run_mod.probe_proxy("127.0.0.1", port, timeout=2.0)
        self.assertTrue(healthy)
        self.assertFalse(retryable)

    def test_shipped_policies_are_valid(self) -> None:
        for engine, rel in (("pipelock", "config/pipelock.yaml"),
                            ("smokescreen", "config/smokescreen.yaml"),
                            ("squid", "config/squid.conf")):
            problems = self.run_mod.validate_policy_file(engine, REPO_ROOT / rel)
            self.assertEqual(problems, [], f"{rel}: {problems}")

    def test_pipelock_policy_rejects_non_strict(self) -> None:
        path = self.write((REPO_ROOT / "config" / "pipelock.yaml").read_text()
                          .replace("mode: strict", "mode: monitor")
                          .replace("enforce: true", "enforce: false"))
        problems = self.run_mod.validate_policy_file("pipelock", path)
        self.assertTrue(any("mode: strict" in p for p in problems))
        self.assertTrue(any("enforce" in p for p in problems))

    def test_pipelock_policy_rejects_tls_interception(self) -> None:
        path = self.write((REPO_ROOT / "config" / "pipelock.yaml").read_text()
                          .replace("tls_interception:\n  enabled: false",
                                   "tls_interception:\n  enabled: true"))
        problems = self.run_mod.validate_policy_file("pipelock", path)
        self.assertTrue(any("tls_interception" in p for p in problems))

    def test_smokescreen_policy_rejects_open_mode(self) -> None:
        path = self.write((REPO_ROOT / "config" / "smokescreen.yaml").read_text()
                          .replace("action: enforce", "action: open"))
        problems = self.run_mod.validate_policy_file("smokescreen", path)
        self.assertTrue(any("open" in p for p in problems))

    def test_smokescreen_policy_requires_allowlist(self) -> None:
        text = re.sub(r"^\s+- .*$", "", (REPO_ROOT / "config" / "smokescreen.yaml").read_text(), flags=re.M)
        problems = self.run_mod.validate_policy_file("smokescreen", self.write(text))
        self.assertTrue(any("allowed_domains" in p for p in problems))

    def test_every_entry_point_runs_through_uv(self) -> None:
        """The docs say `./run.py ...`, so the shebang has to be the thing
        that makes that true.

        With `#!/usr/bin/env python3` it would pick up whatever interpreter
        is on PATH — no jinja2, no pyyaml, possibly no `tomllib` — and the
        failure would land on whoever was least equipped to read it. uv
        resolves both the interpreter (.python-version) and the
        dependencies (pyproject.toml), which is why nothing in this
        repository is imported lazily any more.
        """
        expected = "#!/usr/bin/env -S uv run --quiet python"
        entry_points = [REPO_ROOT / "run.py", REPO_ROOT / "lab.py",
                        REPO_ROOT / "checks" / "egress.py"]
        entry_points += sorted((REPO_ROOT / "scripts").glob("*.py"))
        for path in entry_points:
            first = path.read_text(encoding="utf-8").splitlines()[0]
            self.assertEqual(first, expected, f"{path.name}: {first}")
            self.assertTrue(os.access(path, os.X_OK), f"{path.name} is not executable")

    # -- the properties that motivated parsing YAML rather than matching it --

    def test_a_later_duplicate_key_cannot_hide_an_unsafe_value(self) -> None:
        """Real YAML resolves a repeated key to the *last* one.

        The regex reader this replaced found the first `tls_interception:`
        and stopped, so a policy that set it safely and then overrode it
        passed validation while the engine read the override. The values
        below are the ones that matter: each is safe on its first
        appearance and unsafe on its second.
        """
        base = (REPO_ROOT / "config" / "pipelock.yaml").read_text()
        for label, override in (
            ("tls_interception", "\ntls_interception:\n  enabled: true\n"),
            ("mode", "\nmode: permissive\n"),
            ("forward_proxy",
             "\nforward_proxy:\n  enabled: true\n"
             "  sni_verification: false\n  sni_require_tls: false\n"),
        ):
            problems = self.run_mod.validate_policy_file(
                "pipelock", self.write(base + override))
            self.assertTrue(problems, f"{label}: an override passed validation")
            self.assertTrue(any("duplicate key" in p for p in problems),
                            f"{label}: {problems}")

    def test_a_quoted_scalar_is_read_as_its_value(self) -> None:
        """`action: "open"` is the same policy as `action: open`.

        A text search for the bare word missed the quoted form; a parser
        cannot, because by the time it is compared the quotes are gone.
        """
        path = self.write((REPO_ROOT / "config" / "smokescreen.yaml").read_text()
                          .replace("action: enforce", 'action: "open"'))
        problems = self.run_mod.validate_policy_file("smokescreen", path)
        self.assertTrue(any("open" in p for p in problems), problems)

    def test_an_open_action_on_a_service_is_refused_too(self) -> None:
        """`services:` entries carry the same shape as `default:`, and one
        of them set to `open` is an open proxy for that role."""
        path = self.write((REPO_ROOT / "config" / "smokescreen.yaml").read_text()
                          .replace("services: []",
                                   "services:\n  - name: x\n    action: open\n"
                                   "    allowed_domains: [a.com]"))
        problems = self.run_mod.validate_policy_file("smokescreen", path)
        self.assertTrue(any("open" in p for p in problems), problems)

    def test_unparseable_yaml_is_a_problem_not_a_traceback(self) -> None:
        """A policy that cannot be parsed cannot be checked, so it has to
        fail closed through the same list of problems every other failure
        uses — not by raising past the caller that would refuse to start."""
        path = self.write((REPO_ROOT / "config" / "pipelock.yaml").read_text()
                          + "\n  : : broken\n")
        problems = self.run_mod.validate_policy_file("pipelock", path)
        self.assertTrue(any("not valid YAML" in p for p in problems), problems)

    def test_squid_policy_requires_default_deny_last(self) -> None:
        text = (REPO_ROOT / "config" / "squid.conf").read_text()
        path = self.write(text.replace("http_access deny all",
                                       "http_access deny all\nhttp_access allow allowlist_exact"))
        problems = self.run_mod.validate_policy_file("squid", path)
        self.assertTrue(any("deny all" in p for p in problems), problems)

    def test_squid_policy_rejects_open_proxy(self) -> None:
        text = (REPO_ROOT / "config" / "squid.conf").read_text()
        path = self.write(text.replace("http_access allow allowlist_exact",
                                       "http_access allow all"))
        problems = self.run_mod.validate_policy_file("squid", path)
        self.assertTrue(any("allow all" in p for p in problems), problems)

    def test_squid_policy_rejects_ssrf_floors_after_the_allowlist(self) -> None:
        # http_access is first-match-wins: an allow above the `dst` denies
        # would let an allowlisted hostname reach a private address.
        text = (REPO_ROOT / "config" / "squid.conf").read_text()
        text = text.replace("http_access deny private_ip\n", "")
        text = text.replace("http_access allow allowlist_wild",
                            "http_access allow allowlist_wild\nhttp_access deny private_ip")
        problems = self.run_mod.validate_policy_file("squid", self.write(text))
        self.assertTrue(any("private_ip" in p and "before" in p for p in problems), problems)

    def test_squid_policy_rejects_a_missing_deny_range(self) -> None:
        text = (REPO_ROOT / "config" / "squid.conf").read_text()
        path = self.write(text.replace("acl private_ip dst 169.254.0.0/16\n", ""))
        problems = self.run_mod.validate_policy_file("squid", path)
        self.assertTrue(any("169.254.0.0/16" in p for p in problems), problems)

    def test_squid_policy_rejects_tls_interception(self) -> None:
        text = (REPO_ROOT / "config" / "squid.conf").read_text()
        path = self.write(text + "\nssl_bump bump all\n")
        problems = self.run_mod.validate_policy_file("squid", path)
        self.assertTrue(any("ssl_bump" in p for p in problems), problems)

    def test_squid_policy_rejects_a_deny_info_for_an_undefined_acl(self) -> None:
        """The failure mode this closes: an ACL is renamed, `deny_info` is
        not, Squid starts happily, and every SSRF denial falls back to the
        stock page and classifies as `unknown`."""
        text = (REPO_ROOT / "config" / "squid.conf").read_text()
        text = re.sub(r"^acl private_ip ", "acl private_ipv4 ", text, flags=re.M)
        text = text.replace("http_access deny private_ip\n",
                            "http_access deny private_ipv4\n")
        problems = self.run_mod.validate_policy_file("squid", self.write(text))
        self.assertTrue(any("does not define" in p for p in problems), problems)

    def test_squid_policy_requires_a_page_for_every_cause(self) -> None:
        for acl, page in self.run_mod.REQUIRED_SQUID_DENY_INFO.items():
            text = (REPO_ROOT / "config" / "squid.conf").read_text()
            text = text.replace(f"deny_info {page} {acl}\n", "")
            problems = self.run_mod.validate_policy_file("squid", self.write(text))
            self.assertTrue(any(page in p and "missing" in p for p in problems),
                            f"{acl}: {problems}")

    def test_squid_policy_rejects_two_pages_for_one_acl(self) -> None:
        # Only one can ever be shown, so the file no longer says which.
        text = (REPO_ROOT / "config" / "squid.conf").read_text()
        text += "\ndeny_info ERR_IPL_NOT_ALLOWLISTED private_ip\n"
        problems = self.run_mod.validate_policy_file("squid", self.write(text))
        self.assertTrue(any("two denial pages" in p for p in problems), problems)

    def test_squid_denial_pages_exist_in_the_image(self) -> None:
        squid_conf = REPO_ROOT / "config" / "squid.conf"
        text = squid_conf.read_text()
        self.assertEqual(self.run_mod.check_squid_error_pages(text, squid_conf), [])
        broken = text.replace("deny_info ERR_IPL_METADATA", "deny_info ERR_IPL_TYPO")
        problems = self.run_mod.check_squid_error_pages(broken, squid_conf)
        self.assertTrue(any("ERR_IPL_TYPO" in p for p in problems), problems)

    def test_squid_allowlist_normalizes_to_the_shared_forms(self) -> None:
        # `*.d` is an anchored dstdom_regex in Squid; it has to read back as
        # `*.d` or the cross-engine sync check compares nothing.
        entries = self.run_mod.policy_allowlist(
            "squid", REPO_ROOT / "config" / "squid.conf")
        self.assertIn("*.github.com", entries)
        self.assertIn("*.githubusercontent.com", entries)
        self.assertIn("github.com", entries)
        self.assertNotIn("githubusercontent.com", entries)

    def test_squid_allowlist_keeps_unrecognized_patterns_visible(self) -> None:
        # A hand-written regex must not be silently read as a wildcard
        # entry; it should surface as drift instead.
        self.assertEqual(self.run_mod._squid_regex_to_glob(r"\.github\.com$"), "*.github.com")
        self.assertEqual(self.run_mod._squid_regex_to_glob(r"github"), "github")

    def test_shipped_allowlists_are_identical_across_engines(self) -> None:
        """The three files express one allowlist.

        They are all rendered from `[policy].allow`, so this can only fail
        through a template or generator bug — which is exactly the failure
        it is here to catch, now that no human keeps them in sync.
        """
        allowlists = {}
        for engine in self.run_mod.ENGINES:
            spec = self.run_mod.ServiceSpec.load(engine)
            allowlists[engine] = self.run_mod.policy_allowlist(engine,
                                                               spec.config_path())
        self.assertEqual(len(set(map(frozenset, allowlists.values()))), 1,
                         f"the engines disagree: {allowlists}")
        self.assertEqual(set(next(iter(allowlists.values()))),
                         set(self.run_mod.load_policy_config().allow))

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
        for path, body in sorted(self.run_mod.render_policies().items()):
            rel = path.relative_to(REPO_ROOT)
            self.assertTrue(path.is_file(), f"{rel} is missing")
            self.assertEqual(
                path.read_text(encoding="utf-8"), body,
                f"{rel} is stale — run `./run.py policy` and commit the result")

    def test_generated_policies_validate(self) -> None:
        """Auto-regeneration means the generator's output is what runs, so it
        goes through the same checks the hand-written files went through."""
        rendered = self.run_mod.render_policies()
        self.assertEqual(self.run_mod.check_rendered_policies(rendered), [])

    def test_generated_allowlists_round_trip(self) -> None:
        """Every engine's rendered file reads back as exactly the config.toml
        list — so `squid_wild` and `_squid_regex_to_glob` stay inverses."""
        config = self.run_mod.load_policy_config()
        rendered = self.run_mod.render_policies(config)
        for engine in self.run_mod.ENGINES:
            spec = self.run_mod.ServiceSpec.load(engine)
            entries = self.run_mod.policy_allowlist_text(
                engine, rendered[REPO_ROOT / spec.config_file])
            self.assertEqual(entries, set(config.allow), spec.config_file)

    def test_squid_wildcard_filter_is_the_inverse_of_the_reader(self) -> None:
        for entry in ("*.github.com", "*.rebind.fixture.test", "*.io"):
            pattern = self.run_mod._squid_wild(entry)
            self.assertEqual(self.run_mod._squid_regex_to_glob(pattern), entry)
        # The apex must not match: `\.d$` is a suffix, not a prefix.
        self.assertEqual(self.run_mod._squid_wild("*.github.com"), r"\.github\.com$")

    def test_yaml_scalar_quotes_wildcards(self) -> None:
        # A bare leading `*` is a YAML alias, not a string.
        self.assertEqual(self.run_mod._yaml_scalar("*.github.com"), '"*.github.com"')
        self.assertEqual(self.run_mod._yaml_scalar("github.com"), "github.com")

    def test_config_toml_rejects_bad_entries(self) -> None:
        """Every rejection here is a policy that would otherwise be wrong in a
        way no engine would complain about."""
        Fail = self.run_mod.Fail
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
            "localhost": "allowlist form",     # single label; `dns_defnames off`
            "github.com:443": "allowlist form",
            "https://github.com": "allowlist form",
            "*.github.com/path": "allowlist form",
        }
        for entry, expected in cases.items():
            path = self.policy_config([entry])
            with self.assertRaises(Fail, msg=f"{entry} was accepted") as ctx:
                self.run_mod.load_policy_config(path)
            self.assertIn(expected, str(ctx.exception), entry)

    def test_config_toml_rejects_an_empty_allowlist(self) -> None:
        path = self.policy_config([])
        with self.assertRaises(self.run_mod.Fail) as ctx:
            self.run_mod.load_policy_config(path)
        self.assertIn("must not be empty", str(ctx.exception))

    def test_config_toml_rejects_duplicates_and_typos(self) -> None:
        Fail = self.run_mod.Fail
        dupe = self.policy_config(["github.com", "github.com"])
        with self.assertRaises(Fail) as ctx:
            self.run_mod.load_policy_config(dupe)
        self.assertIn("twice", str(ctx.exception))

        # `allows = [...]` would otherwise render an empty allowlist.
        typo = self.policy_config(["github.com"])
        typo.write_text(typo.read_text().replace("[policy]\nallow", "[policy]\nallows"))
        with self.assertRaises(Fail) as ctx:
            self.run_mod.load_policy_config(typo)
        self.assertIn("unknown key", str(ctx.exception))

    def test_generation_survives_a_new_domain(self) -> None:
        """An added domain must reach all three engines in the right form."""
        config = self.run_mod.PolicyConfig(allow=("github.com", "*.example.test"))
        rendered = self.run_mod.render_policies(config)
        self.assertEqual(self.run_mod.check_rendered_policies(rendered), [])
        squid = rendered[REPO_ROOT / "config" / "squid.conf"]
        self.assertIn(r"acl allowlist_wild dstdom_regex -i \.example\.test$", squid)
        self.assertIn("acl allowlist_exact dstdomain github.com", squid)
        self.assertIn('  - "*.example.test"',
                      rendered[REPO_ROOT / "config" / "pipelock.yaml"])
        self.assertIn('    - "*.example.test"',
                      rendered[REPO_ROOT / "config" / "smokescreen.yaml"])

    def test_sync_refuses_to_write_a_policy_that_fails_validation(self) -> None:
        """Auto-regeneration must never replace a working config with a
        broken one: a bad render has to fail before it touches the disk."""
        original = self.run_mod.render_policies
        squid_conf = REPO_ROOT / "config" / "squid.conf"
        before = squid_conf.read_text(encoding="utf-8")

        def broken(config=None):
            rendered = original(config)
            # Drop the SSRF floor: `validate_policy_text` must catch it.
            rendered[squid_conf] = rendered[squid_conf].replace(
                "http_access deny private_ip\n", "")
            return rendered

        self.run_mod.render_policies = broken
        self.addCleanup(setattr, self.run_mod, "render_policies", original)
        with quiet() as printed:
            with self.assertRaises(self.run_mod.Fail):
                self.run_mod.sync_policies()
        self.assertEqual(squid_conf.read_text(encoding="utf-8"), before,
                         "a failed render must leave the shipped config untouched")
        # Failing closed silently would be worse than not failing: the
        # problem has to reach stderr, where an operator will see it.
        self.assertIn("CONFIG ERROR", printed.err)
        self.assertIn("http_access deny private_ip", printed.err)

    def test_container_ip_parses_docker_and_apple_shapes(self) -> None:
        Backend = self.run_mod.Backend

        def fake(payload, returncode=0):
            backend = Backend("docker")
            backend._run = lambda *a, **k: CompletedProcess(  # type: ignore[method-assign]
                a, returncode, stdout=payload, stderr="")
            return backend

        docker_flat = json.dumps([{"NetworkSettings": {"IPAddress": "172.17.0.4"}}])
        docker_named = json.dumps([{"NetworkSettings": {
            "IPAddress": "", "Networks": {"bridge": {"IPAddress": "172.18.0.7"}}}}])
        # Apple `container` reports a CIDR, which has to be trimmed.
        apple = json.dumps([{"status": {"networks": [{"ipv4Address": "192.168.64.38/24"}]}}])
        self.assertEqual(fake(docker_flat).container_ip("x"), "172.17.0.4")
        self.assertEqual(fake(docker_named).container_ip("x"), "172.18.0.7")
        self.assertEqual(fake(apple).container_ip("x"), "192.168.64.38")
        self.assertEqual(fake("", returncode=1).container_ip("x"), "")

    def test_published_ports_parses_docker_and_apple_shapes(self) -> None:
        """The loopback binding is one `--publish` argument, and reading it
        back is how scripts/verify_loopback.py asserts it instead of
        trusting it (docs/lab.md, "Backend parity")."""
        Backend = self.run_mod.Backend

        def fake(payload, returncode=0):
            backend = Backend("docker")
            backend._run = lambda *a, **k: CompletedProcess(  # type: ignore[method-assign]
                a, returncode, stdout=payload, stderr="")
            return backend

        docker = json.dumps([{"HostConfig": {"PortBindings": {
            "8888/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]}}}])
        apple = json.dumps([{"configuration": {"publishedPorts": [
            {"containerPort": 8888, "hostAddress": "127.0.0.1",
             "hostPort": 18080, "proto": "tcp"}]}}])
        # The shape this exists to catch: bound to every interface.
        wide = json.dumps([{"HostConfig": {"PortBindings": {
            "8888/tcp": [{"HostIp": "", "HostPort": "18080"}]}}}])
        self.assertEqual(fake(docker).published_ports("x"), [("127.0.0.1", 18080, 8888)])
        self.assertEqual(fake(apple).published_ports("x"), [("127.0.0.1", 18080, 8888)])
        self.assertEqual(fake(wide).published_ports("x"), [("", 18080, 8888)])
        self.assertEqual(fake("", returncode=1).published_ports("x"), [])
        self.assertEqual(fake(json.dumps([{}])).published_ports("x"), [])

    def test_build_args_come_from_the_build_table(self) -> None:
        """`[build]` is passed through as `KEY.upper()`, not mapped by hand.

        The mapping used to be three named fields and three literal
        uppercase strings, so a new base pin meant editing run.py as well
        as the TOML and the Dockerfile. These are the ARGs the Dockerfiles
        actually declare.
        """
        load = self.run_mod.ServiceSpec.load
        self.assertEqual(load("smokescreen").build_args,
                         {"GO_IMAGE": "golang:1.24.6-alpine3.22",
                          "RUNTIME_IMAGE": "alpine:3.22.1"})
        squid = load("squid").build_args
        self.assertEqual(squid["BASE_IMAGE"], "alpine:3.22.1")
        # [source.packages] arrives as `<NAME>_VERSION` in the same table.
        self.assertEqual(squid["SQUID_VERSION"],
                         load("squid").packages["squid"])

    def test_pin_kind_per_service(self) -> None:
        kinds = {engine: self.run_mod.ServiceSpec.load(engine).pin_kind
                 for engine in self.run_mod.ENGINES}
        self.assertEqual(kinds, {"pipelock": "digest", "smokescreen": "source",
                                 "squid": "package"})

    # -- [fixture] in config.toml -------------------------------------------

    def test_container_state_parses_docker_and_apple_shapes(self) -> None:
        Backend = self.run_mod.Backend

        def fake(payload, returncode=0):
            backend = Backend("docker")
            backend._run = lambda *a, **k: CompletedProcess(  # type: ignore[method-assign]
                a, returncode, stdout=payload, stderr="")
            return backend

        docker_shape = json.dumps([{"State": {"Status": "running"}}])
        apple_shape = json.dumps([{"status": "running", "configuration": {}}])
        stopped = json.dumps([{"State": {"Status": "exited"}}])
        self.assertEqual(fake(docker_shape).container_state("x"), "running")
        self.assertEqual(fake(apple_shape).container_state("x"), "running")
        self.assertEqual(fake(stopped).container_state("x"), "stopped")
        self.assertEqual(fake("", returncode=1).container_state("x"), "absent")

    def test_service_specs_load_and_refuse_unsafe_flags(self) -> None:
        for engine in self.run_mod.ENGINES:
            spec = self.run_mod.ServiceSpec.load(engine)
            self.assertNotIn("--unsafe-allow-private-ranges", spec.args)
            self.assertNotEqual(spec.image_tag, "latest")

    def test_every_engine_has_a_shipped_config(self) -> None:
        for engine in self.run_mod.ENGINES:
            spec = self.run_mod.ServiceSpec.load(engine)
            self.assertTrue(spec.config_path().is_file())
            # The `.test` variant belongs to the other lane and must not be
            # reachable from a service definition any more.
            self.assertFalse(hasattr(spec, "test_config_file"))

    def test_squid_image_ref_is_the_pinned_package_version(self) -> None:
        spec = self.run_mod.ServiceSpec.load("squid")
        self.assertEqual(spec.packages.get("squid"), spec.primary_package_version)
        self.assertEqual(spec.run_image_ref(),
                         f"{spec.image_repository}:{spec.primary_package_version}")
        self.assertTrue(spec.primary_package_version,
                        "services/squid.toml must pin a version")

    def test_every_pinned_package_has_a_version(self) -> None:
        for engine in self.run_mod.ENGINES:
            spec = self.run_mod.ServiceSpec.load(engine)
            for name, version in spec.packages.items():
                self.assertTrue(version, f"services/{engine}.toml: {name} is unpinned")


if __name__ == "__main__":
    unittest.main()
