"""Tests for run.py using a fake container-backend shim.

A stand-in `docker` executable records every CLI invocation and emulates
just enough state (containers, images) for the lifecycle commands. When it
"starts" a container it actually spawns tests/mock_proxy.py on the test
endpoint, so the post-start health check and `check --quick` run for real.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

REPO_ROOT = Path(__file__).resolve().parent.parent

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


def load_module(name: str, path: Path):
    import sys
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


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
        for sub in ("services", "config"):
            shutil.copytree(REPO_ROOT / sub, self.tmp / sub)
        # Start from unpinned service specs regardless of what the checkout
        # currently pins, so the fail-closed tests stay meaningful and the
        # tests that need a pin set one explicitly.
        self.unpin("pipelock", "digest")
        self.unpin("smokescreen", "ref")
        self.unpin("squid", "package_version")
        (self.tmp / "checks").mkdir()
        shutil.copy(REPO_ROOT / "checks" / "egress.py", self.tmp / "checks" / "egress.py")

        bindir = self.tmp / "bin"
        bindir.mkdir()
        shim = bindir / "docker"
        shim.write_text(FAKE_BACKEND)
        shim.chmod(0o755)

        self.state = self.tmp / "state"
        self.state.mkdir()
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

        check = self.run_cli("--backend", "docker", "check", "--quick")
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        self.assertIn("summary:", check.stdout)

        down = self.run_cli("--backend", "docker", "down")
        self.assertEqual(down.returncode, 0)
        self.assertIn("removed internet-proxy-pipelock", down.stdout)
        self.assertFalse((self.state / "container-internet-proxy-pipelock").exists())

    def test_check_wires_engine_log_capture(self) -> None:
        # `check` should pass --backend-bin/--container through to
        # checks/egress.py so each result's `engine_logs` is populated
        # from the running container's own log stream (TODO.md §1).
        self.pin_pipelock()
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)

        check = self.run_cli("--backend", "docker", "check", "--quick", "--json")
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
        toml.write_text(re.sub(r'^package_version = ""$', f'package_version = "{version}"',
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
        toml.write_text(re.sub(r'^package_version = ""$', 'package_version = "6.12-r0"',
                               toml.read_text(), flags=re.M))
        proc = self.run_cli("--backend", "docker", "--engine", "squid", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not built yet", proc.stderr)
        self.assertIn("--engine squid setup", proc.stderr)

    def fake_dns_fixture_image(self) -> None:
        self.fake_image("internet-proxy-locally/dnsmasq:2.91-r1")

    def test_test_policy_starts_the_dns_fixture_and_points_the_engine_at_it(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        up = self.run_cli("--backend", "docker", "up", "--test-policy")
        self.assertEqual(up.returncode, 0, up.stderr + up.stdout)
        runs = [l for l in self.backend_log().splitlines() if l.startswith("run ")]
        fixture = next(l for l in runs if "internet-proxy-dnsfixture" in l)
        engine = next(l for l in runs if "internet-proxy-pipelock" in l)
        # The fixture serves the records and is reachable only from the
        # container network — no host port.
        self.assertIn(":/fixture/hosts:ro", fixture)
        self.assertNotIn("--publish", fixture)
        # The engine resolves through it.
        self.assertIn("--dns 172.17.0.9", engine)

    def test_normal_up_runs_no_dns_fixture(self) -> None:
        self.pin_pipelock()
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        runs = [l for l in self.backend_log().splitlines() if l.startswith("run ")]
        self.assertFalse([l for l in runs if "internet-proxy-dnsfixture" in l])
        engine = next(l for l in runs if "internet-proxy-pipelock" in l)
        self.assertNotIn("--dns", engine)

    def test_normal_up_removes_a_stale_dns_fixture(self) -> None:
        # A fixture left over from `up --test-policy` must not outlive the
        # engine it was attached to, or a real-policy run would still be
        # resolving through it.
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        self.assertEqual(self.run_cli("--backend", "docker", "up", "--test-policy").returncode, 0)
        self.assertTrue((self.state / "container-internet-proxy-dnsfixture").exists())
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn("removed existing container internet-proxy-dnsfixture", up.stdout)
        self.assertFalse((self.state / "container-internet-proxy-dnsfixture").exists())

    def test_down_removes_the_dns_fixture(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        self.assertEqual(self.run_cli("--backend", "docker", "up", "--test-policy").returncode, 0)
        down = self.run_cli("--backend", "docker", "down")
        self.assertEqual(down.returncode, 0)
        self.assertIn("removed internet-proxy-dnsfixture", down.stdout)

    def test_test_policy_refuses_without_the_fixture_image(self) -> None:
        self.pin_pipelock()  # fixture image deliberately absent
        proc = self.run_cli("--backend", "docker", "up", "--test-policy")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("DNS fixture image", proc.stderr)
        self.assertIn("run `./run.py setup`", proc.stderr)

    def test_check_requires_running_engine(self) -> None:
        proc = self.run_cli("--backend", "docker", "check", "--quick")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no engine is running", proc.stderr)


class RunPyUnitTest(unittest.TestCase):
    """In-process unit tests for policy validation and backend parsing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.run_mod = load_module("run_unit", REPO_ROOT / "run.py")

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
        retried instead (docs/comparison.md, "Not yet measured").
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
                            ("pipelock", "config/pipelock.test.yaml"),
                            ("smokescreen", "config/smokescreen.yaml"),
                            ("smokescreen", "config/smokescreen.test.yaml"),
                            ("squid", "config/squid.conf"),
                            ("squid", "config/squid.test.conf")):
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

    def test_allowlist_drift_is_reported_for_every_engine_pair(self) -> None:
        original = self.run_mod.policy_allowlist

        def drifted(engine, path):
            entries = set(original(engine, path))
            if engine == "squid":
                entries.add("evil.example")
            return entries

        self.run_mod.policy_allowlist = drifted
        self.addCleanup(setattr, self.run_mod, "policy_allowlist", original)
        warnings = self.run_mod.check_allowlist_sync(False)
        self.assertTrue(any("evil.example" in w and "pipelock" in w for w in warnings), warnings)
        self.assertTrue(any("evil.example" in w and "smokescreen" in w for w in warnings), warnings)

    def test_shipped_allowlists_are_in_sync(self) -> None:
        self.assertEqual(self.run_mod.check_allowlist_sync(False), [])
        self.assertEqual(self.run_mod.check_allowlist_sync(True), [])

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

    def test_pin_kind_per_service(self) -> None:
        kinds = {engine: self.run_mod.ServiceSpec.load(engine).pin_kind
                 for engine in self.run_mod.PINNABLE}
        self.assertEqual(kinds, {"pipelock": "digest", "smokescreen": "source",
                                 "squid": "package", "dnsmasq": "package"})

    def test_dns_fixture_is_not_an_engine(self) -> None:
        # It is pinned and built like one, but `--engine dnsmasq` must not
        # exist and `down`/`status` must not treat it as a proxy.
        self.assertNotIn(self.run_mod.DNS_FIXTURE, self.run_mod.ENGINES)
        self.assertIn(self.run_mod.DNS_FIXTURE, self.run_mod.PINNABLE)

    def test_dns_fixture_records_cover_the_checker_names(self) -> None:
        """The fixture file and checks/egress.py must agree, and the mixed
        names must each carry one public and one private address in both
        orderings — that is the whole content of the check."""
        import ipaddress
        egress = load_module("egress_fixture", REPO_ROOT / "checks" / "egress.py")
        spec = self.run_mod.ServiceSpec.load(self.run_mod.DNS_FIXTURE)
        records: dict[str, list[str]] = {}
        for line in (REPO_ROOT / spec.config_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            address, *names = line.split()
            for name in names:
                records.setdefault(name, []).append(address)

        self.assertEqual(records.get(egress.MIXED_FIXTURE_CONTROL, []).__len__(), 1,
                         "the control must resolve to exactly one address")
        self.assertFalse(any(ipaddress.ip_address(a).is_private
                             for a in records[egress.MIXED_FIXTURE_CONTROL]))

        orderings = set()
        for name in egress.MIXED_FIXTURE_TARGETS:
            addresses = records.get(name, [])
            self.assertEqual(len(addresses), 2, f"{name}: expected two records")
            private = [ipaddress.ip_address(a).is_private for a in addresses]
            self.assertEqual(sorted(private), [False, True],
                             f"{name}: needs one public and one private address")
            orderings.add(tuple(private))
        self.assertEqual(len(orderings), 2,
                         "both answer orderings must be represented, or an engine that "
                         "validates only the first address would not be distinguished")

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

    def test_every_engine_has_a_config_and_a_test_config(self) -> None:
        for engine in self.run_mod.ENGINES:
            spec = self.run_mod.ServiceSpec.load(engine)
            for test_policy in (False, True):
                self.assertTrue(spec.config_path(test_policy).is_file())

    def test_squid_image_ref_is_the_pinned_package_version(self) -> None:
        spec = self.run_mod.ServiceSpec.load("squid")
        self.assertEqual(spec.run_image_ref(),
                         f"{spec.image_repository}:{spec.package_version}")
        self.assertTrue(spec.package_version, "services/squid.toml must pin a version")


if __name__ == "__main__":
    unittest.main()
