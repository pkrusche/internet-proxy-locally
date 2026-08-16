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
      printf '[{"State": {"Status": "%s"}}]\n' "$(cat "$f")"
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
  logs) echo "fake engine logs" ;;
  rm)
    for a in "$@"; do
      [ "$a" = "-f" ] && continue
      p="$FAKE_STATE/pid-$a"
      if [ -f "$p" ]; then kill "$(cat "$p")" 2>/dev/null; rm -f "$p"; fi
      rm -f "$FAKE_STATE/container-$a"
    done
    ;;
  run)
    name=""; prev=""
    for a in "$@"; do
      if [ "$prev" = "--name" ]; then name="$a"; fi
      prev="$a"
    done
    echo running > "$FAKE_STATE/container-$name"
    if [ -n "${FAKE_PROXY_SPAWN:-}" ]; then
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

    def test_shipped_policies_are_valid(self) -> None:
        for engine, rel in (("pipelock", "config/pipelock.yaml"),
                            ("pipelock", "config/pipelock.test.yaml"),
                            ("smokescreen", "config/smokescreen.yaml"),
                            ("smokescreen", "config/smokescreen.test.yaml")):
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

    def test_shipped_allowlists_are_in_sync(self) -> None:
        self.assertEqual(self.run_mod.check_allowlist_sync(False), [])
        self.assertEqual(self.run_mod.check_allowlist_sync(True), [])

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
        for engine in ("pipelock", "smokescreen"):
            spec = self.run_mod.ServiceSpec.load(engine)
            self.assertNotIn("--unsafe-allow-private-ranges", spec.args)
            self.assertNotEqual(spec.image_tag, "latest")


if __name__ == "__main__":
    unittest.main()
