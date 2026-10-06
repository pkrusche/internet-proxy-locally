"""Endpoint isolation and discovery, against both adapters and the fake runtime."""

from __future__ import annotations

import hashlib
import json
import socket
import unittest
from subprocess import CompletedProcess
from unittest import mock

from internet_proxy_locally.backend import Backend
from internet_proxy_locally.instances import (
    LABEL,
    discover_instances,
    endpoint_key,
    instance_spec,
)
from internet_proxy_locally.net import endpoint, endpoint_text, probe_address
from internet_proxy_locally.spec import ServiceSpec
from tests.test_runpy import RunPyCliFixture, free_port


class EndpointTest(unittest.TestCase):
    def test_component_precedence_and_defaults(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(endpoint(), ("127.0.0.1", 18080))
        with mock.patch.dict("os.environ", {"IPL_ENDPOINT": "[::1]:19000"}):
            self.assertEqual(endpoint(), ("::1", 19000))
            self.assertEqual(endpoint("127.0.0.2"), ("127.0.0.2", 19000))
            self.assertEqual(endpoint(port=20000), ("::1", 20000))
            self.assertEqual(
                endpoint("0.0.0.0", 20000, loopback_only=False), ("0.0.0.0", 20000)
            )

    def test_validation_preserves_lab_restriction(self) -> None:
        for host, port in (
            ("localhost", 80),
            ("127.0.0.1", 0),
            ("127.0.0.1", 65536),
            ("fe80::1%eth0", 80),
        ):
            with self.subTest(host=host, port=port), self.assertRaises(ValueError):
                endpoint(host, port, loopback_only=False)
        with self.assertRaisesRegex(ValueError, "loopback"):
            endpoint("0.0.0.0", 80)

    def test_names_canonicalize_ipv6_and_distinguish_endpoints(self) -> None:
        self.assertEqual(
            endpoint_key(("0:0:0:0:0:0:0:1", 18080)), endpoint_key(("::1", 18080))
        )
        names = {
            instance_spec("pipelock", binding).container_name
            for binding in (
                ("127.0.0.1", 18080),
                ("127.0.0.2", 18080),
                ("127.0.0.1", 18081),
                ("::1", 18080),
            )
        }
        self.assertEqual(len(names), 4)
        self.assertIn(
            "internet-proxy-pipelock-ipv6-00000000000000000000000000000001-18080", names
        )
        self.assertEqual(endpoint_text("::1", 80), "[::1]:80")
        self.assertEqual(probe_address("::"), "::1")
        self.assertEqual(probe_address("0.0.0.0"), "127.0.0.1")
        self.assertEqual(probe_address("192.0.2.1"), "192.0.2.1")


class BackendDiscoveryTest(unittest.TestCase):
    def test_enumeration_commands_for_both_backends(self) -> None:
        for name, args in (
            ("docker", ("ps", "--all", "--format", "{{.Names}}")),
            ("container", ("list", "--all", "--quiet")),
        ):
            backend = Backend(name)
            with mock.patch.object(
                backend, "_run", return_value=CompletedProcess([], 0, "one\ntwo\n")
            ) as run:
                self.assertEqual(backend.container_names(), ["one", "two"])
                run.assert_called_once_with(*args)

    def test_ipv6_publication_is_bracketed(self) -> None:
        for name in ("docker", "container"):
            backend = Backend(name)
            with mock.patch.object(backend, "_run") as run:
                backend.run_detached(
                    name="proxy",
                    image="image",
                    internal_port=8888,
                    mounts=[],
                    publish=("::1", 18080),
                )
                self.assertIn("[::1]:18080:8888", run.call_args.args)

    def test_disappearing_container_is_skipped(self) -> None:
        backend = mock.Mock(spec=Backend)
        backend.container_names.return_value = ["internet-proxy-pipelock"]
        backend.container_labels.return_value = {
            LABEL + "managed": "true",
            LABEL + "workspace": "other",
        }
        backend.container_state.side_effect = ["running", "absent"]
        backend.published_ports.return_value = [("127.0.0.1", 18080, 8888)]
        self.assertEqual(discover_instances(backend), [])


class InstanceCliTest(RunPyCliFixture):
    def name(
        self, engine: str = "pipelock", ip: str = "127.0.0.1", port: int | None = None
    ) -> str:
        return instance_spec(engine, (ip, port or self.port)).container_name

    def add_container(
        self,
        name: str,
        *,
        engine: str = "pipelock",
        ip: str = "127.0.0.1",
        port: int = 18080,
        workspace: str | None = None,
        role: str = "operational",
        state: str = "running",
        managed: bool = True,
        legacy: bool = False,
    ) -> None:
        labels = {
            LABEL + "managed": str(managed).lower(),
            LABEL + "workspace": workspace
            or hashlib.sha256(str(self.tmp).encode()).hexdigest()[:16],
            LABEL + "role": role,
        }
        if not legacy:
            labels[LABEL + "engine"] = engine
        metadata = [
            {
                "State": {"Status": state},
                "Config": {"Labels": labels},
                "HostConfig": {
                    "PortBindings": {
                        f"{ServiceSpec.load(engine).internal_port}/tcp": [
                            {"HostIp": ip, "HostPort": str(port)}
                        ]
                    }
                },
            }
        ]
        (self.state / f"container-{name}").write_text(state)
        (self.state / f"meta-{name}").write_text(json.dumps(metadata))

    def test_two_ports_and_selected_lifecycle(self) -> None:
        self.build_engine()
        self.build_engine("squid")
        other_port = free_port()
        self.assertEqual(self.run_cli("up").returncode, 0)
        other = self.run_cli("--port", str(other_port), "up")
        self.assertEqual(other.returncode, 0, other.stderr)
        original_pid = (self.state / f"pid-{self.name()}").read_text()
        switched = self.run_cli(
            "--port", str(other_port), "--engine", "squid", "restart"
        )
        self.assertEqual(switched.returncode, 0, switched.stderr)
        self.assertEqual((self.state / f"pid-{self.name()}").read_text(), original_pid)
        self.assertFalse(
            (self.state / f"container-{self.name(port=other_port)}").exists()
        )
        status = self.run_cli("--port", str(other_port), "status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("squid: running (active)", status.stdout)
        self.assertIn("pipelock: absent", status.stdout)
        logs = self.run_cli("--port", str(other_port), "logs")
        self.assertEqual(logs.returncode, 0, logs.stderr)
        self.assertIn(f"logs {self.name('squid', port=other_port)}", self.backend_log())
        check = self.run_cli("check", "--json")
        self.assertEqual(check.returncode, 0, check.stderr)
        document = json.loads(check.stdout)
        self.assertEqual(document["engine"], "pipelock")
        self.assertEqual(document["proxy"], f"http://127.0.0.1:{self.port}")
        other_check = self.run_cli("--port", str(other_port), "check", "--json")
        self.assertEqual(other_check.returncode, 0, other_check.stderr)
        other_document = json.loads(other_check.stdout)
        self.assertEqual(other_document["engine"], "squid")
        self.assertEqual(other_document["proxy"], f"http://127.0.0.1:{other_port}")
        down = self.run_cli("--port", str(other_port), "down")
        self.assertEqual(down.returncode, 0, down.stderr)
        self.assertTrue((self.state / f"container-{self.name()}").exists())
        self.assertFalse(
            (self.state / f"container-{self.name('squid', port=other_port)}").exists()
        )

    def test_same_port_different_ips(self) -> None:
        try:
            with socket.socket() as sock:
                sock.bind(("127.0.0.2", self.port))
        except OSError as exc:
            self.skipTest(f"second loopback address unavailable: {exc}")
        self.build_engine()
        self.assertEqual(self.run_cli("up").returncode, 0)
        other = self.run_cli("--ip", "127.0.0.2", "up")
        self.assertEqual(other.returncode, 0, other.stderr)
        listed = self.run_cli("list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn(f"127.0.0.1:{self.port}", listed.stdout)
        self.assertIn(f"127.0.0.2:{self.port}", listed.stdout)
        self.assertEqual(self.run_cli("--ip", "127.0.0.2", "down").returncode, 0)
        self.assertEqual(self.run_cli("status").returncode, 0)

    def test_wildcard_binding_checks_through_loopback(self) -> None:
        self.build_engine()
        up = self.run_cli("--ip", "0.0.0.0", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn(f"on http://0.0.0.0:{self.port}", up.stdout)
        self.assertIn(f"HTTP_PROXY=http://127.0.0.1:{self.port}", up.stdout)
        self.assertEqual(self.run_cli("--ip", "0.0.0.0", "status").returncode, 0)

    def test_ipv6_instance_and_canonical_selection(self) -> None:
        try:
            with socket.socket(socket.AF_INET6) as sock:
                sock.bind(("::1", 0))
                port = sock.getsockname()[1]
        except OSError as exc:
            self.skipTest(f"IPv6 loopback unavailable: {exc}")
        self.build_engine()
        self.env["FAKE_PUBLISH_IP_OVERRIDE"] = "0:0:0:0:0:0:0:1"
        up = self.run_cli("--ip", "0:0:0:0:0:0:0:1", "--port", str(port), "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn(f"HTTP_PROXY=http://[::1]:{port}", up.stdout)
        self.assertIn(f"--publish [::1]:{port}:8888", self.backend_log())
        self.assertEqual(
            self.run_cli("--ip", "::1", "--port", str(port), "status").returncode, 0
        )
        listed = self.run_cli("list")
        self.assertIn(f"[::1]:{port}", listed.stdout)
        self.assertEqual(
            self.run_cli("--ip", "::1", "--port", str(port), "down").returncode, 0
        )

    def test_runtime_publication_mismatch_is_rejected(self) -> None:
        self.build_engine()
        self.env["FAKE_PUBLISH_IP_OVERRIDE"] = "0.0.0.0"
        result = self.run_cli("up")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("runtime did not honor requested publication", result.stderr)
        self.assertFalse((self.state / f"container-{self.name()}").exists())

    def test_wildcard_conflict_preserves_existing_instance(self) -> None:
        self.build_engine()
        self.assertEqual(self.run_cli("up").returncode, 0)
        result = self.run_cli("--ip", "0.0.0.0", "up")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("already in use", result.stderr)
        self.assertTrue((self.state / f"container-{self.name()}").exists())
        self.assertEqual(self.run_cli("status").returncode, 0)

    def test_failed_start_only_cleans_up_new_instance(self) -> None:
        self.build_engine()
        self.assertEqual(self.run_cli("up").returncode, 0)
        self.env["FAKE_PROXY_SPAWN"] = ""
        port = free_port()
        failed = self.run_cli("--port", str(port), "up")
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertIn("created container removed", failed.stderr)
        self.assertFalse((self.state / f"container-{self.name(port=port)}").exists())
        self.assertEqual(self.run_cli("status").returncode, 0)

    def test_tls_config_snapshots_are_independent(self) -> None:
        self.build_engine()
        self.assertEqual(self.run_cli("ca", "init").returncode, 0)
        first = self.run_cli("up", "--tls-interception")
        self.assertEqual(first.returncode, 0, first.stderr)
        snapshot = (
            self.state
            / "instances"
            / endpoint_key(("127.0.0.1", self.port))
            / "pipelock.yaml"
        )
        before = snapshot.read_bytes()
        port = free_port()
        self.assertEqual(self.run_cli("--port", str(port), "up").returncode, 0)
        second = (
            self.state
            / "instances"
            / endpoint_key(("127.0.0.1", port))
            / "pipelock.yaml"
        )
        self.assertEqual(snapshot.read_bytes(), before)
        self.assertNotEqual(second.read_bytes(), before)
        self.assertIn(f"{snapshot}:/config/pipelock.yaml:ro", self.backend_log())
        self.assertEqual(self.run_cli("status").returncode, 0)

    def test_list_all_workspaces_roles_and_legacy(self) -> None:
        self.add_container(
            "z-other", engine="iron", ip="::1", workspace="ffff", role="lab"
        )
        self.add_container(
            "internet-proxy-squid",
            engine="squid",
            ip="0.0.0.0",
            workspace="0000",
            legacy=True,
        )
        self.add_container(self.name(), port=self.port)
        self.add_container("stopped", state="stopped")
        self.add_container("unmanaged", managed=False)
        self.add_container("internet-proxy-dnsfixture", engine="dnsfixture", role="lab")
        self.env["IPL_ENDPOINT"] = "invalid"
        listed = self.run_cli(
            "--ip", "invalid", "--port", "0", "--engine", "smokescreen", "list"
        )
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("(current)", listed.stdout)
        self.assertIn("[::1]:18080", listed.stdout)
        self.assertIn("lab", listed.stdout)
        self.assertIn("0.0.0.0:18080", listed.stdout)
        self.assertLess(
            listed.stdout.index("internet-proxy-squid"),
            listed.stdout.index(self.name()),
        )
        for excluded in ("stopped", "unmanaged", "dnsfixture"):
            self.assertNotIn(excluded, listed.stdout)
        self.assertNotIn("logs ", self.backend_log())

    def test_list_empty_and_runtime_failure(self) -> None:
        listed = self.run_cli("list")
        self.assertEqual(listed.returncode, 0)
        self.assertEqual(listed.stdout.strip(), "no running IPL instances")
        self.env["FAKE_LIST_FAIL"] = "1"
        failed = self.run_cli("list")
        self.assertEqual(failed.returncode, 1)
        self.assertIn("enumeration failed", failed.stderr)
        self.assertNotIn("Traceback", failed.stderr)

    def test_matching_legacy_instance_migrates(self) -> None:
        self.build_engine()
        self.assertEqual(self.run_cli("up").returncode, 0)
        legacy = "internet-proxy-pipelock"
        for prefix in ("container-", "meta-", "pid-"):
            (self.state / f"{prefix}{self.name()}").rename(
                self.state / f"{prefix}{legacy}"
            )
        self.assertIn(f"container: {legacy}\n", self.run_cli("status").stdout)
        restarted = self.run_cli("restart")
        self.assertEqual(restarted.returncode, 0, restarted.stderr)
        self.assertIn(f"removed existing container {legacy}", restarted.stdout)
        self.assertFalse((self.state / f"container-{legacy}").exists())
        self.assertTrue((self.state / f"container-{self.name()}").exists())

    def test_other_legacy_endpoint_and_foreign_names_are_preserved(self) -> None:
        legacy = "internet-proxy-squid"
        self.add_container(legacy, engine="squid", port=self.port + 1, legacy=True)
        self.assertEqual(self.run_cli("down").returncode, 0)
        self.assertTrue((self.state / f"container-{legacy}").exists())
        self.add_container(self.name(), port=self.port, workspace="foreign")
        down = self.run_cli("down")
        self.assertEqual(down.returncode, 1)
        self.assertIn("ownership labels differ", down.stderr)
        self.assertTrue((self.state / f"container-{self.name()}").exists())
        logs = self.run_cli("logs")
        self.assertEqual(logs.returncode, 1)
        self.assertIn("another workspace", logs.stderr)

    def test_ca_guard_covers_other_endpoint_but_not_other_workspace(self) -> None:
        self.assertEqual(self.run_cli("ca", "init").returncode, 0)
        key = self.state / "ca" / "ca-key.pem"
        before = key.read_bytes()
        name = self.name(port=self.port + 1)
        self.add_container(name, port=self.port + 1)
        for args in (("ca", "rotate"), ("ca", "init", "--rebuild")):
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(key.read_bytes(), before)
        self.add_container(name, port=self.port + 1, workspace="foreign")
        self.assertEqual(self.run_cli("ca", "rotate").returncode, 0)

    def test_invalid_endpoint_has_no_side_effects(self) -> None:
        for args in (("--ip", "localhost"), ("--port", "0"), ("--port", "65536")):
            result = self.run_cli(*args, "up")
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.backend_log(), "")
        self.assertFalse((self.state / "instances").exists())
