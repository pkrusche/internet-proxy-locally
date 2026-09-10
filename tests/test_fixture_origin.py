"""Local TLS origin, certificate isolation, DNS roles, and runtime wiring."""

from __future__ import annotations

import io
import os
import runpy
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography import x509

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.cli import lab as lab_cli
from internet_proxy_locally.cli import run as run_cli
from internet_proxy_locally.constants import (
    FIXTURE_NETWORK_NAME,
    FIXTURE_PRIVATE_NETWORK_NAME,
    FIXTURE_PUBLIC_ADDRESS,
    FIXTURE_PUBLIC_SUBNET,
)
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lab import tls
from internet_proxy_locally.lab.fixtures import load_lab_config
from internet_proxy_locally.lab.render import render_test_policies, test_config_path
from internet_proxy_locally.lifecycle import ownership_labels
from internet_proxy_locally.policy.render import render_policies
from internet_proxy_locally.spec import ServiceSpec


def fixture_module():
    config = load_lab_config().fixture
    settings = f"REBIND_ZONE={config.rebind_zone}\nPUBLIC_ANSWER={config.public_answer}\nPTR_ADDRESS={config.ptr_address}\nPTR_CLAIMS={config.ptr_claims}\n"
    original = open

    def opened(path, *args, **kwargs):
        if path == "/fixture/fixture.env":
            return io.StringIO(settings)
        return original(path, *args, **kwargs)

    with patch("builtins.open", side_effect=opened):
        return runpy.run_path(str(paths.image_dir() / "dnsfixture/rebind.py"))


class FixtureOriginTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_lab_config().fixture
        self.code = fixture_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {"IPL_ROOT": str(self.root)})
        self.env.start()
        self.addCleanup(self.env.stop)
        tls.generate(self.config)
        self.origin = self.code["Origin"](
            "127.0.0.1",
            str(tls.directory() / "origin.pem"),
            str(tls.directory() / "origin-key.pem"),
            port=0,
        )
        self.addCleanup(self.origin.server_close)
        thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.origin.shutdown)

    def connect(self, name: str, trusted: bool = True) -> bytes:
        ctx = ssl.create_default_context(
            cafile=str(tls.directory() / "ca.pem") if trusted else None
        )
        with (
            socket.create_connection(self.origin.server_address, timeout=2) as sock,
            ctx.wrap_socket(sock, server_hostname=name) as connection,
        ):
            connection.sendall(
                f"GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode()
            )
            return connection.recv(4096)

    def test_verified_tls_and_http_for_all_fixture_names(self) -> None:
        for name in (*self.config.names, "a0-token." + self.config.rebind_zone):
            with self.subTest(name=name):
                self.assertIn(b"200 OK", self.connect(name))

    def test_wrong_hostname_and_missing_trust_are_rejected(self) -> None:
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect("pypi.org")
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(self.config.control, trusted=False)

    def test_ca_is_constrained_and_its_signing_key_is_not_saved(self) -> None:
        certificate = x509.load_pem_x509_certificate(
            (tls.directory() / "ca.pem").read_bytes()
        )
        constraints = certificate.extensions.get_extension_for_class(
            x509.NameConstraints
        )
        self.assertTrue(constraints.critical)
        self.assertEqual(constraints.value.permitted_subtrees, [x509.DNSName(".test")])
        self.assertEqual(
            {p.name for p in tls.directory().iterdir()},
            {"ca.pem", "origin.pem", "origin-key.pem"},
        )
        self.assertEqual(
            (tls.directory() / "origin-key.pem").stat().st_mode & 0o777, 0o600
        )
        self.assertFalse(paths.ca_dir().exists())

    def test_dns_role_replacement_preserves_both_answer_orders(self) -> None:
        hosts = "9.9.9.9 control.test\n9.9.9.9 mixed-a.test\n10.0.0.1 mixed-a.test\n10.0.0.1 mixed-b.test\n9.9.9.9 mixed-b.test\n"
        actual = self.code["local_hosts"](hosts, "9.9.9.9", "11.203.0.7", "172.17.0.9")
        self.assertEqual(
            actual,
            hosts.replace("9.9.9.9", "11.203.0.7").replace("10.0.0.1", "172.17.0.9"),
        )

    def test_responder_rebinds_to_private_after_first_query(self) -> None:
        responder = self.code["Responder"]("172.17.0.9")
        name = "a0-token." + self.config.rebind_zone
        self.assertEqual(responder.answer_for(name), self.config.public_answer)
        self.assertEqual(responder.answer_for(name), "172.17.0.9")
        self.assertEqual(responder.answer_for(name), "172.17.0.9")


class FixtureWiringTest(unittest.TestCase):
    def test_dns_uses_private_bridge_regardless_of_network_order(self) -> None:
        backend = Backend("docker")
        with patch.object(
            backend,
            "_inspect_entry",
            return_value={
                "NetworkSettings": {
                    "Networks": {
                        FIXTURE_NETWORK_NAME: {"IPAddress": FIXTURE_PUBLIC_ADDRESS},
                        FIXTURE_PRIVATE_NETWORK_NAME: {"IPAddress": "172.17.0.9"},
                    }
                }
            },
        ):
            self.assertEqual(backend.container_ip("fixture"), "172.17.0.9")

    def test_docker_origin_uses_internal_network_without_extra_capabilities(
        self,
    ) -> None:
        backend = Backend("docker")
        with patch.object(backend, "_run") as run:
            backend.run_detached(
                name="fixture",
                image="fixture-image",
                internal_port=53,
                mounts=[],
                lab_network=FIXTURE_NETWORK_NAME,
                lab_address=FIXTURE_PUBLIC_ADDRESS,
            )
            args = run.call_args.args
            self.assertIn(
                f"name={FIXTURE_NETWORK_NAME},ip={FIXTURE_PUBLIC_ADDRESS}", args
            )
            networks = [args[i + 1] for i, arg in enumerate(args) if arg == "--network"]
            self.assertEqual(
                networks,
                [
                    FIXTURE_PRIVATE_NETWORK_NAME,
                    f"name={FIXTURE_NETWORK_NAME},ip={FIXTURE_PUBLIC_ADDRESS}",
                ],
            )
            self.assertNotIn("--publish", args)
            self.assertNotIn("--cap-add", args)
        with self.assertRaises(Fail):
            Backend("container").run_detached(
                name="fixture",
                image="fixture-image",
                internal_port=53,
                mounts=[],
                lab_network=FIXTURE_NETWORK_NAME,
            )

    def test_lab_defaults_to_docker_and_rejects_container(self) -> None:
        parser = lab_cli.build_parser()
        self.assertEqual(parser.parse_args(["up"]).backend, "docker")
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["--backend", "container", "up"])
        self.assertEqual(
            run_cli.build_parser().parse_args(["--backend", "container", "up"]).backend,
            "container",
        )

    def test_network_is_internal_and_foreign_networks_are_refused(self) -> None:
        backend = Backend("docker")
        with (
            patch.object(backend, "_inspect_entry", return_value={}),
            patch.object(backend, "_run") as run,
        ):
            backend.ensure_lab_network(
                FIXTURE_NETWORK_NAME,
                FIXTURE_PUBLIC_SUBNET,
                ownership_labels("lab-fixture"),
            )
            self.assertIn("--internal", run.call_args.args)
        with patch.object(
            backend, "_inspect_entry", return_value={"Labels": {"foreign": "true"}}
        ):
            with self.assertRaises(Fail):
                backend.ensure_lab_network(
                    FIXTURE_NETWORK_NAME, FIXTURE_PUBLIC_SUBNET, ownership_labels()
                )
            with self.assertRaises(Fail):
                backend.remove_lab_network(FIXTURE_NETWORK_NAME, ownership_labels())

    def test_trust_and_cache_floor_are_lab_only(self) -> None:
        spec = ServiceSpec.load("squid")
        for interception in (False, True):
            text = render_test_policies(tls_interception=interception)[
                test_config_path(spec)
            ]
            self.assertIn("tls_outgoing_options cafile=/fixture/ca.pem", text)
            self.assertIn("negative_dns_ttl 1 seconds", text)
            self.assertNotIn("DONT_VERIFY", text)
            self.assertIn("http_access deny private_ip", text)
            operational = render_policies(tls_interception=interception)[
                spec.config_path()
            ]
            self.assertNotIn("/fixture/ca.pem", operational)
            self.assertNotIn("negative_dns_ttl", operational)
