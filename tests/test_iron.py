"""Iron policy translation and runtime wiring, without a container runtime."""

from __future__ import annotations

import ipaddress
import re
import unittest
from unittest.mock import patch

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.lab.render import render_test_policies, test_config_path
from internet_proxy_locally.policy.config import PolicyConfig
from internet_proxy_locally.policy.render import _iron_domain, render_policies
from internet_proxy_locally.spec import ServiceSpec


class IronTest(unittest.TestCase):
    def test_wildcards_require_a_subdomain_without_widening_exact_hosts(self) -> None:
        self.assertEqual(_iron_domain("*.example.test"), "?*.example.test")
        self.assertEqual(_iron_domain("example.test"), "example.test")
        policy = PolicyConfig(allow=("exact.test", "*.example.test"))
        text = render_policies(policy)[paths.config_dir() / "iron.yaml"]
        self.assertIn('        - "?*.example.test"\n', text)
        self.assertIn("        - exact.test\n", text)
        self.assertNotIn('        - "*.example.test"\n', text)
        self.assertNotIn("        - example.test\n", text)

    def test_empty_renderer_input_keeps_a_denying_allowlist(self) -> None:
        # TOML rejects empty allowlists; the renderer must also fail closed
        # if an in-process caller supplies one directly.
        text = render_policies(PolicyConfig(allow=()))[paths.config_dir() / "iron.yaml"]
        self.assertIn("  - name: allowlist\n", text)
        self.assertIn("      warn: false\n", text)
        self.assertIn("      domains: []\n", text)

    def test_destination_floors_match_squid_in_both_lanes_and_modes(self) -> None:
        for render in (render_policies, render_test_policies):
            for enabled in (False, True):
                with self.subTest(lane=render.__name__, interception=enabled):
                    rendered = render(tls_interception=enabled)
                    squid = next(
                        t for p, t in rendered.items() if p.stem.startswith("squid")
                    )
                    iron = next(
                        t for p, t in rendered.items() if p.stem.startswith("iron")
                    )
                    floors = set(
                        re.findall(
                            r"^acl (?:metadata_ip|private_ip) dst (.+)$",
                            squid,
                            re.MULTILINE,
                        )
                    )
                    actual = set(
                        re.findall(r'^    - "([\da-f:./]+)"$', iron, re.MULTILINE)
                    )
                    self.assertEqual(actual, floors)
                    for cidr in actual:
                        ipaddress.ip_network(cidr)
                    self.assertIn("dns:\n  enabled: false\n", iron)
                    self.assertNotIn("upstream_resolver:", iron)
                    self.assertIn('  tunnel_listen: ":1080"', iron)
                    for listener, port in (
                        ("http_listen", 8080),
                        ("https_listen", 8443),
                        ("listen", 9090),
                    ):
                        self.assertIn(f'  {listener}: "127.0.0.1:{port}"', iron)

    def test_lab_only_domains_and_ca_settings(self) -> None:
        spec = ServiceSpec.load("iron")
        for enabled in (False, True):
            operational = render_policies(tls_interception=enabled)[
                paths.config_dir() / "iron.yaml"
            ]
            lab = render_test_policies(tls_interception=enabled)[test_config_path(spec)]
            self.assertNotIn("public-only.fixture.test", operational)
            self.assertIn("public-only.fixture.test", lab)
            self.assertIn('"?*.rebind.fixture.test"', lab)
            for text in (operational, lab):
                self.assertIn("  mode: mitm" if enabled else "  mode: sni-only", text)
                self.assertEqual('  ca_cert: "/config/ca.pem"' in text, enabled)
                self.assertEqual('  ca_key: "/config/ca-key.pem"' in text, enabled)

    def test_both_backends_publish_only_the_explicit_proxy_and_mount_ca_read_only(
        self,
    ) -> None:
        spec = ServiceSpec.load("iron")
        for runtime in ("docker", "container"):
            for enabled in (False, True):
                with self.subTest(runtime=runtime, interception=enabled):
                    backend = Backend(runtime)
                    mounts = spec.mounts()
                    if enabled:
                        mounts += spec.ca_mounts()
                    with patch.object(backend, "_run") as run:
                        backend.run_detached(
                            name=spec.container_name,
                            image=spec.image,
                            internal_port=spec.internal_port,
                            mounts=mounts,
                            publish=("127.0.0.1", 18080),
                        )
                    args = run.call_args.args
                    self.assertEqual(args.count("--publish"), 1)
                    self.assertIn("127.0.0.1:18080:1080", args)
                    self.assertIn(
                        f"{paths.config_dir() / 'iron.yaml'}:/config/iron.yaml:ro", args
                    )
                    self.assertEqual(
                        any(":/config/ca-key.pem:ro" in a for a in args), enabled
                    )
                    self.assertEqual(args[-1], spec.image)

    def test_image_pin_version_and_launch_contract(self) -> None:
        spec = ServiceSpec.load("iron")
        text = (paths.image_dir() / "iron" / "Dockerfile").read_text()
        version = spec.image.rpartition(":")[2].split("-build")[0]
        self.assertIn(f"# iron-proxy {version},", text)
        self.assertIn(f"internal/version.Version={version}", text)
        self.assertIn(
            "checkout --detach c8724937fbe109b7fbc6ddb21490e15902b187c0", text
        )
        self.assertIn("CGO_ENABLED=0 go build", text)
        self.assertIn("./cmd/iron-proxy", text)
        self.assertIn('CMD ["-config", "/config/iron.yaml"]', text)
        self.assertIn("/src/LICENSE /licenses/iron-proxy.LICENSE", text)
