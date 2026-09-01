"""Tests for the lab lane (`ipl-lab`) — test policy, fixture, report.

Same fake-backend shim as tests/test_runpy.py, reused rather than copied:
the two CLIs share `start_engine()`, so a lab `up` has to be exercised
against the same emulated runtime or the reuse is untested.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from internet_proxy_locally import paths
from internet_proxy_locally.checks import egress

# Run from the repository root, so everything imports by name. See the
# comment in `verify.harness`.
from internet_proxy_locally.constants import DNS_FIXTURE, ENGINES, FIXTURE_CONTAINER
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lab.container import fixture_spec
from internet_proxy_locally.lab.fixtures import load_lab_config
from internet_proxy_locally.lab.render import (
    check_rendered_test_policies,
    render_test_policies,
    test_config_path,
)
from internet_proxy_locally.policy.config import load_policy_config
from internet_proxy_locally.policy.validate import (
    policy_allowlist,
    policy_allowlist_text,
)
from internet_proxy_locally.spec import ServiceSpec
from tests.test_runpy import PACKAGE_DATA, REPO_ROOT, RunPyCliTest


def _capture(pattern: str, text: str) -> str:
    """The one capture of `pattern` in `text`.

    A miss means the spec file changed shape, which is worth saying plainly:
    `.group(1)` straight off `re.search` reports it as an AttributeError on
    None, several frames from the pattern that actually stopped matching.
    """
    found = re.search(pattern, text)
    assert found is not None, f"{pattern} no longer matches:\n{text}"
    return found.group(1)


class LabCliTest(RunPyCliTest):
    """`ipl-lab` against the fake backend.

    Inherits the shim, the isolated repository and the pin helpers. The
    inherited `test_*` methods run again here, which is deliberate: they
    exercise `ipl` in a workspace that also holds lab/config/, and that
    combination is exactly what a real checkout is.
    """

    def setUp(self) -> None:
        super().setUp()
        # The rendered test configs are workspace, not package data: the
        # lab lane regenerates them and bind-mounts them into the engine.
        shutil.copytree(REPO_ROOT / "lab", self.tmp / "lab")

    def lab_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "internet_proxy_locally.cli.lab",
                *args,
            ],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=120,
            check=False,
        )

    def fake_dns_fixture_image(self) -> None:
        spec_text = (self.tmp / "data" / "lab" / "dnsfixture.toml").read_text()
        repo = _capture(r'repository = "([^"]+)"', spec_text)
        version = _capture(r'dnsmasq = "([^"]+)"', spec_text)
        self.fake_image(f"{repo}:{version}")

    def test_up_starts_the_dns_fixture_and_points_the_engine_at_it(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        up = self.lab_cli("--backend", "docker", "up")
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

    def test_up_mounts_the_test_policy_not_the_real_one(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        self.assertEqual(self.lab_cli("--backend", "docker", "up").returncode, 0)
        engine = next(
            l
            for l in self.backend_log().splitlines()
            if l.startswith("run ") and "internet-proxy-pipelock" in l
        )
        # Assert on the *host* side of --volume only. The container side is
        # /config/pipelock.yaml in both lanes by design — the engine reads
        # one fixed path — so matching the whole argument would pass for
        # the real policy too.
        args = engine.split()
        host_paths = [
            args[i + 1].split(":")[0] for i, a in enumerate(args) if a == "--volume"
        ]
        self.assertTrue(host_paths, engine)
        for host_path in host_paths:
            self.assertTrue(
                host_path.endswith("lab/config/pipelock.test.yaml"),
                f"mounted {host_path}, not the test policy",
            )

    def test_up_says_loudly_that_this_is_not_an_operational_proxy(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        up = self.lab_cli("--backend", "docker", "up")
        self.assertIn("TEST policy", up.stdout)
        # Saying it is not an operational proxy is half of it; naming the
        # command that gives you one is the other half.
        self.assertIn("`ipl up`", up.stdout)

    def test_normal_up_runs_no_dns_fixture(self) -> None:
        self.pin_pipelock()
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        runs = [l for l in self.backend_log().splitlines() if l.startswith("run ")]
        self.assertFalse([l for l in runs if "internet-proxy-dnsfixture" in l])
        engine = next(l for l in runs if "internet-proxy-pipelock" in l)
        self.assertNotIn("--dns", engine)

    def test_run_py_up_removes_a_stale_dns_fixture(self) -> None:
        # A fixture left over from `ipl-lab up` must not outlive the engine
        # it was attached to: it answers allowlisted names with private
        # addresses, and must never be running alongside a real policy.
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        self.assertEqual(self.lab_cli("--backend", "docker", "up").returncode, 0)
        self.assertTrue((self.state / "container-internet-proxy-dnsfixture").exists())
        up = self.run_cli("--backend", "docker", "up")
        self.assertEqual(up.returncode, 0, up.stderr)
        self.assertIn("removed existing container internet-proxy-dnsfixture", up.stdout)
        self.assertFalse((self.state / "container-internet-proxy-dnsfixture").exists())

    def test_run_py_down_removes_the_dns_fixture(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        self.assertEqual(self.lab_cli("--backend", "docker", "up").returncode, 0)
        down = self.run_cli("--backend", "docker", "down")
        self.assertEqual(down.returncode, 0)
        self.assertIn("removed internet-proxy-dnsfixture", down.stdout)

    def test_lab_down_removes_both(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        self.assertEqual(self.lab_cli("--backend", "docker", "up").returncode, 0)
        down = self.lab_cli("--backend", "docker", "down")
        self.assertEqual(down.returncode, 0)
        self.assertIn("removed internet-proxy-dnsfixture", down.stdout)
        self.assertIn("removed internet-proxy-pipelock", down.stdout)

    def test_up_refuses_without_the_fixture_image(self) -> None:
        self.pin_pipelock()  # fixture image deliberately absent
        proc = self.lab_cli("--backend", "docker", "up")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("DNS fixture image", proc.stderr)
        self.assertIn("ipl-lab setup", proc.stderr)

    def test_check_requires_running_engine(self) -> None:
        proc = self.lab_cli("--backend", "docker", "check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no engine is running", proc.stderr)

    def test_check_runs_the_full_group_and_wires_the_fixture_logs(self) -> None:
        self.pin_pipelock()
        self.fake_dns_fixture_image()
        self.assertEqual(self.lab_cli("--backend", "docker", "up").returncode, 0)
        proc = self.lab_cli("--backend", "docker", "check", "--json")
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["mode"], "full")
        self.assertTrue(any(r["group"] == "full" for r in payload["results"]))

    def test_policy_check_reports_drift_in_the_lab_configs(self) -> None:
        target = self.tmp / "lab" / "config" / "pipelock.test.yaml"
        target.write_text(target.read_text() + "\n# hand edit\n")
        proc = self.lab_cli("policy", "--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("STALE", proc.stderr)
        self.assertIn("hand edit", target.read_text(), "--check must not write")


class LabUnitTest(unittest.TestCase):
    """In-process tests for lab/fixtures.toml validation and rendering.

    `Fail` is imported straight from `errors` here. It used to have to be
    reached through the lab CLI's own reference to the run one, because loading a
    second copy of a module made `Fail` two classes and `assertRaises`
    stopped matching. One package removed the question.
    """

    # -- one source of truth for what the fixture serves ---------------------

    def test_the_fixture_facts_have_exactly_one_source(self) -> None:
        """lab/fixtures.toml, `checks.egress` and lab/dnsfixture/rebind.py
        used to state the same names three times, each with a "keep in
        sync" comment and nothing enforcing it.

        Now the checker reads the TOML and the container is built from it,
        so this asserts the wiring rather than the values: the checker
        agrees with the file, and every fact the responder needs actually
        reaches the image as a build arg.
        """
        fixture = load_lab_config().fixture
        self.assertEqual(egress.MIXED_FIXTURE_CONTROL, fixture.control)
        self.assertEqual(set(egress.MIXED_FIXTURE_TARGETS), set(fixture.targets))
        self.assertEqual(egress.REBIND_ZONE, fixture.rebind_zone)
        self.assertEqual(egress.PTR_FIXTURE_ADDRESS, fixture.ptr_address)
        self.assertEqual(egress.PTR_FIXTURE_CLAIMS, fixture.ptr_claims)

        args = fixture_spec().build_args
        self.assertEqual(args["REBIND_ZONE"], fixture.rebind_zone)
        self.assertEqual(args["PTR_ADDRESS"], fixture.ptr_address)
        self.assertEqual(args["PTR_CLAIMS"], fixture.ptr_claims)
        self.assertEqual(args["PUBLIC_ANSWER"], fixture.public_answer)

        # rebind.py must hold none of them as a literal, and the Dockerfile
        # must declare every ARG that carries one.
        fixture_image = PACKAGE_DATA / "lab" / "dnsfixture"
        rebind = (fixture_image / "rebind.py").read_text()
        dockerfile = (fixture_image / "Dockerfile").read_text()
        for arg, value in (
            ("REBIND_ZONE", fixture.rebind_zone),
            ("PTR_ADDRESS", fixture.ptr_address),
            ("PTR_CLAIMS", fixture.ptr_claims),
            ("PUBLIC_ANSWER", fixture.public_answer),
        ):
            self.assertFalse(
                f'"{value}"' in rebind,
                f"rebind.py restates {arg} ({value}) as a literal",
            )
            self.assertIn(f"ARG {arg}", dockerfile)
            self.assertIn(f'_required("{arg}")', rebind)

    # -- lab/fixtures.toml ---------------------------------------------------

    def fixture_config(self, **overrides) -> Path:
        """A complete lab/fixtures.toml whose `[fixture]` can be perturbed.

        The real allowlist is read from the checkout's config.toml, so these
        exercise the same cross-file check the CLI does.
        """
        tmp = Path(tempfile.mkdtemp(prefix="ipl-fixture-toml-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        table = {
            "control": '"public-only.fixture.test"',
            "rebind_zone": '"rebind.fixture.test"',
            "ptr_address": '"1.0.0.1"',
            "ptr_claims": '"pypi.org"',
            "records": {
                "public-only.fixture.test": '["9.9.9.9"]',
                "mixed-public-first.fixture.test": '["9.9.9.9", "10.0.0.1"]',
                "mixed-private-first.fixture.test": '["10.0.0.1", "9.9.9.9"]',
            },
            "allow_test": [
                "public-only.fixture.test",
                "mixed-public-first.fixture.test",
                "mixed-private-first.fixture.test",
                "*.rebind.fixture.test",
            ],
        }
        table.update(overrides)
        body = "[policy.test]\nallow = [\n"
        body += "".join(f'    "{entry}",\n' for entry in table["allow_test"])
        body += "]\n\n[fixture]\n"
        for key in ("control", "rebind_zone", "ptr_address", "ptr_claims"):
            if table[key] is not None:
                body += f"{key} = {table[key]}\n"
        body += "\n[fixture.records]\n"
        for name, addresses in table["records"].items():
            body += f'"{name}" = {addresses}\n'
        path = tmp / "fixtures.toml"
        path.write_text(body)
        return path

    def assertRefused(self, message: str, **overrides) -> None:
        with self.assertRaises(Fail) as caught:
            load_lab_config(self.fixture_config(**overrides))
        self.assertIn(message, str(caught.exception))

    def test_fixture_config_round_trips(self) -> None:
        config = load_lab_config(self.fixture_config())
        fixture = config.fixture
        self.assertEqual(fixture.control, "public-only.fixture.test")
        self.assertEqual(
            set(fixture.targets),
            {"mixed-public-first.fixture.test", "mixed-private-first.fixture.test"},
        )
        self.assertEqual(
            fixture.addresses("mixed-private-first.fixture.test"),
            ("10.0.0.1", "9.9.9.9"),
        )
        # The test policy carries the real allowlist too.
        self.assertEqual(config.allow, load_policy_config().allow)

    def test_fixture_table_is_required(self) -> None:
        # Without it the fixture has no records to serve, and
        # lab/config/dns-fixture.hosts could not be rendered at all.
        path = self.fixture_config()
        path.write_text(path.read_text().split("[fixture]")[0])
        with self.assertRaises(Fail) as caught:
            load_lab_config(path)
        self.assertIn("[fixture]", str(caught.exception))

    def test_rejects_a_record_the_test_policy_does_not_allowlist(self) -> None:
        self.assertRefused("not allowlisted by", allow_test=["*.rebind.fixture.test"])

    def test_rejects_a_test_policy_name_with_no_record(self) -> None:
        self.assertRefused(
            "does not serve",
            allow_test=[
                "public-only.fixture.test",
                "mixed-public-first.fixture.test",
                "mixed-private-first.fixture.test",
                "*.rebind.fixture.test",
                "ghost.fixture.test",
            ],
        )

    def test_rejects_a_control_that_proves_nothing(self) -> None:
        self.assertRefused(
            "exactly one address",
            records={
                "public-only.fixture.test": '["9.9.9.9", "10.0.0.1"]',
                "mixed-public-first.fixture.test": '["9.9.9.9", "10.0.0.1"]',
                "mixed-private-first.fixture.test": '["10.0.0.1", "9.9.9.9"]',
            },
        )
        self.assertRefused(
            "not a public address",
            records={
                "public-only.fixture.test": '["10.0.0.2"]',
                "mixed-public-first.fixture.test": '["9.9.9.9", "10.0.0.1"]',
                "mixed-private-first.fixture.test": '["10.0.0.1", "9.9.9.9"]',
            },
        )

    def test_requires_a_mixture_and_both_orderings(self) -> None:
        self.assertRefused(
            "must mix one public and one private",
            records={
                "public-only.fixture.test": '["9.9.9.9"]',
                "mixed-public-first.fixture.test": '["9.9.9.9", "8.8.8.8"]',
                "mixed-private-first.fixture.test": '["10.0.0.1", "9.9.9.9"]',
            },
        )
        self.assertRefused(
            "both answer orderings",
            records={
                "public-only.fixture.test": '["9.9.9.9"]',
                "mixed-public-first.fixture.test": '["9.9.9.9", "10.0.0.1"]',
                "mixed-private-first.fixture.test": '["9.9.9.9", "10.0.0.2"]',
            },
        )

    def test_rejects_a_ptr_claim_the_real_policy_does_not_allow(self) -> None:
        self.assertRefused(
            "ptr_claims must be an exact entry", ptr_claims='"not-allowlisted.example"'
        )

    def test_rejects_a_ptr_address_it_also_serves(self) -> None:
        self.assertRefused("is also a record address", ptr_address='"9.9.9.9"')

    def test_rejects_an_unallowlisted_rebind_zone(self) -> None:
        self.assertRefused(
            "needs `*.rebind.fixture.test`",
            allow_test=[
                "public-only.fixture.test",
                "mixed-public-first.fixture.test",
                "mixed-private-first.fixture.test",
            ],
        )

    def test_rejects_a_test_entry_the_real_policy_already_allows(self) -> None:
        real = load_policy_config().allow[0]
        self.assertRefused(
            "config.toml already permits",
            allow_test=[
                "public-only.fixture.test",
                "mixed-public-first.fixture.test",
                "mixed-private-first.fixture.test",
                "*.rebind.fixture.test",
                real,
            ],
        )

    def test_rejects_an_empty_test_allowlist(self) -> None:
        """Without it the test policy *is* the real one, and every
        adversarial check would skip while the run still looked green."""
        path = self.fixture_config()
        body = path.read_text()
        path.write_text(
            "[policy.test]\nallow = []\n" + body[body.index("\n[fixture]") :]
        )
        with self.assertRaises(Fail) as caught:
            load_lab_config(path)
        self.assertIn("must not be empty", str(caught.exception))

    # -- rendering -----------------------------------------------------------

    def test_shipped_lab_configs_match_the_sources(self) -> None:
        for path, body in render_test_policies().items():
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                body,
                f"run `ipl-lab policy` and commit {path.name}",
            )

    def test_rendered_test_policies_validate(self) -> None:
        rendered = render_test_policies()
        self.assertEqual(check_rendered_test_policies(rendered), [])

    def test_test_policy_is_a_strict_superset(self) -> None:
        """Every entry the real policy allows must survive into the test one.

        A `.test` run measuring a *narrower* policy than the one that ships
        would produce verdicts that do not transfer.
        """
        rendered = render_test_policies()
        for engine in ENGINES:
            spec = ServiceSpec.load(engine)
            real = policy_allowlist(engine, spec.config_path())
            test = policy_allowlist_text(engine, rendered[test_config_path(spec)])
            self.assertTrue(real <= test, f"{engine}: test policy drops {real - test}")
            self.assertTrue(test - real, f"{engine}: test policy adds nothing")

    def test_superset_violation_is_reported(self) -> None:
        rendered = dict(render_test_policies())
        spec = ServiceSpec.load("pipelock")
        path = test_config_path(spec)
        # An exact entry: a wildcard one renders quoted, and dropping the
        # wrong string would leave the file unchanged and the test vacuous.
        entry = next(e for e in load_policy_config().allow if not e.startswith("*."))
        before = rendered[path]
        rendered[path] = before.replace(f"  - {entry}\n", "", 1)
        self.assertNotEqual(before, rendered[path], "the entry was not removed")
        problems = check_rendered_test_policies(rendered)
        self.assertTrue(
            any("strict superset" in p and entry in p for p in problems), problems
        )

    def test_fixture_hosts_is_generated_from_the_fixture_table(self) -> None:
        spec = fixture_spec()
        hosts = REPO_ROOT / spec.config_file
        rendered = render_test_policies()
        self.assertIn(hosts, rendered)
        self.assertEqual(
            hosts.read_text(encoding="utf-8"),
            rendered[hosts],
            "run `ipl-lab policy` and commit lab/config/dns-fixture.hosts",
        )
        self.assertIn("GENERATED FILE", rendered[hosts])
        fixture = load_lab_config().fixture
        for name, addresses in fixture.records:
            for address in addresses:
                self.assertRegex(
                    rendered[hosts], rf"(?m)^{re.escape(address)}\s+{re.escape(name)}$"
                )

    # -- the fixture's own constants ----------------------------------------

    def test_checker_constants_match_the_fixture_table(self) -> None:
        """`checks.egress` names the fixture records in its own constants;
        lab/fixtures.toml is what the fixture actually serves."""
        fixture = load_lab_config().fixture
        self.assertEqual(egress.MIXED_FIXTURE_CONTROL, fixture.control)
        self.assertEqual(set(egress.MIXED_FIXTURE_TARGETS), set(fixture.targets))
        self.assertEqual(egress.REBIND_ZONE, fixture.rebind_zone)
        self.assertEqual(egress.PTR_FIXTURE_ADDRESS, fixture.ptr_address)
        self.assertEqual(egress.PTR_FIXTURE_CLAIMS, fixture.ptr_claims)

    def test_dns_fixture_records_cover_the_checker_names(self) -> None:
        """The hosts file and `checks.egress` must agree, and the mixed
        names must each carry one public and one private address in both
        orderings — that is the whole content of the check."""
        spec = fixture_spec()
        records: dict[str, list[str]] = {}
        for line in (REPO_ROOT / spec.config_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            address, *names = line.split()
            for name in names:
                records.setdefault(name, []).append(address)

        self.assertEqual(
            len(records.get(egress.MIXED_FIXTURE_CONTROL, [])),
            1,
            "the control must resolve to exactly one address",
        )
        self.assertFalse(
            any(
                ipaddress.ip_address(a).is_private
                for a in records[egress.MIXED_FIXTURE_CONTROL]
            )
        )

        orderings = set()
        for name in egress.MIXED_FIXTURE_TARGETS:
            addresses = records.get(name, [])
            self.assertEqual(len(addresses), 2, f"{name}: expected two records")
            private = [ipaddress.ip_address(a).is_private for a in addresses]
            self.assertEqual(
                sorted(private),
                [False, True],
                f"{name}: needs one public and one private address",
            )
            orderings.add(tuple(private))
        self.assertEqual(
            len(orderings),
            2,
            "both answer orderings must be represented, or an engine that "
            "validates only the first address would not be distinguished",
        )

    # -- the lane boundary ---------------------------------------------------

    def test_the_dns_fixture_is_not_an_engine(self) -> None:
        self.assertNotIn(DNS_FIXTURE, ENGINES)
        spec = fixture_spec()
        self.assertEqual(spec.root, paths.lab_dir())
        self.assertFalse((PACKAGE_DATA / "services" / "dnsfixture.toml").exists())

    def test_run_py_knows_the_fixture_container_name(self) -> None:
        """The operational lane removes the fixture by name without loading it.

        The constant is the whole coupling, so it is asserted rather than
        trusted: a rename in lab/dnsfixture.toml would otherwise leave a
        fixture running under a real policy.
        """
        self.assertEqual(FIXTURE_CONTAINER, fixture_spec().container_name)

    def test_the_operational_lane_cannot_reach_the_fixture(self) -> None:
        """The split is the point: `ipl` must not grow this back.

        Asserted on the import graph rather than by grepping one file for
        banned words, which is what this used to do and which a module
        split would have quietly defeated. A fresh interpreter imports the
        operational CLI and nothing else; if any lab module is loaded when
        it finishes, something in the operational lane imported it, and
        `ipl up` can reach the machinery that starts a resolver answering
        allowlisted names with private addresses.
        """
        probe = (
            "import sys; import internet_proxy_locally.cli.run; "
            "print([m for m in sys.modules "
            "if m.startswith('internet_proxy_locally.lab')])"
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            proc.stdout.strip(), "[]", "the operational lane imported the lab lane"
        )

    def test_config_toml_rejects_the_test_tables(self) -> None:
        """A `[fixture]` or `[policy.test]` left in config.toml is a mistake
        with a specific fix, so it gets a specific message."""
        tmp = Path(tempfile.mkdtemp(prefix="ipl-split-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "config.toml"
        path.write_text('[policy]\nallow = ["pypi.org"]\n\n[fixture]\ncontrol = "x"\n')
        with self.assertRaises(Fail) as caught:
            load_policy_config(path)
        self.assertIn("lab/fixtures.toml", str(caught.exception))

        path.write_text('[policy]\nallow = ["pypi.org"]\n\n[policy.test]\nallow = []\n')
        with self.assertRaises(Fail) as caught:
            load_policy_config(path)
        self.assertIn("lab/fixtures.toml", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
