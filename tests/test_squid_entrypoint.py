"""Exercise the shipped bootstrap with real copies/modes, without root or Docker."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from internet_proxy_locally.backend import Backend
from internet_proxy_locally.images import SQUID_IMAGE, prepare_image
from internet_proxy_locally.policy.render import render_policies
from internet_proxy_locally.spec import ServiceSpec
from tests.test_runpy import PACKAGE_DATA

IMAGE_DIR = PACKAGE_DATA / "images/squid"


class SquidEntrypointTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ipl-squid-bootstrap-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source"
        self.shm = self.root / "shm"
        self.staged = self.shm / "ipl-squid-ca"
        self.bin = self.root / "bin"
        for path in (self.source, self.shm, self.bin):
            path.mkdir()
        self.fds = self.root / "fds"
        self.fds.mkdir()
        for fd in (1, 2):
            os.mkfifo(self.fds / str(fd))
        for name in ("ca.pem", "ca-key.pem"):
            path = self.source / name
            path.write_text("test-only " + name)
            path.chmod(0o600)
        self.addCleanup(self.relax_staging)
        # Only the absolute filesystem locations are remapped. The actual
        # entrypoint's control flow, cp/chmod, quoting and exec are exercised.
        self.script = (
            (IMAGE_DIR / "entrypoint.sh")
            .read_text()
            .replace("/dev/shm", str(self.shm))
            .replace("/run/ipl-ca", str(self.source))
            .replace("/proc/self/fd", str(self.fds))
        )
        self.stub(
            "su-exec",
            r"""
printf 'drop %s\n' "$1" >> "$TEST_LOG"
[ "${DROP_EXIT:-0}" -eq 0 ] || exit "$DROP_EXIT"
shift
exec "$@"
""",
        )
        self.stub(
            "squid-command",
            r"""
printf 'command pid=%s argc=%s args=%s\n' "$$" "$#" "$*" >> "$TEST_LOG"
exit "${COMMAND_EXIT:-0}"
""",
        )

    def relax_staging(self):
        if self.staged.is_dir() and not self.staged.is_symlink():
            self.staged.chmod(0o700)

    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body)
        path.chmod(0o755)

    def run_entrypoint(self, **env):
        (self.root / "events").write_text("")
        # Mock only runtime-owned identity/filesystem facts and root-only
        # chown. Never change real user IDs or touch /run or /dev/shm in tests.
        prefix = r"""
id() {
    case "$*" in
        '-u') printf '%s\n' "${BOOTSTRAP_UID:-0}" ;;
        '-u squid') printf '%s\n' "${SQUID_UID:-31}" ;;
        '-g squid') printf '%s\n' "${SQUID_GID:-31}" ;;
        *) return 1 ;;
    esac
}
stat() { printf '%s\n' "${FS_TYPE:-tmpfs}"; }
chown() {
    printf 'chown %s\n' "$*" >> "$TEST_LOG"
    [ "${FAIL_COMMAND:-}" != chown ]
    [ "$2" != "${FAIL_CHOWN_PATH:-}" ]
}
chmod() {
    [ "${FAIL_COMMAND:-}" != chmod ] || return 1
    command chmod "$@"
}
printf 'bootstrap pid=%s\n' "$$" >> "$TEST_LOG"
"""
        proc = subprocess.run(
            [
                "sh",
                "-c",
                prefix + self.script,
                "entrypoint",
                "squid-command",
                "arg with spaces",
            ],
            env={
                **os.environ,
                "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                "TEST_LOG": str(self.root / "events"),
                **env,
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        log = (self.root / "events").read_text()
        return proc, log

    def test_stages_private_copy_before_exec_without_modifying_host_key(self):
        before = {p.name: (p.read_bytes(), p.stat()) for p in self.source.iterdir()}
        proc, log = self.run_entrypoint()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.staged.stat().st_mode & 0o777, 0o500)
        for name, (content, stat) in before.items():
            source = self.source / name
            staged = self.staged / name
            self.assertEqual(staged.read_bytes(), content)
            self.assertEqual(staged.stat().st_mode & 0o777, 0o400)
            self.assertNotEqual(staged.stat().st_ino, stat.st_ino)
            self.assertEqual(source.read_bytes(), content)
            self.assertEqual(source.stat().st_mode, stat.st_mode)
            self.assertEqual(source.stat().st_uid, stat.st_uid)
        self.assertIn("chown 31:31", log)
        self.assertLess(log.index("chown"), log.index("drop 31:31"))
        for fd in (1, 2):
            event = f"chown 31:31 {self.fds / str(fd)}"
            self.assertIn(event, log)
            self.assertLess(log.index(event), log.index("drop 31:31"))
        bootstrap = log.splitlines()[0].removeprefix("bootstrap ")
        self.assertIn(f"command {bootstrap} argc=1 args=arg with spaces", log)

    def test_tls_off_executes_directly_without_root_or_staging(self):
        proc, log = self.run_entrypoint(BOOTSTRAP_UID="31", COMMAND_EXIT="7")
        self.assertEqual(proc.returncode, 7)
        self.assertNotIn("drop", log)
        self.assertNotIn("chown", log)
        self.assertFalse(self.staged.exists())
        bootstrap = log.splitlines()[0].removeprefix("bootstrap ")
        self.assertIn(f"command {bootstrap}", log)

    def test_disk_backed_staging_and_root_target_ids_are_rejected(self):
        for env in ({"FS_TYPE": "overlayfs"}, {"SQUID_UID": "0"}, {"SQUID_GID": "0"}):
            with self.subTest(env=env):
                proc, log = self.run_entrypoint(**env)
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn("command pid", log)
                self.assertNotIn("drop", log)
                self.assertFalse(self.staged.exists())

    def test_missing_key_and_permission_failures_never_launch_squid(self):
        for env in ({"FAIL_COMMAND": "chmod"}, {"FAIL_COMMAND": "chown"}):
            with self.subTest(env=env):
                proc, log = self.run_entrypoint(**env)
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn("drop", log)
                self.assertNotIn("command pid", log)
                self.relax_staging()
                for path in self.staged.iterdir():
                    path.unlink()
                self.staged.rmdir()
        (self.source / "ca-key.pem").unlink()
        proc, log = self.run_entrypoint()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("command pid", log)

    def test_existing_directory_or_symlink_is_not_overwritten(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                if symlink:
                    self.staged.symlink_to(self.source, target_is_directory=True)
                else:
                    self.staged.mkdir()
                proc, log = self.run_entrypoint()
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn("drop", log)
                self.assertNotIn("command pid", log)
                self.assertEqual(
                    (self.source / "ca-key.pem").read_text(), "test-only ca-key.pem"
                )
                if symlink:
                    self.staged.unlink()
                else:
                    self.staged.rmdir()

    def test_privilege_drop_failure_does_not_fall_back_to_root(self):
        proc, log = self.run_entrypoint(DROP_EXIT="7")
        self.assertEqual(proc.returncode, 7)
        self.assertIn("drop 31:31", log)
        self.assertNotIn("command pid", log)

    def test_logging_never_chowns_redirected_regular_files(self):
        output = self.fds / "1"
        output.unlink()
        output.write_text("must not change")
        proc, log = self.run_entrypoint()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("requires a runtime pipe on fd 1", proc.stderr)
        self.assertNotIn(f"chown 31:31 {output}", log)
        self.assertNotIn("drop", log)
        self.assertEqual(output.read_text(), "must not change")

    def test_logging_permission_failure_never_launches_squid(self):
        proc, log = self.run_entrypoint(FAIL_CHOWN_PATH=str(self.fds / "2"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("logging pipe fd 2", proc.stderr)
        self.assertNotIn("drop", log)
        self.assertNotIn("command pid", log)

    def test_image_and_configs_use_bootstrap_and_the_private_staged_copy(self):
        dockerfile = (IMAGE_DIR / "Dockerfile").read_text()
        self.assertIn('"su-exec=0.2-r3"', dockerfile)
        self.assertIn("USER squid", dockerfile)
        self.assertIn("mkdir -m 0700 /run/ipl-ca", dockerfile)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/ipl-squid-entrypoint"]', dockerfile)
        self.assertIn(
            'CMD ["/usr/sbin/squid", "-N", "-f", "/etc/squid/squid.conf"]', dockerfile
        )
        spec = ServiceSpec.load("squid")
        self.assertEqual(spec.ca_cert_mount, "/run/ipl-ca/ca.pem")
        self.assertEqual(spec.ca_key_mount, "/run/ipl-ca/ca-key.pem")
        for enabled in (False, True):
            config = next(
                v
                for p, v in render_policies(tls_interception=enabled).items()
                if p.name == "squid.conf"
            )
            self.assertEqual(
                "tls-key=/dev/shm/ipl-squid-ca/ca-key.pem" in config, enabled
            )
            self.assertNotIn("/run/ipl-ca", config)

    def test_old_image_cannot_skip_the_bootstrap_rebuild(self):
        backend = Mock(spec=Backend)
        backend.image_present.side_effect = lambda tag: (
            tag
            in {
                "internet-proxy-locally/squid:6.12-r0-build1",
                "internet-proxy-locally/squid:6.12-r0-build2",
            }
        )
        prepare_image(backend, "squid")
        self.assertEqual(SQUID_IMAGE, "internet-proxy-locally/squid:6.12-r0-build3")
        backend.build.assert_called_once_with(
            tag=SQUID_IMAGE, dockerfile=IMAGE_DIR / "Dockerfile", context=IMAGE_DIR
        )

    def verify_runtime(self, status, *, backend="docker", mode="on", **env):
        status_path = self.root / "pid1-status"
        status_path.write_text(status)
        script = (
            PACKAGE_DATA.parents[2] / "scripts/check-squid-runtime.sh"
        ).read_text()
        script = (
            script.replace("/proc/1/status", str(status_path))
            .replace("/dev/shm", str(self.shm))
            .replace("/run/ipl-ca", str(self.root / "inaccessible-source"))
        )
        runtime = r"""
fake_runtime() {
    [ "$1:$2:$3:$4:$5:$6" = exec:--user:squid:internet-proxy-squid:sh:-ec ] || exit 90
    shift 6
    diagnostic="$1"
    shift
    sh -ec "$TEST_PREFIX$diagnostic" "$@"
}
docker() { fake_runtime "$@"; }
container() { fake_runtime "$@"; }
"""
        prefix = r"""
id() {
    case "$*" in
        '-u'|'-u squid') printf '%s\n' "${SQUID_UID:-31}" ;;
        '-g squid') printf '%s\n' "${SQUID_GID:-31}" ;;
        *) return 1 ;;
    esac
}
stat() {
    if [ "$1" = -f ]; then
        printf '%s\n' "${FS_TYPE:-tmpfs}"
    else
        fixture_stat "$3"
    fi
}
"""
        # Real fixture modes, mocked container ownership on every host. Do not
        # accidentally compare macOS uid/gid against the fake Squid identity.
        cases = []
        if self.staged.exists():
            for path in (self.staged, *self.staged.iterdir()):
                mode_bits = path.stat().st_mode & 0o777
                cases.append(
                    f"{shlex.quote(str(path))}) printf '%s\\n' '{mode_bits:o}:31:31' ;;"
                )
        prefix += '\nfixture_stat() { case "$1" in\n' + "\n".join(cases)
        prefix += "\n*) return 1 ;;\nesac; }\n"
        return subprocess.run(
            ["sh", "-c", runtime + script, "check-squid", backend, mode],
            env={**os.environ, "TEST_PREFIX": prefix, **env},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_live_verifier_rejects_root_saved_ids_and_extra_groups(self):
        self.assertEqual(self.run_entrypoint()[0].returncode, 0)
        status = "Uid:\t31 31 31 31\nGid:\t31 31 31 31\nGroups:\t31\n"
        for backend in ("docker", "container"):
            proc = self.verify_runtime(status, backend=backend)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for changed in (
            status.replace("31 31 31 31", "31 31 0 31", 1),
            status.replace("Gid:\t31 31 31 31", "Gid:\t31 0 31 31"),
            status.replace("Groups:\t31", "Groups:\t31 0"),
            status.replace("Groups:\t31", "Groups:\t31 999"),
            "",
        ):
            with self.subTest(status=changed):
                proc = self.verify_runtime(changed)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("Squid runtime verification failed", proc.stderr)
        for env in ({"SQUID_UID": "0"}, {"SQUID_GID": "0"}, {"FS_TYPE": "overlayfs"}):
            self.assertNotEqual(self.verify_runtime(status, **env).returncode, 0)
        (self.staged / "ca-key.pem").chmod(0o644)
        proc = self.verify_runtime(status)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(
            "ca-key.pem mode/uid/gid: expected [400:31:31], got [644:31:31]",
            proc.stderr,
        )

    def test_live_verifier_reports_actual_identity_and_groups(self):
        for status, diagnostic in (
            ("Uid:\t31 31 0 31\n", "got [31:31:0:31]"),
            ("Gid:\t31 0 31 31\n", "got [31:0:31:31]"),
            ("Groups:\t31 999\n", "unexpected supplementary groups [31 999"),
        ):
            with self.subTest(status=status):
                proc = self.verify_runtime(status, mode="off")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(diagnostic, proc.stderr)

    def test_live_verifier_tls_off_accepts_no_supplementary_groups_but_no_ca_copy(self):
        status = "Uid:\t31 31 31 31\nGid:\t31 31 31 31\nGroups:\n"
        proc = self.verify_runtime(status, mode="off")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.run_entrypoint()[0].returncode, 0)
        self.assertNotEqual(self.verify_runtime(status, mode="off").returncode, 0)
