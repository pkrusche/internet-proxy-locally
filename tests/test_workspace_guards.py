"""File modes and ownership must work across container users and CLI directories."""

from __future__ import annotations

import contextlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from internet_proxy_locally import paths
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.errors import Fail
from internet_proxy_locally.lifecycle import ownership_labels, remove_owned
from internet_proxy_locally.policy.render import render_policies, write_rendered


class WorkspaceGuardsTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="ipl-workspace-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_rendering_sets_and_repairs_public_config_permissions(self) -> None:
        path = self.root / "squid.conf"
        old_umask = os.umask(0o077)
        try:
            for text in ("first", "updated", "updated"):
                if path.exists():
                    path.chmod(0o600)
                self.assertEqual(write_rendered({path: text}), [path])
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                self.assertEqual(path.read_text(), text)
            self.assertEqual(write_rendered({path: "updated"}), [])
        finally:
            os.umask(old_umask)

    def test_subdirectories_and_root_aliases_share_ownership(self) -> None:
        (self.root / "config.toml").touch()
        child = self.root / "docs"
        child.mkdir()
        with patch.dict(os.environ, {"IPL_ROOT": ""}):
            with contextlib.chdir(self.root):
                expected = ownership_labels()
            with contextlib.chdir(child):
                self.assertEqual(paths.workspace_root(), self.root)
                self.assertEqual(ownership_labels(), expected)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with patch.dict(os.environ, {"IPL_ROOT": str(alias)}):
            self.assertEqual(ownership_labels(), expected)

    def test_separate_roots_cannot_remove_each_others_containers(self) -> None:
        backend = Mock(spec=Backend)
        backend.container_state.return_value = "running"
        with patch.dict(os.environ, {"IPL_ROOT": str(self.root / "first")}):
            first = ownership_labels()
        backend.container_labels.return_value = first
        with patch.dict(os.environ, {"IPL_ROOT": str(self.root / "second")}):
            self.assertNotEqual(ownership_labels(), first)
            with self.assertRaisesRegex(Fail, "foreign container"):
                remove_owned(backend, "internet-proxy-pipelock")
        backend.remove_container.assert_not_called()
        with patch.dict(os.environ, {"IPL_ROOT": str(self.root / "first")}):
            remove_owned(backend, "internet-proxy-pipelock")
        backend.remove_container.assert_called_once_with("internet-proxy-pipelock")

    def test_squid_configs_leave_privilege_drop_to_the_entrypoint(self) -> None:
        for enabled in (False, True):
            text = next(
                v
                for p, v in render_policies(tls_interception=enabled).items()
                if p.name == "squid.conf"
            )
            self.assertNotIn("cache_effective_user", text)
            self.assertNotIn("cache_effective_group", text)
