"""Tests for `ca.py` — the TLS-interception CA lifecycle.

Pure filesystem, no container/subprocess. `IPL_ROOT` is pointed at a
temporary directory so `paths.ca_dir()` never touches the real checkout's
`state/`.
"""

from __future__ import annotations

import datetime
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from internet_proxy_locally import ca
from internet_proxy_locally.errors import Fail


class CaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ipl-ca-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.dict("os.environ", {"IPL_ROOT": str(self.tmp)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_generates_a_valid_p256_cert_and_key(self) -> None:
        ca.generate_ca()
        self.assertTrue(ca.ca_present())
        key = serialization.load_pem_private_key(
            ca.ca_key_path().read_bytes(), password=None
        )
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        self.assertEqual(key.curve.name, "secp256r1")
        cert = x509.load_pem_x509_certificate(ca.ca_cert_path().read_bytes())
        cert_public_key = cert.public_key()
        assert isinstance(cert_public_key, ec.EllipticCurvePublicKey)
        self.assertEqual(
            cert_public_key.public_numbers(), key.public_key().public_numbers()
        )

    def test_idempotent_without_force(self) -> None:
        ca.generate_ca()
        first = ca.ca_key_path().read_bytes()
        ca.generate_ca()
        self.assertEqual(ca.ca_key_path().read_bytes(), first)

    def test_force_produces_a_new_key(self) -> None:
        ca.generate_ca()
        first = ca.ca_key_path().read_bytes()
        ca.generate_ca(force=True)
        self.assertNotEqual(ca.ca_key_path().read_bytes(), first)

    def test_cert_is_usable_as_a_signing_ca(self) -> None:
        """The three extensions without which nothing can sign or chain."""
        ca.generate_ca()
        cert = x509.load_pem_x509_certificate(ca.ca_cert_path().read_bytes())
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(constraints.critical)
        self.assertTrue(constraints.value.ca)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(usage.critical)
        self.assertTrue(usage.value.key_cert_sign)
        # RFC 5280 requires this on every CA certificate.
        self.assertEqual(
            cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
            x509.SubjectKeyIdentifier.from_public_key(cert.public_key()),
        )

    def test_private_key_file_is_0600(self) -> None:
        ca.generate_ca()
        mode = ca.ca_key_path().stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_rotation_tightens_a_loosened_key_file(self) -> None:
        """`open(..., 0o600)` only applies on create, so rotate must unlink.

        The rotate-after-compromise runbook in docs/tls-interception.md
        writes a fresh private key over the old one; if it inherited the old
        file's permissions, that key would land world-readable.
        """
        ca.generate_ca()
        ca.ca_key_path().chmod(0o644)
        ca.generate_ca(force=True)
        self.assertEqual(ca.ca_key_path().stat().st_mode & 0o777, 0o600)

    def test_ca_dir_is_not_world_readable(self) -> None:
        ca.generate_ca()
        self.assertEqual(ca.ca_key_path().parent.stat().st_mode & 0o777, 0o700)

    def test_export_creates_a_missing_destination_parent(self) -> None:
        ca.generate_ca()
        destination = self.tmp / "no-such-dir" / "ca.pem"
        ca.export_ca_cert(destination)
        self.assertEqual(destination.read_bytes(), ca.ca_cert_path().read_bytes())

    def test_export_copies_cert_bytes_only(self) -> None:
        ca.generate_ca()
        out = self.tmp / "exported.pem"
        ca.export_ca_cert(out)
        self.assertEqual(out.read_bytes(), ca.ca_cert_path().read_bytes())
        self.assertNotEqual(out.read_bytes(), ca.ca_key_path().read_bytes())

    def test_export_fails_with_no_ca_present(self) -> None:
        with self.assertRaises(Fail):
            ca.export_ca_cert(self.tmp / "exported.pem")

    def pair_bytes(self):
        return {p: p.read_bytes() for p in (ca.ca_cert_path(), ca.ca_key_path())}

    def test_partial_and_malformed_pairs_are_rejected_without_replacement(self) -> None:
        ca.generate_ca()
        original = self.pair_bytes()
        for path in original:
            for contents in (None, b"not PEM"):
                with self.subTest(path=path.name, contents=contents):
                    if contents is None:
                        path.unlink()
                    else:
                        path.write_bytes(contents)
                    self.assertFalse(ca.ca_present())
                    with self.assertRaises(Fail):
                        ca.generate_ca()
                    self.assertEqual(
                        path.read_bytes() if path.exists() else None, contents
                    )
                    for other, data in original.items():
                        if other != path:
                            self.assertEqual(other.read_bytes(), data)
                    path.write_bytes(original[path])
                    if path == ca.ca_key_path():
                        path.chmod(0o600)

    def test_mismatched_key_is_rejected(self) -> None:
        ca.generate_ca()
        cert = ca.ca_cert_path().read_bytes()
        ca.generate_ca(force=True)
        ca.ca_cert_path().write_bytes(cert)
        with self.assertRaisesRegex(Fail, "do not match"):
            ca.validate_ca()

    def test_invalid_certificate_dates_and_signing_extensions_are_rejected(
        self,
    ) -> None:
        ca.generate_ca()
        cert, key = ca.validate_ca()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        now = datetime.datetime.now(datetime.UTC)
        for case in (
            "expired",
            "future",
            "missing-basic",
            "missing-usage",
            "not-ca",
            "no-signing",
        ):
            with self.subTest(case=case):
                before = now + datetime.timedelta(days=1 if case == "future" else -2)
                after = now + datetime.timedelta(days=-1 if case == "expired" else 2)
                builder = (
                    x509.CertificateBuilder()
                    .subject_name(cert.subject)
                    .issuer_name(cert.issuer)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(before)
                    .not_valid_after(after)
                )
                if case != "missing-basic":
                    builder = builder.add_extension(
                        x509.BasicConstraints(ca=case != "not-ca", path_length=None),
                        critical=True,
                    )
                if case != "missing-usage":
                    builder = builder.add_extension(
                        x509.KeyUsage(
                            digital_signature=False,
                            content_commitment=False,
                            key_encipherment=False,
                            data_encipherment=False,
                            key_agreement=False,
                            key_cert_sign=case != "no-signing",
                            crl_sign=True,
                            encipher_only=False,
                            decipher_only=False,
                        ),
                        critical=True,
                    )
                ca.ca_cert_path().write_bytes(
                    builder.sign(key, hashes.SHA256()).public_bytes(
                        serialization.Encoding.PEM
                    )
                )
                with self.assertRaises(Fail):
                    ca.validate_ca()

    def test_unsafe_key_permissions_and_managed_symlinks_are_rejected(self) -> None:
        ca.generate_ca()
        ca.ca_key_path().chmod(0o644)
        with self.assertRaisesRegex(Fail, "permissions"):
            ca.validate_ca()
        ca.ca_key_path().chmod(0o600)
        for path in (ca.ca_cert_path(), ca.ca_key_path()):
            with self.subTest(path=path.name):
                target = path.with_suffix(".saved")
                path.rename(target)
                path.symlink_to(target)
                with self.assertRaisesRegex(Fail, "regular file"):
                    ca.validate_ca()
                path.unlink()
                target.rename(path)

    def test_unsafe_ca_directory_is_rejected(self) -> None:
        directory = ca.ca_cert_path().parent
        directory.mkdir(parents=True, mode=0o755)
        directory.chmod(0o755)
        with self.assertRaisesRegex(Fail, "unsafe CA directory"):
            ca.generate_ca()
        directory.rmdir()
        target = self.tmp / "external"
        target.mkdir()
        directory.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(Fail, "symbolic link"):
            ca.generate_ca()
        self.assertEqual(list(target.iterdir()), [])

    def test_export_requires_overwrite_and_never_changes_managed_state(self) -> None:
        ca.generate_ca()
        before = self.pair_bytes()
        destination = self.tmp / "export.pem"
        destination.write_bytes(b"existing")
        with self.assertRaisesRegex(Fail, "overwrite"):
            ca.export_ca_cert(destination)
        self.assertEqual(destination.read_bytes(), b"existing")
        ca.export_ca_cert(destination, overwrite=True)
        self.assertEqual(destination.read_bytes(), before[ca.ca_cert_path()])
        for managed in before:
            alias = self.tmp / "alias"
            alias.symlink_to(managed)
            for path in (managed, alias):
                for overwrite in (False, True):
                    with (
                        self.subTest(path=path, overwrite=overwrite),
                        self.assertRaisesRegex(Fail, "managed CA state"),
                    ):
                        ca.export_ca_cert(path, overwrite=overwrite)
            alias.unlink()
        self.assertEqual(self.pair_bytes(), before)

    def test_export_does_not_follow_other_symlinks(self) -> None:
        ca.generate_ca()
        target = self.tmp / "target"
        target.write_bytes(b"preserve me")
        alias = self.tmp / "alias"
        alias.symlink_to(target)
        with self.assertRaises(Fail):
            ca.export_ca_cert(alias, overwrite=True)
        self.assertEqual(target.read_bytes(), b"preserve me")

    def test_failed_rotation_preserves_the_previous_pair(self) -> None:
        ca.generate_ca()
        before = self.pair_bytes()
        replace = os.replace
        for failing_call in (1, 2):
            calls = 0

            def fail_replace(source, destination, failing_call=failing_call):
                nonlocal calls
                calls += 1
                if calls == failing_call:
                    raise OSError("injected replacement failure")
                replace(source, destination)

            with self.subTest(failing_call=failing_call):
                with (
                    mock.patch.object(ca.os, "replace", side_effect=fail_replace),
                    self.assertRaises(OSError),
                ):
                    ca.generate_ca(force=True)
                self.assertEqual(self.pair_bytes(), before)
                self.assertTrue(ca.ca_present())
                self.assertEqual(ca.ca_key_path().stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    list(ca.ca_key_path().parent.glob(".ca-generation-*")), []
                )

    def test_failed_initial_generation_leaves_no_partial_pair(self) -> None:
        replace = os.replace

        def fail_certificate(source, destination):
            if destination == ca.ca_cert_path():
                raise OSError("injected replacement failure")
            replace(source, destination)

        with (
            mock.patch.object(ca.os, "replace", side_effect=fail_certificate),
            self.assertRaises(OSError),
        ):
            ca.generate_ca()
        self.assertFalse(ca.ca_key_path().exists())
        self.assertFalse(ca.ca_cert_path().exists())
        ca.generate_ca()
        self.assertTrue(ca.ca_present())


if __name__ == "__main__":
    unittest.main()
