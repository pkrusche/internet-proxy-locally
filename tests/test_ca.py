"""Tests for `ca.py` — the TLS-interception CA lifecycle.

Pure filesystem, no container/subprocess — the same isolation
`policy/validate.py`'s tests get. `IPL_ROOT` is pointed at a temporary
directory so `paths.ca_dir()` never touches the real checkout's `state/`.
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
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

    def test_export_reports_an_unwritable_destination_as_a_fail(self) -> None:
        ca.generate_ca()
        with self.assertRaises(Fail):
            ca.export_ca_cert(self.tmp / "no-such-dir" / "ca.pem")

    def test_export_copies_cert_bytes_only(self) -> None:
        ca.generate_ca()
        out = self.tmp / "exported.pem"
        ca.export_ca_cert(out)
        self.assertEqual(out.read_bytes(), ca.ca_cert_path().read_bytes())
        self.assertNotEqual(out.read_bytes(), ca.ca_key_path().read_bytes())

    def test_export_fails_with_no_ca_present(self) -> None:
        with self.assertRaises(Fail):
            ca.export_ca_cert(self.tmp / "exported.pem")


if __name__ == "__main__":
    unittest.main()
