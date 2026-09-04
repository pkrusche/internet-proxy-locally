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

    def test_private_key_file_is_0600(self) -> None:
        ca.generate_ca()
        mode = ca.ca_key_path().stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

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
