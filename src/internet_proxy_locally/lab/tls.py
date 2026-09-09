"""Ephemeral, name-constrained certificates for the lab's HTTPS origin."""

from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from internet_proxy_locally import paths
from internet_proxy_locally.ca import _safe_private_dir
from internet_proxy_locally.lab.fixtures import FixtureConfig


def directory() -> Path:
    return paths.fixture_tls_dir()


def generate(fixture: FixtureConfig) -> None:
    """Rotate at fixture startup. The CA signing key never leaves memory.

    Only the leaf key is mounted into the fixture. Engines receive the
    public CA, whose DNS name constraint prevents signing production names.
    This material is independent of the interception CA.
    """
    root = directory()
    _safe_private_dir(root)
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IPL lab origin CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.NameConstraints([x509.DNSName(".test")], None), critical=True
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fixture.control)])
        )
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in (*fixture.names, f"*.{fixture.rebind_zone}")]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    for name, data, mode in (
        ("ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM), 0o644),
        ("origin.pem", leaf.public_bytes(serialization.Encoding.PEM), 0o644),
        (
            "origin-key.pem",
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            0o600,
        ),
    ):
        staged = root / f".{name}"
        fd = os.open(
            staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(staged, root / name)
