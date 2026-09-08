"""The TLS-interception signing CA: generate, check, export.

Filesystem-only, no `Backend`/container dependency — matching how
`policy/validate.py` and `policy/config.py` stay pure and therefore
trivially unit-testable. Nothing here touches `project-sandbox`: getting
the cert into a sandbox's trust store is a manual step documented in
docs/tls-interception.md, the same way exporting `HTTP_PROXY` already is.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from internet_proxy_locally import paths
from internet_proxy_locally.errors import Fail

CA_SUBJECT = "internet-proxy-locally MITM CA"
CA_VALIDITY_DAYS = 3650


def ca_cert_path() -> Path:
    return paths.ca_dir() / "ca.pem"


def ca_key_path() -> Path:
    return paths.ca_dir() / "ca-key.pem"


def ca_present() -> bool:
    return ca_cert_path().is_file() and ca_key_path().is_file()


def generate_ca(force: bool = False) -> None:
    """Write a P-256 ECDSA self-signed CA (cert + key) in PEM.

    Skipped if a CA already exists unless `force=True` — mirroring
    `images.py`'s `prepare_image()` skip/rebuild pattern, for the same
    reason: regenerating on every `up` would invalidate whatever already
    trusts the old cert (every sandbox that installed it into its trust
    store).
    """
    if ca_present() and not force:
        return

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_SUBJECT)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # RFC 5280 4.2.1.2: "this extension MUST appear in all conforming CA
        # certificates". Squid's generated leaf certs mimic the origin's
        # extensions, so a leaf can carry an authorityKeyIdentifier; without
        # a matching subjectKeyIdentifier here, a verifier that matches those
        # two up has nothing to match against.
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    ca_dir = paths.ca_dir()
    # 0700: docs/tls-interception.md tells the reader to treat state/ as a
    # private-key store, and the default 0755 would not be one. The key's own
    # 0600 is the protection; this is the second lock on the same door.
    ca_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # os.open with the mode set at creation time, not chmod afterward —
    # chmod leaves a window where the key is world-readable between the
    # write and the permission change. The unlink is what makes that mode
    # apply on the `force=True` path too: open()'s mode argument is honoured
    # only when the file is *created*, so rotating onto an existing key file
    # would otherwise keep whatever permissions that file already had — the
    # rotate-after-compromise runbook writing a fresh key into a
    # world-readable file, silently.
    ca_key_path().unlink(missing_ok=True)
    fd = os.open(ca_key_path(), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key_bytes)
    finally:
        os.close(fd)

    ca_cert_path().write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ca_info() -> tuple[str, datetime.datetime]:
    """The CA cert's subject and expiry, for `ipl ca status`."""
    if not ca_present():
        raise Fail("no CA exists yet — run `ipl ca init`")
    try:
        cert = x509.load_pem_x509_certificate(ca_cert_path().read_bytes())
    except ValueError as exc:
        # `ipl ca status` is the command someone runs *because* something
        # looks wrong; an unreadable cert is the answer, not a traceback.
        raise Fail(
            f"{ca_cert_path()} is not a readable PEM certificate ({exc}) — "
            "run `ipl ca rotate` to replace it"
        ) from exc
    subject = cert.subject.rfc4514_string()
    return subject, cert.not_valid_after_utc


def export_ca_cert(destination: Path) -> None:
    """Copy the CA's public cert only — never the key — to `destination`."""
    if not ca_present():
        raise Fail("no CA exists yet — run `ipl ca init`")
    try:
        destination.write_bytes(ca_cert_path().read_bytes())
    except OSError as exc:
        # `--out` is a path a person typed; a missing parent directory or an
        # unwritable one is their problem to fix, not a traceback.
        raise Fail(f"cannot write the exported cert to {destination}: {exc}") from exc
