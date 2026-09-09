"""The TLS-interception signing CA: generate, check, export."""

from __future__ import annotations

import datetime
import fcntl
import os
import stat
import tempfile
from contextlib import contextmanager
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
    try:
        validate_ca()
    except Fail:
        return False
    return True


def _lock_path() -> Path:
    return paths.ca_dir().parent / "ca.lock"


@contextmanager
def _ca_lock(*, exclusive: bool):
    parent = paths.ca_dir().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(_lock_path(), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _safe_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise Fail(f"unsafe CA directory: {path} is a symbolic link")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = stat.S_IMODE(path.stat().st_mode)
    if path.stat().st_uid != os.getuid() or mode & 0o077:
        raise Fail(
            f"unsafe CA directory {path}: must be owned by this user and mode 0700"
        )


def validate_ca() -> tuple[x509.Certificate, object]:
    """Parse and validate the complete managed CA pair, failing closed."""
    cert_path, key_path = ca_cert_path(), ca_key_path()
    present = (cert_path.exists(), key_path.exists())
    if present != (True, True):
        if any(present):
            raise Fail(
                "partial CA state: restore the missing file or run `ipl ca rotate`"
            )
        raise Fail("no CA exists yet — run `ipl ca init`")
    for path in (cert_path, key_path):
        if path.is_symlink() or not path.is_file():
            raise Fail(f"unsafe managed CA path: {path} must be a regular file")
        if path.stat().st_uid != os.getuid():
            raise Fail(f"unsafe managed CA path: {path} is owned by another user")
    if stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise Fail(f"unsafe CA key permissions on {key_path}: expected 0600")
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (ValueError, OSError) as exc:
        raise Fail(f"malformed CA material: {exc}") from exc
    if cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise Fail("CA certificate and private key do not match")
    now = datetime.datetime.now(datetime.UTC)
    if not (cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
        raise Fail("CA certificate is not currently valid")
    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise Fail("CA certificate is missing required CA extensions") from exc
    if not basic.ca or not usage.key_cert_sign:
        raise Fail("certificate is not authorized to sign certificates")
    return cert, key


def generate_ca(force: bool = False) -> None:
    """Write a P-256 ECDSA self-signed CA (cert + key) in PEM.

    Skipped if a CA already exists unless `force=True` — mirroring
    `images.py`'s `prepare_image()` skip/rebuild pattern, for the same
    reason: regenerating on every `up` would invalidate whatever already
    trusts the old cert (every sandbox that installed it into its trust
    store).
    """
    with _ca_lock(exclusive=True):
        cert_exists, key_exists = ca_cert_path().exists(), ca_key_path().exists()
        if cert_exists or key_exists:
            if cert_exists != key_exists:
                raise Fail(
                    "partial CA state: restore the pair or deliberately run `ipl ca rotate`"
                )
            if not force:
                validate_ca()
                return

        _generate_ca_locked()


def _generate_ca_locked() -> None:
    """Generate and transactionally replace a pair while holding the lock."""

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
        # Squid leaf authorityKeyIdentifier needs a matching CA subjectKeyIdentifier.
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    ca_dir = paths.ca_dir()
    _safe_private_dir(ca_dir)

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Create a fresh file with mode 0600 to avoid exposure during writes or rotation.
    staged = Path(tempfile.mkdtemp(prefix=".ca-generation-", dir=ca_dir))
    try:
        key_tmp, cert_tmp = staged / "ca-key.pem", staged / "ca.pem"
        fd = os.open(
            key_tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as fh:
            fh.write(key_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        cert_tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(cert_tmp, 0o644)
        # Readers take the shared operation lock. Preserve the prior pair so
        # either failed replace can be rolled back before releasing it.
        old_cert = ca_cert_path().read_bytes() if ca_cert_path().exists() else None
        old_key = ca_key_path().read_bytes() if ca_key_path().exists() else None
        try:
            os.replace(key_tmp, ca_key_path())
            os.replace(cert_tmp, ca_cert_path())
        except OSError:
            if old_key is not None:
                ca_key_path().write_bytes(old_key)
                os.chmod(ca_key_path(), 0o600)
            if old_cert is not None:
                ca_cert_path().write_bytes(old_cert)
                os.chmod(ca_cert_path(), 0o644)
            raise
        validate_ca()
    finally:
        for item in staged.iterdir():
            item.unlink(missing_ok=True)
        staged.rmdir()


def ca_info() -> tuple[str, datetime.datetime]:
    """The CA cert's subject and expiry, for `ipl ca status`."""
    with _ca_lock(exclusive=False):
        cert, _key = validate_ca()
    subject = cert.subject.rfc4514_string()
    return subject, cert.not_valid_after_utc


def export_ca_cert(destination: Path, *, overwrite: bool = False) -> None:
    """Copy the CA's public cert only — never the key — to `destination`."""
    with _ca_lock(exclusive=False):
        cert, _key = validate_ca()
        try:
            resolved = destination.resolve(strict=False)
            managed = {
                ca_cert_path().resolve(),
                ca_key_path().resolve(),
                _lock_path().resolve(),
            }
            if resolved in managed:
                raise Fail("export destination identifies managed CA state")
            if destination.exists() and not overwrite:
                raise Fail(
                    f"refusing to overwrite existing file {destination}; "
                    "pass --overwrite"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
            flags |= os.O_TRUNC if overwrite else os.O_EXCL
            fd = os.open(destination, flags, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(cert.public_bytes(serialization.Encoding.PEM))
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise Fail(
                f"cannot write the exported cert to {destination}: {exc}"
            ) from exc
