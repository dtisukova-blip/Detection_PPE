from __future__ import annotations

import fcntl
import ipaddress
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PkiPaths:
    root_cert: Path
    root_key: Path
    control_center_cert: Path
    control_center_key: Path


def get_paths(pki_dir: Path) -> PkiPaths:
    pki_dir.mkdir(parents=True, exist_ok=True)
    return PkiPaths(
        root_cert=pki_dir / "root_ca.crt",
        root_key=pki_dir / "root_ca.key",
        control_center_cert=pki_dir / "control_center.crt",
        control_center_key=pki_dir / "control_center.key",
    )


def _save_pem(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_bytes(data)
    os.replace(tmp_path, path)


@contextmanager
def _pki_lock(pki_dir: Path):
    pki_dir.mkdir(parents=True, exist_ok=True)
    lock_path = pki_dir / ".pki.lock"
    with lock_path.open("w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _cert_covers_hosts(cert: x509.Certificate, hosts: Iterable[str]) -> bool:
    required = {host.strip() for host in hosts if host.strip()}
    if not required:
        return True
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False

    present: set[str] = set()
    for name in san:
        if isinstance(name, x509.DNSName):
            present.add(name.value)
        elif isinstance(name, x509.IPAddress):
            present.add(str(name.value))
    return required.issubset(present)


def _cert_signed_by_root(cert: x509.Certificate, root_cert: x509.Certificate) -> bool:
    try:
        root_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return cert.issuer == root_cert.subject
    except Exception:
        return False


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _serialize_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _build_san(hosts: Iterable[str]) -> x509.SubjectAlternativeName:
    san_items: list[x509.GeneralName] = []
    for host in hosts:
        host = host.strip()
        if not host:
            continue
        try:
            san_items.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san_items.append(x509.DNSName(host))
    return x509.SubjectAlternativeName(san_items)


def ensure_internal_ca(pki_dir: Path, control_center_hosts: list[str]) -> PkiPaths:
    with _pki_lock(pki_dir):
        paths = get_paths(pki_dir)
        if not paths.root_cert.exists() or not paths.root_key.exists():
            root_key = _new_key()
            subject = issuer = _name("PPE Root CA")
            now = utcnow()
            root_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(root_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, key_encipherment=False, key_agreement=False, content_commitment=False, data_encipherment=False, encipher_only=False, decipher_only=False, crl_sign=True), critical=True)
                .sign(root_key, hashes.SHA256())
            )
            _save_pem(paths.root_key, _serialize_key(root_key))
            _save_pem(paths.root_cert, _serialize_cert(root_cert))

        root_cert = _load_cert(paths.root_cert)
        need_reissue = not paths.control_center_cert.exists() or not paths.control_center_key.exists()
        if not need_reissue:
            current = _load_cert(paths.control_center_cert)
            need_reissue = (
                current.not_valid_after_utc <= utcnow()
                or not _cert_covers_hosts(current, control_center_hosts)
                or not _cert_signed_by_root(current, root_cert)
            )

        if need_reissue:
            issue_server_certificate(
                pki_dir=pki_dir,
                common_name="control-center",
                hosts=control_center_hosts,
                cert_path=paths.control_center_cert,
                key_path=paths.control_center_key,
                ttl_hours=24 * 30,
            )
    return paths


def issue_server_certificate(
    pki_dir: Path,
    common_name: str,
    hosts: list[str],
    cert_path: Path,
    key_path: Path,
    ttl_hours: int,
) -> tuple[str, str]:
    root_key = _load_key(get_paths(pki_dir).root_key)
    root_cert = _load_cert(get_paths(pki_dir).root_cert)
    leaf_key = _new_key()
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=ttl_hours))
        .add_extension(_build_san(hosts), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False, key_agreement=False, content_commitment=False, data_encipherment=False, encipher_only=False, decipher_only=False, crl_sign=False), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    _save_pem(key_path, _serialize_key(leaf_key))
    _save_pem(cert_path, _serialize_cert(cert))
    return cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8 or 1, "big").hex(), cert.not_valid_after_utc.isoformat()


def sign_service_csr(
    pki_dir: Path,
    csr_pem: str,
    ttl_hours: int,
) -> tuple[str, str, str]:
    root_key = _load_key(get_paths(pki_dir).root_key)
    root_cert = _load_cert(get_paths(pki_dir).root_cert)
    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    now = utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=ttl_hours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False, key_agreement=False, content_commitment=False, data_encipherment=False, encipher_only=False, decipher_only=False, crl_sign=False), critical=True)
    )
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san.value, critical=False)
    except x509.ExtensionNotFound:
        pass
    cert = builder.sign(root_key, hashes.SHA256())
    serial_hex = cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8 or 1, "big").hex()
    return _serialize_cert(cert).decode("utf-8"), serial_hex, cert.not_valid_after_utc.isoformat()


def root_certificate_pem(pki_dir: Path) -> str:
    return get_paths(pki_dir).root_cert.read_text()
