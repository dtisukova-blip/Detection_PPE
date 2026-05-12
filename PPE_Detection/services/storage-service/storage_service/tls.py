from __future__ import annotations

import ipaddress
import ssl
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def ensure_pki_dir(pki_dir: Path) -> None:
    pki_dir.mkdir(parents=True, exist_ok=True)


def root_cert_path(pki_dir: Path) -> Path:
    return pki_dir / "root_ca.crt"


def cert_path(pki_dir: Path) -> Path:
    return pki_dir / "service.crt"


def key_path(pki_dir: Path) -> Path:
    return pki_dir / "service.key"


def has_tls_material(pki_dir: Path) -> bool:
    return cert_path(pki_dir).exists() and key_path(pki_dir).exists() and root_cert_path(pki_dir).exists()


def build_csr(common_name: str, local_url: str, pki_dir: Path) -> str:
    ensure_pki_dir(pki_dir)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host = urlparse(local_url).hostname or common_name
    san_items: list[x509.GeneralName] = [x509.DNSName(common_name)]
    try:
        san_items.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        san_items.append(x509.DNSName(host))
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path(pki_dir).write_bytes(key_bytes)
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def save_enrolled_certificate(pki_dir: Path, cert_pem: str, root_pem: str) -> None:
    ensure_pki_dir(pki_dir)
    cert_path(pki_dir).write_text(cert_pem)
    root_cert_path(pki_dir).write_text(root_pem)


def save_root_certificate(pki_dir: Path, root_pem: str) -> None:
    ensure_pki_dir(pki_dir)
    root_cert_path(pki_dir).write_text(root_pem)


def httpx_tls_kwargs(pki_dir: Path, use_client_cert: bool, insecure_skip_verify: bool = False) -> dict:
    kwargs: dict = {"verify": False}
    if use_client_cert and cert_path(pki_dir).exists() and key_path(pki_dir).exists():
        if insecure_skip_verify or not root_cert_path(pki_dir).exists():
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context(cafile=str(root_cert_path(pki_dir)))
        context.load_cert_chain(str(cert_path(pki_dir)), str(key_path(pki_dir)))
        kwargs["verify"] = context
    elif not insecure_skip_verify and root_cert_path(pki_dir).exists():
        kwargs["verify"] = str(root_cert_path(pki_dir))
    return kwargs
