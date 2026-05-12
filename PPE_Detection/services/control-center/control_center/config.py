from pathlib import Path
import os
import socket


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "control_center.db"
DEFAULT_PKI_DIR = BASE_DIR / "pki"


def get_db_path() -> Path:
    return Path(os.getenv("CONTROL_CENTER_DB", DEFAULT_DB_PATH))


def get_root_password() -> str:
    return os.getenv("CONTROL_CENTER_ROOT_PASSWORD", "change-me-root")


def get_pki_dir() -> Path:
    return Path(os.getenv("CONTROL_CENTER_PKI_DIR", DEFAULT_PKI_DIR))


def get_ui_host() -> str:
    return os.getenv("CONTROL_CENTER_HOST", "0.0.0.0")


def get_ui_port() -> int:
    return int(os.getenv("CONTROL_CENTER_PORT", "8000"))


def get_runtime_port() -> int:
    return int(os.getenv("CONTROL_CENTER_RUNTIME_PORT", "8443"))


def get_tls_public_hosts() -> list[str]:
    raw = os.getenv("CONTROL_CENTER_TLS_HOSTS", "localhost,127.0.0.1")
    hosts = {item.strip() for item in raw.split(",") if item.strip()}
    hosts.add("localhost")
    hosts.add("127.0.0.1")
    try:
        hostname = socket.gethostname()
        if hostname:
            hosts.add(hostname)
        fqdn = socket.getfqdn()
        if fqdn:
            hosts.add(fqdn)
        for candidate in {hostname, fqdn} - {""}:
            try:
                for result in socket.getaddrinfo(candidate, None):
                    address = result[4][0]
                    if address:
                        hosts.add(address)
            except socket.gaierror:
                continue
    except Exception:
        pass
    return sorted(hosts)


def is_runtime_mtls_enabled() -> bool:
    return os.getenv("CONTROL_CENTER_RUNTIME_MTLS", "1") not in {"0", "false", "False"}
