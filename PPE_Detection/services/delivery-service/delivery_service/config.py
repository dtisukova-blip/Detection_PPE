from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "delivery.db"
DEFAULT_SERVICE_ID = "delivery-01"
DEFAULT_PKI_DIR = BASE_DIR / "pki"


def get_db_path() -> Path:
    return Path(os.getenv("DELIVERY_DB", DEFAULT_DB_PATH))


def get_default_service_id() -> str:
    return os.getenv("DELIVERY_SERVICE_ID", DEFAULT_SERVICE_ID)


def get_default_local_url() -> str:
    return os.getenv("DELIVERY_LOCAL_URL", "")


def get_pki_dir() -> Path:
    return Path(os.getenv("DELIVERY_PKI_DIR", DEFAULT_PKI_DIR))


def get_host() -> str:
    return os.getenv("DELIVERY_HOST", "0.0.0.0")


def get_port() -> int:
    return int(os.getenv("DELIVERY_PORT", "8030"))
