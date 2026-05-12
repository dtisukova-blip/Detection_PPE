import hashlib
import hmac
import secrets
from typing import Tuple


# Local MVP choice: PBKDF2 is built into Python and keeps the auth layer simple.
PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> Tuple[str, str]:
    """Hash a password and return hex-encoded salt and digest."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, password_hash: str) -> bool:
    """Verify a plain password against the stored salt/hash pair."""
    salt = bytes.fromhex(salt_hex)
    _, computed_hash = hash_password(password, salt=salt)
    return hmac.compare_digest(computed_hash, password_hash)


def issue_token() -> str:
    """Issue an opaque bearer token for a user session."""
    return secrets.token_urlsafe(32)
