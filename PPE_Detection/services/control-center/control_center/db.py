import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
import secrets

from .security import hash_password


# The schema is intentionally explicit so it can later be moved to PostgreSQL
# with minimal semantic changes.
SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('root', 'admin', 'auditor')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id TEXT NOT NULL UNIQUE,
    service_type TEXT NOT NULL CHECK(service_type IN ('checkpoint', 'worker', 'storage', 'delivery_service', 'viewer', 'control_center')),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'registered' CHECK(status IN ('registered', 'active', 'disabled')),
    settings_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_service_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    access_level TEXT NOT NULL CHECK(access_level IN ('read', 'manage')),
    UNIQUE(user_id, service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS service_runtime_state (
    service_id INTEGER PRIMARY KEY,
    local_url TEXT,
    last_seen_at TEXT,
    registration_status TEXT NOT NULL DEFAULT 'pending' CHECK(registration_status IN ('pending', 'approved', 'denied')),
    config_version INTEGER NOT NULL DEFAULT 1,
    settings_updated_at TEXT NOT NULL,
    last_error TEXT,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS service_credentials (
    service_id INTEGER PRIMARY KEY,
    bootstrap_secret TEXT NOT NULL,
    rotated_at TEXT NOT NULL,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS inspection_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    checkpoint_service_id TEXT NOT NULL,
    worker_service_id TEXT,
    image_base64 TEXT NOT NULL,
    required_ppe_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('queued', 'leased', 'completed', 'timeout', 'failed')),
    result_json TEXT,
    created_at TEXT NOT NULL,
    leased_at TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS route_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    checkpoint_service_id INTEGER,
    worker_service_id INTEGER NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 100,
    is_active INTEGER NOT NULL DEFAULT 1,
    match_rules_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(checkpoint_service_id) REFERENCES services(id) ON DELETE CASCADE,
    FOREIGN KEY(worker_service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS route_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route_id INTEGER NOT NULL,
    target_service_id INTEGER NOT NULL,
    target_kind TEXT NOT NULL CHECK(target_kind IN ('database', 'webhook', 'email', 'viewer')),
    is_required INTEGER NOT NULL DEFAULT 0,
    order_index INTEGER NOT NULL DEFAULT 0,
    filter_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(route_id) REFERENCES route_bindings(id) ON DELETE CASCADE,
    FOREIGN KEY(target_service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS runtime_event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_class TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_service_id TEXT NOT NULL,
    source_service_type TEXT NOT NULL,
    request_id TEXT,
    job_id TEXT,
    severity TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL UNIQUE,
    route_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    checkpoint_service_id TEXT NOT NULL,
    worker_service_id TEXT,
    target_service_id TEXT NOT NULL,
    target_kind TEXT NOT NULL CHECK(target_kind IN ('database', 'webhook', 'email', 'viewer')),
    is_required INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK(status IN ('queued', 'leased', 'completed', 'failed')),
    payload_json TEXT NOT NULL,
    error_text TEXT,
    created_at TEXT NOT NULL,
    leased_at TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS service_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    serial_hex TEXT NOT NULL UNIQUE,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'replaced')),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoke_reason TEXT,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
);
"""


def utcnow() -> str:
    """Return a normalized UTC timestamp for stored entities and audit events."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    """Small SQLite helper used by the AAA layer."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        """Open a connection with dict-like access to columns."""
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Wrap write operations in a transaction with rollback on failure."""
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self, root_password: str) -> None:
        """
        Create the schema and bootstrap the built-in root account.

        On the first start we also register the control center itself as a
        manageable service so later RBAC can reference it the same way as other
        services in the ecosystem.
        """
        with self.transaction() as connection:
            connection.executescript(SCHEMA)
            self._ensure_runtime_schema_allows_new_types(connection)
            # Normalize legacy rows from the earlier "registered/active/disabled"
            # lifecycle into the current binary admin switch.
            connection.execute("UPDATE services SET status = 'active' WHERE status = 'registered'")
            existing_root = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                ("root",),
            ).fetchone()
            if existing_root is None:
                salt, password_hash = hash_password(root_password)
                connection.execute(
                    """
                    INSERT INTO users (username, password_salt, password_hash, role, created_at)
                    VALUES (?, ?, ?, 'root', ?)
                    """,
                    ("root", salt, password_hash, utcnow()),
                )
                connection.execute(
                    """
                    INSERT INTO services (service_id, service_type, display_name, status, settings_json, created_at)
                    VALUES (?, 'control_center', ?, 'active', '{}', ?)
                    """,
                    ("control-center", "Main Control Center", utcnow()),
                )
                service_row = connection.execute(
                    "SELECT id FROM services WHERE service_id = ?",
                    ("control-center",),
                ).fetchone()
                connection.execute(
                    """
                    INSERT INTO service_runtime_state (service_id, registration_status, config_version, settings_updated_at)
                    VALUES (?, 'approved', 1, ?)
                    """,
                    (service_row["id"], utcnow()),
                )
                connection.execute(
                    """
                    INSERT INTO service_credentials (service_id, bootstrap_secret, rotated_at)
                    VALUES (?, ?, ?)
                    """,
                    (service_row["id"], secrets.token_urlsafe(24), utcnow()),
                )

    def _ensure_runtime_schema_allows_new_types(self, connection: sqlite3.Connection) -> None:
        schema_rows = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name IN ('services', 'route_targets', 'delivery_tasks')"
        ).fetchall()
        replacements: list[tuple[str, str, str]] = []
        for row in schema_rows:
            sql = row["sql"]
            if row["name"] == "services":
                if "delivery_service" not in sql:
                    replacements.append(("services", "'storage', 'control_center'", "'storage', 'delivery_service', 'control_center'"))
                    sql = sql.replace("'storage', 'control_center'", "'storage', 'delivery_service', 'control_center'")
                if "viewer" not in sql:
                    replacements.append(("services", "'delivery_service', 'control_center'", "'delivery_service', 'viewer', 'control_center'"))
            if row["name"] in {"route_targets", "delivery_tasks"} and "viewer" not in sql:
                replacements.append((row["name"], "'webhook', 'email'", "'webhook', 'email', 'viewer'"))
        if not replacements:
            return
        current_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute("PRAGMA writable_schema = ON")
        for table_name, old_sql, new_sql in replacements:
            connection.execute(
                """
                UPDATE sqlite_master
                SET sql = replace(sql, ?, ?)
                WHERE type = 'table' AND name = ?
                """,
                (old_sql, new_sql, table_name),
            )
        connection.execute("PRAGMA writable_schema = OFF")
        connection.execute(f"PRAGMA schema_version = {current_version + 1}")

    def fetchone(self, query: str, params: tuple = ()) -> sqlite3.Row | None:
        """Fetch a single row from the database."""
        with self.connect() as connection:
            return connection.execute(query, params).fetchone()

    def fetchall(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Fetch multiple rows from the database."""
        with self.connect() as connection:
            return connection.execute(query, params).fetchall()
