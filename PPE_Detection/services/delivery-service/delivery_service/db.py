import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import get_default_local_url, get_default_service_id


SCHEMA = """
CREATE TABLE IF NOT EXISTS kv_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    status TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.transaction() as connection:
            connection.executescript(SCHEMA)
            defaults = {
                "control_center_url": "",
                "control_center_runtime_url": "",
                "service_id": get_default_service_id(),
                "service_secret": "",
                "local_url": get_default_local_url(),
                "service_type": "delivery_service",
                "registered": False,
                "config_version": 0,
                "settings": {
                    "heartbeat_interval_sec": 10,
                    "send_timeout_sec": 10,
                    "max_local_queue_size": 20,
                    "accepted_target_kinds": ["webhook", "email"],
                    "rules": [
                        {
                            "name": "all_webhooks",
                            "enabled": True,
                            "target_kinds": ["webhook"],
                            "when": {"decisions": ["permit-access", "deny-access", "error"]},
                            "channel": "webhook",
                        },
                        {
                            "name": "violations_email",
                            "enabled": False,
                            "target_kinds": ["email"],
                            "when": {"decisions": ["deny-access", "error"]},
                            "channel": "email",
                        },
                    ],
                    "channels": {
                        "webhook": {
                            "enabled": True,
                            "url": "",
                            "method": "POST",
                            "headers": {},
                            "secret_header": "X-PPE-Signature",
                            "secret": "",
                        },
                        "email": {
                            "enabled": False,
                            "mode": "log",
                            "smtp_host": "",
                            "smtp_port": 587,
                            "smtp_tls": True,
                            "username": "",
                            "password": "",
                            "from": "",
                            "to": [],
                            "subject_template": "PPE inspection: {decision}",
                        },
                    },
                    "logging": {
                        "enabled": True,
                        "store_local_events": True,
                        "forward_to_control_center": True,
                        "include_payloads": True,
                        "classes": {
                            "aaa": {"enabled": True, "mode": "all"},
                            "bootstrap": {"enabled": True, "mode": "all"},
                            "registration": {"enabled": True, "mode": "all"},
                            "heartbeat": {"enabled": True, "mode": "all"},
                            "delivery": {"enabled": True, "mode": "all"},
                            "config": {"enabled": True, "mode": "all"},
                            "system": {"enabled": True, "mode": "all"},
                        },
                    },
                },
                "desired_settings": {},
                "last_error": "",
                "connection_status": "not_configured",
                "runtime_registration_status": "pending",
                "last_registration_status": "idle",
                "last_registration_message": "",
                "last_connection_check_at": "",
                "last_heartbeat_status": "idle",
                "last_registration_at": "",
                "last_heartbeat_at": "",
                "tls_enrolled": False,
                "tls_expires_at": "",
                "tls_serial_hex": "",
                "restart_required": False,
                "tls_serial_hex": "",
            }
            for key, value in defaults.items():
                if connection.execute("SELECT 1 FROM kv_state WHERE key = ?", (key,)).fetchone() is None:
                    connection.execute("INSERT INTO kv_state (key, value) VALUES (?, ?)", (key, json.dumps(value)))

    def get(self, key: str, default: Any = None) -> Any:
        with self.connect() as connection:
            row = connection.execute("SELECT value FROM kv_state WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        return json.loads(row["value"])

    def set(self, key: str, value: Any) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO kv_state (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, json.dumps(value)),
            )

    def append_history(self, task_id: str, request_id: str, status: str, details: dict[str, Any]) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO delivery_history (task_id, request_id, status, details_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (task_id, request_id, status, json.dumps(details), utcnow()),
            )

    def get_history(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT task_id, request_id, status, details_json, created_at FROM delivery_history ORDER BY id DESC LIMIT 100"
            ).fetchall()
        return [
            {
                "task_id": row["task_id"],
                "request_id": row["request_id"],
                "status": row["status"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def append_event(self, category: str, status: str, message: str, details: dict[str, Any] | None = None) -> None:
        payload = details or {}
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO event_log (category, status, message, details_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (category, status, message, json.dumps(payload), utcnow()),
            )

    def get_events(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT category, status, message, details_json, created_at FROM event_log ORDER BY id DESC LIMIT 200"
            ).fetchall()
        return [
            {
                "category": row["category"],
                "status": row["status"],
                "message": row["message"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
