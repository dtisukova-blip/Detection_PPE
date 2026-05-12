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

CREATE TABLE IF NOT EXISTS viewer_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL,
    checkpoint_service_id TEXT NOT NULL,
    worker_service_id TEXT,
    decision TEXT NOT NULL,
    decision_label TEXT NOT NULL,
    reason_code TEXT,
    reason_text TEXT,
    required_ppe_json TEXT NOT NULL,
    missing_required_json TEXT NOT NULL,
    detections_json TEXT NOT NULL,
    annotated_image_base64 TEXT,
    annotated_image_media_type TEXT,
    inspection_created_at TEXT,
    inspection_processed_at TEXT,
    inspection_completed_at TEXT,
    received_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
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
                "service_type": "viewer",
                "registered": False,
                "config_version": 0,
                "settings": {
                    "heartbeat_interval_sec": 10,
                    "max_local_queue_size": 200,
                    "accepted_target_kinds": ["viewer"],
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

    def append_record(self, task: dict[str, Any]) -> None:
        payload = task["payload"]
        now = utcnow()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO viewer_records
                (task_id, request_id, checkpoint_service_id, worker_service_id, decision, decision_label, reason_code,
                 reason_text, required_ppe_json, missing_required_json, detections_json, annotated_image_base64,
                 annotated_image_media_type, inspection_created_at, inspection_processed_at, inspection_completed_at,
                 received_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    decision = excluded.decision,
                    decision_label = excluded.decision_label,
                    reason_code = excluded.reason_code,
                    reason_text = excluded.reason_text,
                    required_ppe_json = excluded.required_ppe_json,
                    missing_required_json = excluded.missing_required_json,
                    detections_json = excluded.detections_json,
                    annotated_image_base64 = excluded.annotated_image_base64,
                    annotated_image_media_type = excluded.annotated_image_media_type,
                    inspection_created_at = excluded.inspection_created_at,
                    inspection_processed_at = excluded.inspection_processed_at,
                    inspection_completed_at = excluded.inspection_completed_at,
                    received_at = excluded.received_at,
                    payload_json = excluded.payload_json
                """,
                (
                    task["task_id"],
                    task["request_id"],
                    task["checkpoint_service_id"],
                    task.get("worker_service_id") or payload.get("worker_service_id"),
                    payload.get("decision") or "error",
                    payload.get("decision_label") or payload.get("decision") or "Ошибка проверки",
                    payload.get("reason_code"),
                    payload.get("reason_text"),
                    json.dumps(payload.get("required_ppe", []), ensure_ascii=False),
                    json.dumps(payload.get("missing_required", []), ensure_ascii=False),
                    json.dumps(payload.get("detections", []), ensure_ascii=False),
                    payload.get("annotated_image_base64"),
                    payload.get("annotated_image_media_type"),
                    payload.get("inspection_created_at"),
                    payload.get("inspection_processed_at"),
                    payload.get("inspection_completed_at"),
                    now,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )

    def get_records(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT task_id, request_id, checkpoint_service_id, worker_service_id, decision, decision_label,
                       reason_code, reason_text, required_ppe_json, missing_required_json, detections_json,
                       annotated_image_base64, annotated_image_media_type, inspection_created_at,
                       inspection_processed_at, inspection_completed_at, received_at, payload_json
                FROM viewer_records
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "task_id": row["task_id"],
                "request_id": row["request_id"],
                "checkpoint_service_id": row["checkpoint_service_id"],
                "worker_service_id": row["worker_service_id"],
                "decision": row["decision"],
                "decision_label": row["decision_label"],
                "reason_code": row["reason_code"],
                "reason_text": row["reason_text"],
                "required_ppe": json.loads(row["required_ppe_json"]),
                "missing_required": json.loads(row["missing_required_json"]),
                "detections": json.loads(row["detections_json"]),
                "annotated_image_base64": row["annotated_image_base64"],
                "annotated_image_media_type": row["annotated_image_media_type"],
                "inspection_created_at": row["inspection_created_at"],
                "inspection_processed_at": row["inspection_processed_at"],
                "inspection_completed_at": row["inspection_completed_at"],
                "received_at": row["received_at"],
                "payload": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def count_records(self) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM viewer_records").fetchone()
        return int(row["total"]) if row else 0

    def trim_records(self, max_records: int) -> None:
        if max_records <= 0:
            return
        with self.transaction() as connection:
            connection.execute(
                """
                DELETE FROM viewer_records
                WHERE id NOT IN (
                    SELECT id FROM viewer_records ORDER BY id DESC LIMIT ?
                )
                """,
                (max_records,),
            )

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
