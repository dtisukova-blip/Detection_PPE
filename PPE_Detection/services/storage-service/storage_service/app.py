import asyncio
import json
import os
from pathlib import Path
import sqlite3
from typing import Any
from urllib.parse import unquote, urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import get_db_path, get_pki_dir
from .db import Database, utcnow
from .tls import build_csr, has_tls_material, httpx_tls_kwargs, root_cert_path, save_enrolled_certificate, save_root_certificate


STATIC_DIR = Path(__file__).resolve().parent / "static"
app = FastAPI(title="PPE Storage Service", version="0.1.0")
SERVICE_TYPE = "storage"


class ControlCenterConfigRequest(BaseModel):
    control_center_url: str = Field(min_length=1)
    control_center_runtime_url: str | None = None
    service_id: str = Field(min_length=1)
    service_secret: str | None = None
    local_url: str = Field(min_length=1)


class LocalSettingsRequest(BaseModel):
    settings: dict[str, Any] = Field(default_factory=dict)


class InternalConfigApplyRequest(BaseModel):
    service_id: str = Field(min_length=1)
    service_secret: str = Field(min_length=1)
    config_version: int
    settings: dict[str, Any] = Field(default_factory=dict)


class InternalDeliveryTaskRequest(BaseModel):
    service_id: str = Field(min_length=1)
    service_secret: str = Field(min_length=1)
    task: dict[str, Any] = Field(default_factory=dict)


class OperatorLoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


def is_bootstrap_configured(db: Database) -> bool:
    return bool(db.get("control_center_url")) and bool(db.get("service_id")) and bool(db.get("service_secret"))


def normalize_http_url(value: str, field_name: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must start with http:// or https://")
    return normalized


def normalize_https_url(value: str, field_name: str) -> str:
    normalized = normalize_http_url(value, field_name)
    parsed = urlparse(normalized)
    if parsed.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must start with https://",
        )
    return normalized


def normalize_local_url(value: str, field_name: str = "local_url") -> str:
    local_url = normalize_http_url(value, field_name)
    if has_tls_material(get_pki_dir()) and local_url.startswith("http://"):
        return f"https://{local_url.removeprefix('http://')}"
    return local_url


def normalize_local_url_for_tls(db: Database) -> None:
    local_url = str(db.get("local_url") or "").strip()
    if local_url.startswith("http://") and has_tls_material(get_pki_dir()):
        db.set("local_url", f"https://{local_url.removeprefix('http://')}")


async def restart_process(delay_sec: float = 1.0) -> None:
    await asyncio.sleep(delay_sec)
    os._exit(0)


def schedule_restart(db: Database) -> bool:
    if getattr(app.state, "restart_scheduled", False):
        return False
    app.state.restart_scheduled = True
    db.set("restart_required", True)
    asyncio.create_task(restart_process())
    return True


def should_emit_event(db: Database, event_class: str, status_name: str) -> bool:
    logging_config = db.get("settings", {}).get("logging", {})
    if not logging_config.get("enabled", True):
        return False
    if not logging_config.get("forward_to_control_center", True):
        return False
    class_config = logging_config.get("classes", {}).get(event_class, {"enabled": True, "mode": "all"})
    if not class_config.get("enabled", True):
        return False
    if class_config.get("mode") == "errors_only" and status_name != "error":
        return False
    return True


def validate_table_name(table_name: str) -> str:
    if not table_name.replace("_", "").isalnum():
        raise RuntimeError("backend.table_name must contain only letters, digits and underscore")
    return table_name


def access_session_record(task: dict[str, Any]) -> dict[str, Any]:
    payload = task["payload"]
    detections = payload.get("detections", [])
    violation_classes = sorted(
        item.get("class")
        for item in detections
        if isinstance(item, dict) and isinstance(item.get("class"), str) and item["class"].startswith("no_")
    )
    return {
        "task_id": task["task_id"],
        "route_id": task["route_id"],
        "request_id": task["request_id"],
        "checkpoint_service_id": task["checkpoint_service_id"],
        "worker_service_id": task.get("worker_service_id") or payload.get("worker_service_id"),
        "decision": payload.get("decision"),
        "access_granted": payload.get("decision") == "permit-access",
        "reason_code": payload.get("reason_code"),
        "reason_text": payload.get("reason_text"),
        "required_ppe_json": json.dumps(payload.get("required_ppe", []), ensure_ascii=False),
        "detections_json": json.dumps(detections, ensure_ascii=False),
        "violation_classes_json": json.dumps(violation_classes, ensure_ascii=False),
        "payload_json": json.dumps(payload, ensure_ascii=False),
        "created_at": utcnow(),
    }


def sqlite_db_path(backend: dict[str, Any]) -> Path:
    db_path = Path(str(backend.get("sqlite_path") or "/data/storage_records.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


def create_sqlite_table(connection: sqlite3.Connection, table_name: str) -> None:
    connection.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL UNIQUE,
            route_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            checkpoint_service_id TEXT NOT NULL,
            worker_service_id TEXT,
            decision TEXT,
            access_granted INTEGER NOT NULL,
            reason_code TEXT,
            reason_text TEXT,
            required_ppe_json TEXT NOT NULL,
            detections_json TEXT NOT NULL,
            violation_classes_json TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )


def write_sqlite_record(backend: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    db_path = sqlite_db_path(backend)
    table_name = str(backend.get("table_name") or "inspection_results")
    validate_table_name(table_name)
    record = access_session_record(task)
    with sqlite3.connect(db_path, timeout=float(backend.get("_write_timeout_sec", 10))) as connection:
        if backend.get("create_table", True):
            create_sqlite_table(connection, table_name)
        connection.execute(
            f"""
            INSERT OR REPLACE INTO {table_name}
            (task_id, route_id, request_id, checkpoint_service_id, worker_service_id, decision, access_granted, reason_code, reason_text, required_ppe_json, detections_json, violation_classes_json, payload_json, created_at)
            VALUES (:task_id, :route_id, :request_id, :checkpoint_service_id, :worker_service_id, :decision, :access_granted, :reason_code, :reason_text, :required_ppe_json, :detections_json, :violation_classes_json, :payload_json, :created_at)
            """,
            record | {"access_granted": int(record["access_granted"])},
        )
    return {"backend": "sqlite", "sqlite_path": str(db_path), "table_name": table_name}


def create_postgres_table(connection: Any, table_name: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id BIGSERIAL PRIMARY KEY,
                task_id TEXT NOT NULL UNIQUE,
                route_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                checkpoint_service_id TEXT NOT NULL,
                worker_service_id TEXT,
                decision TEXT,
                access_granted BOOLEAN NOT NULL,
                reason_code TEXT,
                reason_text TEXT,
                required_ppe_json JSONB NOT NULL,
                detections_json JSONB NOT NULL,
                violation_classes_json JSONB NOT NULL,
                payload_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )
            """
        )


def write_postgres_record(backend: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("PostgreSQL backend requires psycopg") from exc
    table_name = validate_table_name(str(backend.get("table_name") or "inspection_results"))
    dsn = str(backend.get("dsn") or "").strip()
    if not dsn:
        raise RuntimeError("backend.dsn is required for PostgreSQL")
    record = access_session_record(task)
    with psycopg.connect(dsn, connect_timeout=int(backend.get("connect_timeout_sec", 10))) as connection:
        if backend.get("create_table", True):
            create_postgres_table(connection, table_name)
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO {table_name}
                (task_id, route_id, request_id, checkpoint_service_id, worker_service_id, decision, access_granted, reason_code, reason_text, required_ppe_json, detections_json, violation_classes_json, payload_json, created_at)
                VALUES (%(task_id)s, %(route_id)s, %(request_id)s, %(checkpoint_service_id)s, %(worker_service_id)s, %(decision)s, %(access_granted)s, %(reason_code)s, %(reason_text)s, %(required_ppe_json)s::jsonb, %(detections_json)s::jsonb, %(violation_classes_json)s::jsonb, %(payload_json)s::jsonb, %(created_at)s)
                ON CONFLICT (task_id) DO UPDATE SET
                    decision = EXCLUDED.decision,
                    access_granted = EXCLUDED.access_granted,
                    reason_code = EXCLUDED.reason_code,
                    reason_text = EXCLUDED.reason_text,
                    required_ppe_json = EXCLUDED.required_ppe_json,
                    detections_json = EXCLUDED.detections_json,
                    violation_classes_json = EXCLUDED.violation_classes_json,
                    payload_json = EXCLUDED.payload_json
                """,
                record,
            )
    return {"backend": "postgres", "table_name": table_name}


def create_mysql_table(connection: Any, table_name: str) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                task_id VARCHAR(128) NOT NULL UNIQUE,
                route_id VARCHAR(128) NOT NULL,
                request_id VARCHAR(128) NOT NULL,
                checkpoint_service_id VARCHAR(128) NOT NULL,
                worker_service_id VARCHAR(128),
                decision VARCHAR(64),
                access_granted BOOLEAN NOT NULL,
                reason_code VARCHAR(128),
                reason_text TEXT,
                required_ppe_json JSON NOT NULL,
                detections_json JSON NOT NULL,
                violation_classes_json JSON NOT NULL,
                payload_json JSON NOT NULL,
                created_at VARCHAR(64) NOT NULL
            )
            """
        )
    finally:
        cursor.close()


def write_mysql_record(backend: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    try:
        import mysql.connector
    except ImportError as exc:
        raise RuntimeError("MySQL backend requires mysql-connector-python") from exc
    table_name = validate_table_name(str(backend.get("table_name") or "inspection_results"))
    dsn = str(backend.get("dsn") or "").strip()
    if not dsn:
        raise RuntimeError("backend.dsn is required for MySQL")
    record = access_session_record(task)
    parsed = urlparse(dsn)
    if parsed.scheme not in {"mysql", "mysql+pymysql"} or not parsed.hostname or not parsed.path.strip("/"):
        raise RuntimeError("MySQL dsn must look like mysql://user:password@host:3306/database")
    connection = mysql.connector.connect(
        host=parsed.hostname,
        port=parsed.port or 3306,
        user=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
        database=parsed.path.strip("/"),
        connection_timeout=int(backend.get("connect_timeout_sec", 10)),
    )
    try:
        if backend.get("create_table", True):
            create_mysql_table(connection, table_name)
        cursor = connection.cursor()
        try:
            cursor.execute(
                f"""
                INSERT INTO {table_name}
                (task_id, route_id, request_id, checkpoint_service_id, worker_service_id, decision, access_granted, reason_code, reason_text, required_ppe_json, detections_json, violation_classes_json, payload_json, created_at)
                VALUES (%(task_id)s, %(route_id)s, %(request_id)s, %(checkpoint_service_id)s, %(worker_service_id)s, %(decision)s, %(access_granted)s, %(reason_code)s, %(reason_text)s, %(required_ppe_json)s, %(detections_json)s, %(violation_classes_json)s, %(payload_json)s, %(created_at)s)
                ON DUPLICATE KEY UPDATE
                    decision = VALUES(decision),
                    access_granted = VALUES(access_granted),
                    reason_code = VALUES(reason_code),
                    reason_text = VALUES(reason_text),
                    required_ppe_json = VALUES(required_ppe_json),
                    detections_json = VALUES(detections_json),
                    violation_classes_json = VALUES(violation_classes_json),
                    payload_json = VALUES(payload_json)
                """,
                record | {"access_granted": int(record["access_granted"])},
            )
        finally:
            cursor.close()
        connection.commit()
    finally:
        connection.close()
    return {"backend": "mysql", "table_name": table_name}


async def write_storage_record(settings: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    if task["target_kind"] != "database":
        raise RuntimeError(f"Storage service accepts only database tasks, got {task['target_kind']}")
    backend = dict(settings.get("backend", {}))
    backend["_write_timeout_sec"] = settings.get("write_timeout_sec", 10)
    backend_type = backend.get("type", "sqlite")
    if backend_type == "sqlite":
        return await asyncio.to_thread(write_sqlite_record, backend, task)
    if backend_type == "postgres":
        return await asyncio.to_thread(write_postgres_record, backend, task)
    if backend_type == "mysql":
        return await asyncio.to_thread(write_mysql_record, backend, task)
    raise RuntimeError(f"Unsupported storage backend: {backend_type}")


def runtime_control_center_url(db: Database) -> str:
    configured = (db.get("control_center_runtime_url") or "").strip()
    if configured:
        return configured
    base_url = db.get("control_center_url", "").strip()
    if not base_url:
        return ""
    parsed = urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    return f"https://{host}:8443"


def base_url_for_path(db: Database, path: str) -> str:
    if path.startswith("/api/v1/runtime/pki/"):
        return db.get("control_center_url", "").strip()
    return runtime_control_center_url(db) if path.startswith("/api/v1/runtime/") else db.get("control_center_url", "").strip()


async def post_json(db: Database, path: str, payload: dict[str, Any], timeout: float = 15) -> httpx.Response:
    base_url = base_url_for_path(db, path)
    if not base_url:
        raise HTTPException(status_code=400, detail="Control Center URL is not configured")
    try:
        use_client_cert = path.startswith("/api/v1/runtime/") and not path.startswith("/api/v1/runtime/pki/")
        insecure_skip_verify = path.startswith("/api/v1/runtime/pki/")
        async with httpx.AsyncClient(timeout=timeout, **httpx_tls_kwargs(get_pki_dir(), use_client_cert=use_client_cert, insecure_skip_verify=insecure_skip_verify)) as client:
            return await client.post(f"{base_url}{path}", json=payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Control Center request failed: {exc}") from exc


async def emit_runtime_event(
    db: Database,
    event_class: str,
    event_type: str,
    status_name: str,
    message: str,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
    job_id: str | None = None,
) -> None:
    payload = details or {}
    logging_config = db.get("settings", {}).get("logging", {})
    if logging_config.get("store_local_events", True):
        db.append_event(event_class, status_name, message, payload)
    outbound_payload = payload if logging_config.get("include_payloads", True) else {}
    if not should_emit_event(db, event_class, status_name):
        return
    if not db.get("registered", False):
        return
    try:
        await post_json(
            db,
            "/api/v1/runtime/events",
            {
                "event_id": f"{db.get('service_id')}-{event_class}-{utcnow()}",
                "service_id": db.get("service_id"),
                "service_type": SERVICE_TYPE,
                "service_secret": db.get("service_secret"),
                "event_class": event_class,
                "event_type": event_type,
                "severity": "error" if status_name == "error" else "info",
                "request_id": request_id,
                "job_id": job_id,
                "payload": outbound_payload | {"message": message},
                "created_at": utcnow(),
            },
        )
    except Exception:
        pass


async def fetch_control_center_user(db: Database, token: str) -> dict[str, Any]:
    base_url = db.get("control_center_url", "").strip()
    if not base_url:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Control Center URL is not configured")
    try:
        async with httpx.AsyncClient(timeout=15, **httpx_tls_kwargs(get_pki_dir(), use_client_cert=False)) as client:
            response = await client.get(f"{base_url}/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Control Center is unreachable: {exc}") from exc
    data = response.json()
    if response.status_code >= 400:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=data.get("detail", "Invalid session"))
    return data


def user_can_access_service(user: dict[str, Any], service_id: str, mode: str) -> bool:
    if user["role"] == "root":
        return True
    grants = {entry["service_id"]: entry["access_level"] for entry in user.get("access", [])}
    access_level = grants.get(service_id)
    if access_level is None:
        return False
    if mode == "read":
        return True
    return access_level == "manage"


async def require_operator(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    db: Database = request.app.state.db
    if not is_bootstrap_configured(db):
        raise HTTPException(status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="Bootstrap is required")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    return await fetch_control_center_user(db, token)


def require_mode(mode: str):
    async def dependency(request: Request, user: dict[str, Any] = Depends(require_operator)) -> dict[str, Any]:
        service_id = request.app.state.db.get("service_id")
        if not user_can_access_service(user, service_id, mode):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions for this delivery adapter")
        return user

    return dependency


async def probe_control_center(db: Database) -> dict[str, Any]:
    base_url = db.get("control_center_url", "").strip()
    if not base_url:
        db.set("connection_status", "not_configured")
        db.set("last_registration_message", "Control Center URL is not configured")
        return {"ok": False, "detail": "Control Center URL is not configured"}
    try:
        async with httpx.AsyncClient(timeout=10, **httpx_tls_kwargs(get_pki_dir(), use_client_cert=False)) as client:
            response = await client.get(f"{base_url}/health")
        db.set("last_connection_check_at", utcnow())
        if response.status_code < 400:
            db.set("connection_status", "connected")
            return {"ok": True}
        detail = f"Control Center health check failed with status {response.status_code}"
        db.set("connection_status", "error")
        db.set("last_registration_message", detail)
        return {"ok": False, "detail": detail}
    except Exception as exc:
        db.set("last_connection_check_at", utcnow())
        db.set("connection_status", "error")
        db.set("last_registration_message", str(exc))
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            refreshed = await _refresh_root_certificate(db)
            if refreshed:
                try:
                    async with httpx.AsyncClient(timeout=10, **httpx_tls_kwargs(get_pki_dir(), use_client_cert=False)) as client:
                        response = await client.get(f"{base_url}/health")
                    if response.status_code < 400:
                        db.set("connection_status", "connected")
                        return {"ok": True}
                except Exception:
                    pass
        return {"ok": False, "detail": str(exc)}


async def _refresh_root_certificate(db: Database) -> bool:
    base_url = db.get("control_center_url", "").strip()
    if not base_url:
        return False
    previous_root = root_cert_path(get_pki_dir()).read_text() if root_cert_path(get_pki_dir()).exists() else ""
    try:
        async with httpx.AsyncClient(timeout=10, **httpx_tls_kwargs(get_pki_dir(), use_client_cert=False, insecure_skip_verify=True)) as client:
            response = await client.get(f"{base_url}/api/v1/pki/root-cert")
        if response.status_code >= 400:
            return False
        current_root = response.text
        save_root_certificate(get_pki_dir(), current_root)
        if current_root != previous_root:
            db.set("tls_enrolled", False)
            db.set("tls_serial_hex", "")
            db.set("tls_expires_at", "")
        db.append_event("security", "success", "Control Center root certificate refreshed", {"changed": current_root != previous_root})
        return True
    except Exception:
        return False


async def _register_with_control_center_unlocked(db: Database) -> dict[str, Any]:
    if runtime_control_center_url(db).startswith("https://") and not db.get("tls_enrolled"):
        await _enroll_tls_certificate(db)
    probe = await probe_control_center(db)
    if runtime_control_center_url(db).startswith("https://") and not db.get("tls_enrolled"):
        await _enroll_tls_certificate(db)
    db.set("last_registration_status", "running")
    if not probe["ok"]:
        db.set("registered", False)
        db.set("runtime_registration_status", "failed")
        db.set("last_registration_status", "failed")
        await emit_runtime_event(db, "registration", "registration.failed", "error", probe["detail"])
        raise HTTPException(status_code=502, detail=probe["detail"])
    register_payload = {
        "service_id": db.get("service_id"),
        "service_type": SERVICE_TYPE,
        "service_secret": db.get("service_secret"),
        "local_url": db.get("local_url"),
        "status_snapshot": {"history_size": len(db.get_history())},
    }
    try:
        response = await post_json(db, "/api/v1/runtime/register", register_payload)
    except HTTPException as exc:
        detail = str(exc.detail)
        if exc.status_code == 502 and ("CERTIFICATE_VERIFY_FAILED" in detail or "Server disconnected" in detail):
            db.set("tls_enrolled", False)
            db.set("tls_serial_hex", "")
            db.set("tls_expires_at", "")
            await _enroll_tls_certificate(db)
            response = await post_json(db, "/api/v1/runtime/register", register_payload)
        else:
            raise
    data = response.json()
    if response.status_code >= 400:
        db.set("registered", False)
        db.set("runtime_registration_status", "failed")
        db.set("last_registration_status", "failed")
        db.set("last_registration_at", utcnow())
        db.set("last_registration_message", data.get("detail", "Registration failed"))
        db.set("last_error", data.get("detail", "Registration failed"))
        await emit_runtime_event(db, "registration", "registration.failed", "error", data.get("detail", "Registration failed"))
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "Registration failed"))
    db.set("registered", data["approved"])
    db.set("runtime_registration_status", "approved" if data["approved"] else "failed")
    db.set("config_version", data["config_version"])
    db.set("settings", data["settings"])
    db.set("last_registration_at", utcnow())
    db.set("last_registration_status", "ok")
    db.set("last_registration_message", "Runtime registration approved")
    db.set("last_error", "")
    await emit_runtime_event(db, "registration", "registration.approved", "success", "Runtime registration approved")
    if db.get("restart_required", False):
        schedule_restart(db)
    return data


async def register_with_control_center(db: Database) -> dict[str, Any]:
    lock = getattr(app.state, "registration_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        app.state.registration_lock = lock
    async with lock:
        if db.get("registered", False):
            return {
                "approved": True,
                "service_id": db.get("service_id"),
                "heartbeat_interval_sec": int(db.get("settings", {}).get("heartbeat_interval_sec", 10)),
                "config_version": db.get("config_version", 0),
                "settings": db.get("settings", {}),
            }
        return await _register_with_control_center_unlocked(db)


async def registration_loop() -> None:
    while True:
        db: Database = app.state.db
        if is_bootstrap_configured(db) and not db.get("registered", False):
            try:
                await register_with_control_center(db)
            except Exception:
                pass
        await asyncio.sleep(5)


async def heartbeat_loop() -> None:
    while True:
        db: Database = app.state.db
        if db.get("registered", False):
            try:
                await emit_runtime_event(db, "heartbeat", "heartbeat.sent", "success", "Heartbeat sent")
                response = await post_json(
                    db,
                    "/api/v1/runtime/heartbeat",
                    {
                        "service_id": db.get("service_id"),
                        "service_type": SERVICE_TYPE,
                        "service_secret": db.get("service_secret"),
                        "local_url": db.get("local_url"),
                        "status_snapshot": {"history_size": len(db.get_history())},
                    },
                )
                if response.status_code < 400:
                    db.set("last_heartbeat_at", utcnow())
                    db.set("last_heartbeat_status", "ok")
                    db.set("last_error", "")
                    await emit_runtime_event(db, "heartbeat", "heartbeat.ok", "success", "Heartbeat accepted by control center")
                else:
                    detail = response.json().get("detail", "Heartbeat failed")
                    db.set("last_heartbeat_status", "failed")
                    db.set("last_error", detail)
                    await emit_runtime_event(db, "heartbeat", "heartbeat.failed", "error", detail)
            except Exception as exc:
                db.set("last_heartbeat_status", "failed")
                db.set("last_error", str(exc))
                await emit_runtime_event(db, "heartbeat", "heartbeat.failed", "error", str(exc))
        interval = int(db.get("settings", {}).get("heartbeat_interval_sec", 10))
        await asyncio.sleep(max(interval, 2))


async def config_pull_loop() -> None:
    while True:
        db: Database = app.state.db
        if db.get("registered", False):
            try:
                await emit_runtime_event(db, "config", "config.pull.requested", "success", "Requested config pull")
                response = await post_json(
                    db,
                    "/api/v1/runtime/config/pull",
                    {
                        "service_id": db.get("service_id"),
                        "service_type": SERVICE_TYPE,
                        "service_secret": db.get("service_secret"),
                        "current_version": db.get("config_version", 0),
                    },
                )
                if response.status_code < 400:
                    data = response.json()
                    if data["changed"]:
                        db.set("config_version", data["config_version"])
                        db.set("settings", data["settings"])
                        await emit_runtime_event(db, "config", "config.applied", "success", "Applied updated config", {"config_version": data["config_version"]})
                    else:
                        await emit_runtime_event(db, "config", "config.unchanged", "success", "Config unchanged")
                else:
                    detail = response.json().get("detail", "Config pull failed")
                    db.set("last_error", detail)
                    await emit_runtime_event(db, "config", "config.pull.failed", "error", detail)
            except Exception as exc:
                db.set("last_error", str(exc))
                await emit_runtime_event(db, "config", "config.pull.failed", "error", str(exc))
        await asyncio.sleep(5)


async def delivery_consumer_loop() -> None:
    while True:
        task = await app.state.delivery_queue.get()
        db: Database = app.state.db
        try:
            db.append_history(task["task_id"], task["request_id"], "processing", task["payload"])
            await emit_runtime_event(db, "delivery", "delivery.processing.started", "success", "Started delivery processing", {"task_id": task["task_id"]})
            storage_result = await write_storage_record(db.get("settings", {}), task)
            details = {
                "delivered_to": task["target_kind"],
                "target_service_id": task["target_service_id"],
                "payload_keys": sorted(task["payload"].keys()),
            } | storage_result
            response = await post_json(
                db,
                "/api/v1/runtime/delivery/tasks/result",
                {
                    "service_id": db.get("service_id"),
                    "service_type": SERVICE_TYPE,
                    "service_secret": db.get("service_secret"),
                    "task_id": task["task_id"],
                    "delivered_at": utcnow(),
                    "details": details,
                },
            )
            if response.status_code >= 400:
                detail = response.text
                db.append_history(task["task_id"], task["request_id"], "failed", {"detail": detail})
                db.set("last_error", detail)
                await emit_runtime_event(db, "delivery", "delivery.processing.failed", "error", detail, {"task_id": task["task_id"]})
            else:
                db.append_history(task["task_id"], task["request_id"], "completed", details)
                await emit_runtime_event(db, "delivery", "delivery.processing.completed", "success", "Delivery task completed", {"task_id": task["task_id"]})
        except Exception as exc:
            db.append_history(task["task_id"], task["request_id"], "failed", {"error": str(exc)})
            await emit_runtime_event(db, "delivery", "delivery.processing.failed", "error", str(exc), {"task_id": task["task_id"]})
        finally:
            app.state.delivery_queue.task_done()


@app.on_event("startup")
async def startup() -> None:
    db = Database(get_db_path())
    db.initialize()
    app.state.db = db
    app.state.restart_scheduled = False
    app.state.registration_lock = asyncio.Lock()
    normalize_local_url_for_tls(db)
    db.set("restart_required", False)
    app.state.db = db
    app.state.delivery_queue = asyncio.Queue()
    app.state.registration_task = asyncio.create_task(registration_loop())
    app.state.heartbeat_task = asyncio.create_task(heartbeat_loop())
    app.state.delivery_task = asyncio.create_task(delivery_consumer_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    for task_name in ("registration_task", "heartbeat_task", "delivery_task"):
        task = getattr(app.state, task_name, None)
        if task:
            task.cancel()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/bootstrap")
def get_bootstrap_state() -> dict[str, Any]:
    db: Database = app.state.db
    return {
        "configured": is_bootstrap_configured(db),
        "control_center_url": db.get("control_center_url"),
        "control_center_runtime_url": runtime_control_center_url(db),
        "service_id": db.get("service_id"),
        "local_url": db.get("local_url"),
    }


@app.post("/api/bootstrap")
async def configure_bootstrap(payload: ControlCenterConfigRequest) -> dict[str, Any]:
    db: Database = app.state.db
    if is_bootstrap_configured(db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Bootstrap already configured")
    if not payload.service_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Service secret is required for bootstrap")
    control_center_url = normalize_https_url(payload.control_center_url, "control_center_url")
    control_center_runtime_url = normalize_https_url(payload.control_center_runtime_url, "control_center_runtime_url") if payload.control_center_runtime_url else f"https://{urlparse(control_center_url).hostname}:8443"
    local_url = normalize_local_url(payload.local_url, "local_url")
    db.set("control_center_url", control_center_url)
    db.set("control_center_runtime_url", control_center_runtime_url)
    db.set("service_id", payload.service_id.strip())
    db.set("service_secret", payload.service_secret)
    db.set("local_url", local_url)
    db.set("registered", False)
    db.set("connection_status", "configured")
    db.set("runtime_registration_status", "pending")
    db.set("last_registration_status", "idle")
    db.set("last_registration_message", "")
    db.set("last_heartbeat_status", "idle")
    db.append_event("bootstrap", "success", "Bootstrap configuration saved", {"control_center_url": control_center_url, "control_center_runtime_url": control_center_runtime_url, "service_id": payload.service_id, "local_url": local_url})
    try:
        registration = await register_with_control_center(db)
        return {"status": "saved", "connected": True, "registered": registration["approved"], "message": "Connection established and runtime registration approved"}
    except HTTPException as exc:
        db.set("control_center_url", "")
        db.set("control_center_runtime_url", "")
        db.set("service_id", "")
        db.set("service_secret", "")
        db.set("local_url", "")
        db.set("registered", False)
        raise exc


@app.post("/api/session/login")
async def operator_login(payload: OperatorLoginRequest) -> dict[str, Any]:
    db: Database = app.state.db
    if not is_bootstrap_configured(db):
        raise HTTPException(status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="Bootstrap is required")
    response = await post_json(db, "/api/v1/auth/login", {"username": payload.username, "password": payload.password})
    data = response.json()
    if response.status_code >= 400:
        db.append_event("aaa", "error", data.get("detail", "Login failed"), {"username": payload.username})
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "Login failed"))
    if not user_can_access_service(data["user"], db.get("service_id"), "read"):
        db.append_event("aaa", "error", "No access to this delivery adapter", {"username": payload.username})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this delivery adapter")
    db.append_event("aaa", "success", "Operator authenticated through control center", {"username": payload.username})
    return data


@app.get("/api/session/me")
async def operator_me(user: dict[str, Any] = Depends(require_mode("read"))) -> dict[str, Any]:
    return {"user": user}


@app.get("/api/state")
async def get_state(_: dict[str, Any] = Depends(require_mode("read"))) -> dict[str, Any]:
    db: Database = app.state.db
    return {
        "control_center_url": db.get("control_center_url"),
        "control_center_runtime_url": runtime_control_center_url(db),
        "service_id": db.get("service_id"),
        "local_url": db.get("local_url"),
        "connection_status": db.get("connection_status"),
        "registered": db.get("registered"),
        "runtime_registration_status": db.get("runtime_registration_status"),
        "last_registration_status": db.get("last_registration_status"),
        "last_registration_message": db.get("last_registration_message"),
        "config_version": db.get("config_version"),
        "settings": db.get("settings"),
        "desired_settings": db.get("desired_settings"),
        "last_error": db.get("last_error"),
        "last_connection_check_at": db.get("last_connection_check_at"),
        "last_registration_at": db.get("last_registration_at"),
        "last_heartbeat_status": db.get("last_heartbeat_status"),
        "last_heartbeat_at": db.get("last_heartbeat_at"),
        "tls_enrolled": db.get("tls_enrolled"),
        "tls_expires_at": db.get("tls_expires_at"),
        "tls_serial_hex": db.get("tls_serial_hex"),
        "restart_required": db.get("restart_required", False),
        "history": db.get_history(),
        "events": db.get_events(),
    }


@app.post("/api/control-center")
async def configure_control_center(payload: ControlCenterConfigRequest, _: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, str]:
    db: Database = app.state.db
    control_center_url = normalize_https_url(payload.control_center_url, "control_center_url")
    control_center_runtime_url = normalize_https_url(payload.control_center_runtime_url, "control_center_runtime_url") if payload.control_center_runtime_url else f"https://{urlparse(control_center_url).hostname}:8443"
    local_url = normalize_local_url(payload.local_url, "local_url")
    db.set("control_center_url", control_center_url)
    db.set("control_center_runtime_url", control_center_runtime_url)
    db.set("service_id", payload.service_id.strip())
    if payload.service_secret:
        db.set("service_secret", payload.service_secret)
    db.set("local_url", local_url)
    db.set("registered", False)
    db.set("connection_status", "configured")
    db.set("runtime_registration_status", "pending")
    db.set("last_registration_status", "idle")
    db.set("last_registration_message", "")
    db.set("last_heartbeat_status", "idle")
    db.append_event("config", "success", "Control center connection settings updated", {"control_center_url": control_center_url, "control_center_runtime_url": control_center_runtime_url, "service_id": payload.service_id, "local_url": local_url})
    return {"status": "saved"}


@app.post("/api/register")
async def register_runtime(_: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    return await register_with_control_center(app.state.db)


@app.post("/api/settings")
async def update_local_settings(payload: LocalSettingsRequest, _: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    db: Database = app.state.db
    db.set("desired_settings", payload.settings)
    response = await post_json(
        db,
        "/api/v1/runtime/config/propose",
        {
            "service_id": db.get("service_id"),
            "service_type": SERVICE_TYPE,
            "service_secret": db.get("service_secret"),
            "proposed_at": utcnow(),
            "settings": payload.settings,
        },
    )
    data = response.json()
    if response.status_code >= 400:
        db.set("last_error", data.get("detail", "Settings proposal failed"))
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "Settings proposal failed"))
    if data.get("accepted"):
        db.set("settings", data["settings"])
        db.set("config_version", data["config_version"])
    return data


@app.post("/api/internal/config/apply")
async def apply_pushed_config(payload: InternalConfigApplyRequest) -> dict[str, Any]:
    db: Database = app.state.db
    if payload.service_id != db.get("service_id") or payload.service_secret != db.get("service_secret"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid service credentials")
    if payload.config_version < int(db.get("config_version", 0)):
        return {"accepted": False, "reason": "stale_config", "config_version": db.get("config_version", 0)}
    db.set("settings", payload.settings)
    db.set("config_version", payload.config_version)
    db.set("last_error", "")
    await emit_runtime_event(db, "config", "config.pushed.applied", "success", "Applied pushed config", {"config_version": payload.config_version})
    return {"accepted": True, "config_version": payload.config_version}


@app.post("/api/internal/delivery/enqueue")
async def enqueue_delivery_task(payload: InternalDeliveryTaskRequest) -> dict[str, Any]:
    db: Database = app.state.db
    if payload.service_id != db.get("service_id") or payload.service_secret != db.get("service_secret"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid service credentials")
    max_queue_size = int(db.get("settings", {}).get("max_local_queue_size", 20))
    if app.state.delivery_queue.qsize() >= max_queue_size:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Local delivery queue is full")
    task = payload.task
    if task.get("target_kind") != "database":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Storage accepts only database delivery tasks")
    await app.state.delivery_queue.put(task)
    await emit_runtime_event(db, "delivery", "delivery.task.accepted", "success", "Accepted pushed storage task", {"task_id": task.get("task_id")})
    return {"accepted": True, "task_id": task.get("task_id"), "queue_size": app.state.delivery_queue.qsize()}


@app.get("/api/tls/state")
async def tls_state(_: dict[str, Any] = Depends(require_mode("read"))) -> dict[str, Any]:
    db: Database = app.state.db
    return {
        "tls_enrolled": db.get("tls_enrolled"),
        "tls_serial_hex": db.get("tls_serial_hex"),
        "restart_required": db.get("restart_required", False),
        "tls_expires_at": db.get("tls_expires_at"),
        "runtime_url": runtime_control_center_url(db),
    }


async def _enroll_tls_certificate(db: Database) -> dict[str, Any]:
    csr_pem = build_csr(db.get("service_id"), db.get("local_url"), get_pki_dir())
    response = await post_json(
        db,
        "/api/v1/runtime/pki/enroll",
        {
            "service_id": db.get("service_id"),
            "service_type": SERVICE_TYPE,
            "service_secret": db.get("service_secret"),
            "csr_pem": csr_pem,
        },
    )
    data = response.json()
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "TLS enrollment failed"))
    save_enrolled_certificate(get_pki_dir(), data["cert_pem"], data["root_cert_pem"])
    db.set("tls_enrolled", True)
    db.set("tls_serial_hex", data["serial_hex"])
    db.set("tls_expires_at", data["expires_at"])
    db.set("restart_required", True)
    await emit_runtime_event(db, "security", "security.certificate.enrolled", "success", "Service certificate enrolled", {"serial_hex": data["serial_hex"], "expires_at": data["expires_at"]})
    return data


@app.post("/api/tls/enroll")
async def tls_enroll(_: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    data = await _enroll_tls_certificate(app.state.db)
    data["restart_scheduled"] = schedule_restart(app.state.db)
    return data


@app.post("/api/tls/renew")
async def tls_renew(_: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    data = await _enroll_tls_certificate(app.state.db)
    data["restart_scheduled"] = schedule_restart(app.state.db)
    return data
