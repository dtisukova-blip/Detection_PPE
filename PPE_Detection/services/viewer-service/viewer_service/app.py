from __future__ import annotations

import asyncio
import os
import signal
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import get_db_path, get_default_local_url, get_default_service_id, get_pki_dir
from .db import Database, utcnow
from .tls import build_csr, has_tls_material, httpx_tls_kwargs, root_cert_path, save_enrolled_certificate, save_root_certificate


SERVICE_TYPE = "viewer"
app = FastAPI(title="PPE Viewer Service", version="0.1.0")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class ControlCenterConfigRequest(BaseModel):
    control_center_url: str
    control_center_runtime_url: str | None = None
    service_id: str = Field(default_factory=get_default_service_id)
    service_secret: str = ""
    local_url: str = Field(default_factory=get_default_local_url)


class LocalSettingsRequest(BaseModel):
    settings: dict[str, Any] = Field(default_factory=dict)


class InternalConfigApplyRequest(BaseModel):
    service_id: str
    service_secret: str
    config_version: int
    settings: dict[str, Any] = Field(default_factory=dict)


class InternalDeliveryTaskRequest(BaseModel):
    service_id: str
    service_secret: str
    task: dict[str, Any]


class OperatorLoginRequest(BaseModel):
    username: str
    password: str


def is_bootstrap_configured(db: Database) -> bool:
    return bool(db.get("control_center_url") and db.get("service_id") and db.get("service_secret") and db.get("local_url"))


def normalize_https_url(value: str, field_name: str) -> str:
    candidate = value.strip().rstrip("/")
    parsed = urlparse(candidate)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be an https URL")
    return candidate


def normalize_local_url(value: str, field_name: str = "local_url") -> str:
    return normalize_https_url(value, field_name)


def normalize_local_url_for_tls(db: Database) -> None:
    if has_tls_material(get_pki_dir()) and not str(db.get("local_url") or "").startswith("https://"):
        configured = get_default_local_url()
        if configured:
            db.set("local_url", normalize_local_url(configured))


async def restart_process(delay_sec: float = 1.0) -> None:
    await asyncio.sleep(delay_sec)
    os.kill(os.getpid(), signal.SIGTERM)


def schedule_restart(db: Database) -> bool:
    if getattr(app.state, "restart_scheduled", False):
        return False
    app.state.restart_scheduled = True
    db.set("restart_required", True)
    asyncio.create_task(restart_process())
    return True


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


async def fetch_control_center_user(db: Database, token: str) -> dict[str, Any]:
    base_url = db.get("control_center_url", "").strip()
    if not base_url:
        raise HTTPException(status_code=status.HTTP_428_PRECONDITION_REQUIRED, detail="Control Center URL is not configured")
    try:
        async with httpx.AsyncClient(timeout=10, **httpx_tls_kwargs(get_pki_dir(), use_client_cert=False, insecure_skip_verify=False)) as client:
            response = await client.get(f"{base_url}/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Control Center request failed: {exc}") from exc
    data = response.json()
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "Authentication failed"))
    return data


def user_can_access_service(user: dict[str, Any], service_id: str, mode: str) -> bool:
    if user["role"] == "root":
        return True
    required = "manage" if mode == "manage" else "read"
    for entry in user.get("access", []):
        if entry.get("service_id") == service_id:
            level = entry.get("access_level")
            return level == "manage" or level == required
    return False


async def require_operator(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    db: Database = request.app.state.db
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    return await fetch_control_center_user(db, token)


def require_mode(mode: str):
    async def dependency(request: Request, user: dict[str, Any] = Depends(require_operator)) -> dict[str, Any]:
        db: Database = request.app.state.db
        if not user_can_access_service(user, db.get("service_id"), mode):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this viewer")
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
    if not should_emit_event(db, event_class, status_name) or not db.get("registered", False):
        return
    outbound_payload = payload if logging_config.get("include_payloads", True) else {}
    try:
        await post_json(
            db,
            "/api/v1/runtime/events",
            {
                "event_id": f"{db.get('service_id')}-{uuid4()}",
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
        return


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
    if not is_bootstrap_configured(db):
        raise HTTPException(status_code=400, detail="Bootstrap is not configured")
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
        await emit_runtime_event(db, "registration", "registration.failed", "error", probe["detail"], {"service_id": db.get("service_id")})
        raise HTTPException(status_code=502, detail=probe["detail"])
    payload = {
        "service_id": db.get("service_id"),
        "service_type": SERVICE_TYPE,
        "service_secret": db.get("service_secret"),
        "local_url": db.get("local_url"),
        "status_snapshot": {"record_count": db.count_records()},
    }
    try:
        response = await post_json(db, "/api/v1/runtime/register", payload)
    except HTTPException as exc:
        detail = str(exc.detail)
        if exc.status_code == 502 and ("CERTIFICATE_VERIFY_FAILED" in detail or "Server disconnected" in detail):
            db.set("tls_enrolled", False)
            db.set("tls_serial_hex", "")
            db.set("tls_expires_at", "")
            await _enroll_tls_certificate(db)
            response = await post_json(db, "/api/v1/runtime/register", payload)
        else:
            raise
    data = response.json()
    if response.status_code >= 400:
        db.set("registered", False)
        db.set("runtime_registration_status", "failed")
        db.set("last_registration_status", "failed")
        db.set("last_registration_message", data.get("detail", "Registration failed"))
        db.set("last_registration_at", utcnow())
        db.set("last_error", data.get("detail", "Registration failed"))
        await emit_runtime_event(db, "registration", "registration.failed", "error", data.get("detail", "Registration failed"), {"service_id": db.get("service_id")})
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "Registration failed"))
    approved = bool(data.get("approved"))
    db.set("registered", approved)
    db.set("runtime_registration_status", "approved" if approved else "failed")
    db.set("settings", data.get("settings", db.get("settings", {})))
    db.set("config_version", data.get("config_version", 0))
    db.set("connection_status", "connected")
    db.set("last_registration_status", "ok" if approved else "failed")
    db.set("last_registration_message", data.get("reason") or "Runtime registration approved")
    db.set("last_registration_at", utcnow())
    db.set("last_error", "")
    await emit_runtime_event(db, "registration", "registration.approved", "success", "Runtime registration approved")
    if db.get("restart_required", False):
        schedule_restart(db)
    return data


async def register_with_control_center(db: Database) -> dict[str, Any]:
    async with app.state.registration_lock:
        return await _register_with_control_center_unlocked(db)


async def registration_loop() -> None:
    while True:
        db: Database = app.state.db
        if is_bootstrap_configured(db) and not db.get("registered", False):
            try:
                await register_with_control_center(db)
            except Exception as exc:
                db.set("last_error", str(exc))
        await asyncio.sleep(5)


async def heartbeat_loop() -> None:
    while True:
        db: Database = app.state.db
        if db.get("registered", False):
            try:
                response = await post_json(
                    db,
                    "/api/v1/runtime/heartbeat",
                    {
                        "service_id": db.get("service_id"),
                        "service_type": SERVICE_TYPE,
                        "service_secret": db.get("service_secret"),
                        "local_url": db.get("local_url"),
                        "status_snapshot": {"record_count": db.count_records()},
                    },
                )
                if response.status_code < 400:
                    db.set("last_heartbeat_status", "success")
                    db.set("last_heartbeat_at", utcnow())
                else:
                    db.set("last_heartbeat_status", "error")
            except Exception as exc:
                db.set("last_heartbeat_status", "error")
                db.set("last_error", str(exc))
        await asyncio.sleep(int(db.get("settings", {}).get("heartbeat_interval_sec", 10)))


async def config_pull_loop() -> None:
    while True:
        db: Database = app.state.db
        if db.get("registered", False):
            try:
                response = await post_json(
                    db,
                    "/api/v1/runtime/config/pull",
                    {
                        "service_id": db.get("service_id"),
                        "service_type": SERVICE_TYPE,
                        "service_secret": db.get("service_secret"),
                        "current_version": int(db.get("config_version", 0)),
                    },
                )
                data = response.json()
                if response.status_code < 400 and data.get("changed"):
                    db.set("config_version", data["config_version"])
                    db.set("settings", data["settings"])
                    db.set("last_error", "")
                    await emit_runtime_event(db, "config", "config.applied", "success", "Applied settings from control center", {"config_version": data["config_version"]})
            except Exception as exc:
                db.set("last_error", str(exc))
        await asyncio.sleep(5)


@app.on_event("startup")
async def startup() -> None:
    db = Database(get_db_path())
    db.initialize()
    app.state.restart_scheduled = False
    app.state.registration_lock = asyncio.Lock()
    normalize_local_url_for_tls(db)
    db.set("restart_required", False)
    app.state.db = db
    app.state.registration_task = asyncio.create_task(registration_loop())
    app.state.heartbeat_task = asyncio.create_task(heartbeat_loop())
    app.state.config_task = asyncio.create_task(config_pull_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    for task_name in ("registration_task", "heartbeat_task", "config_task"):
        task = getattr(app.state, task_name, None)
        if task:
            task.cancel()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


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
    try:
        registration = await register_with_control_center(db)
        return {"status": "saved", "registered": registration["approved"], "message": "Connection established and runtime registration approved"}
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
        await emit_runtime_event(db, "aaa", "aaa.login.failed", "error", data.get("detail", "Login failed"), {"username": payload.username})
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "Login failed"))
    if not user_can_access_service(data["user"], db.get("service_id"), "read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this viewer")
    await emit_runtime_event(db, "aaa", "aaa.login.success", "success", "Operator authenticated through control center", {"username": payload.username})
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
        "last_error": db.get("last_error"),
        "last_heartbeat_status": db.get("last_heartbeat_status"),
        "last_heartbeat_at": db.get("last_heartbeat_at"),
        "tls_enrolled": db.get("tls_enrolled"),
        "tls_expires_at": db.get("tls_expires_at"),
        "tls_serial_hex": db.get("tls_serial_hex"),
        "restart_required": db.get("restart_required", False),
        "records": db.get_records(),
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
async def enqueue_viewer_task(payload: InternalDeliveryTaskRequest) -> dict[str, Any]:
    db: Database = app.state.db
    if payload.service_id != db.get("service_id") or payload.service_secret != db.get("service_secret"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid service credentials")
    task = payload.task
    if task.get("target_kind") != "viewer":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Viewer accepts only viewer tasks")
    max_records = int(db.get("settings", {}).get("max_local_queue_size", 200))
    db.append_record(task)
    db.trim_records(max_records)
    await emit_runtime_event(db, "delivery", "viewer.record.accepted", "success", "Viewer record accepted", {"task_id": task.get("task_id")}, request_id=task.get("request_id"))
    response = await post_json(
        db,
        "/api/v1/runtime/delivery/tasks/result",
        {
            "service_id": db.get("service_id"),
            "service_type": SERVICE_TYPE,
            "service_secret": db.get("service_secret"),
            "task_id": task["task_id"],
            "delivered_at": utcnow(),
            "details": {"channel": "viewer", "stored": True},
        },
    )
    if response.status_code >= 400:
        data = response.json()
        raise HTTPException(status_code=response.status_code, detail=data.get("detail", "Viewer delivery result failed"))
    return {"accepted": True, "task_id": task.get("task_id")}


@app.get("/api/tls/state")
async def tls_state(_: dict[str, Any] = Depends(require_mode("read"))) -> dict[str, Any]:
    db: Database = app.state.db
    return {
        "tls_enrolled": db.get("tls_enrolled", False),
        "tls_expires_at": db.get("tls_expires_at", ""),
        "tls_serial_hex": db.get("tls_serial_hex", ""),
        "restart_required": db.get("restart_required", False),
        "control_center_runtime_url": runtime_control_center_url(db),
    }


async def _enroll_tls_certificate(db: Database, schedule_restart_after: bool = False) -> dict[str, Any]:
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
    db.set("tls_expires_at", data["expires_at"])
    db.set("tls_serial_hex", data["serial_hex"])
    db.set("restart_required", True)
    if schedule_restart_after:
        data["restart_scheduled"] = schedule_restart(db)
    return data


@app.post("/api/tls/enroll")
async def tls_enroll(_: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    return await _enroll_tls_certificate(app.state.db, schedule_restart_after=True)


@app.post("/api/tls/renew")
async def tls_renew(_: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    return await _enroll_tls_certificate(app.state.db, schedule_restart_after=True)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
