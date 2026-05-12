import asyncio
import base64
from email.message import EmailMessage
import hashlib
import hmac
import json
import os
from pathlib import Path
import smtplib
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import get_db_path, get_pki_dir
from .db import Database, utcnow
from .tls import build_csr, has_tls_material, httpx_tls_kwargs, root_cert_path, save_enrolled_certificate, save_root_certificate


STATIC_DIR = Path(__file__).resolve().parent / "static"
app = FastAPI(title="PPE Delivery Service", version="0.1.0")
SERVICE_TYPE = "delivery_service"


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


class DeliveryTestRequest(BaseModel):
    decision: str = "deny-access"
    reason_code: str = "ppe_missing"
    reason_text: str = "PPE violation detected"
    include_sample_image: bool = False


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


def rule_matches(rule: dict[str, Any], task: dict[str, Any]) -> bool:
    if not rule.get("enabled", True):
        return False
    if task["target_kind"] not in rule.get("target_kinds", [task["target_kind"]]):
        return False
    when = rule.get("when", {})
    decisions = when.get("decisions")
    if decisions and task["payload"].get("decision") not in decisions:
        return False
    reason_codes = when.get("reason_codes")
    if reason_codes and task["payload"].get("reason_code") not in reason_codes:
        return False
    return True


def delivery_rule_for_task(settings: dict[str, Any], task: dict[str, Any]) -> dict[str, Any] | None:
    for rule in settings.get("rules", []):
        if rule_matches(rule, task):
            return rule
    return None


def _image_extension(media_type: str | None) -> str:
    if media_type == "image/png":
        return "png"
    if media_type == "image/webp":
        return "webp"
    return "jpg"


def _sanitize_delivery_payload(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(payload)
    if sanitized.get("annotated_image_base64"):
        sanitized["annotated_image_base64"] = f"<base64:{len(str(sanitized['annotated_image_base64']))} chars>"
    return sanitized


def _build_email_text(task: dict[str, Any]) -> str:
    payload = task["payload"]
    required = ", ".join(str(item) for item in payload.get("required_ppe", [])) or "-"
    missing = ", ".join(str(item) for item in payload.get("missing_required", [])) or "-"
    detected = ", ".join(
        str(item.get("class"))
        for item in payload.get("detections", [])
        if isinstance(item, dict) and item.get("class")
    ) or "-"
    inspected_at = payload.get("inspection_completed_at") or payload.get("inspection_processed_at") or payload.get("inspection_created_at") or "-"
    return "\n".join(
        [
            "PPE inspection result",
            "",
            f"Time: {inspected_at}",
            f"Result: {payload.get('decision_label') or payload.get('decision') or '-'}",
            f"Decision code: {payload.get('decision') or '-'}",
            f"Reason: {payload.get('reason_text') or payload.get('reason_code') or '-'}",
            f"Request ID: {task.get('request_id') or payload.get('request_id') or '-'}",
            f"Checkpoint: {payload.get('checkpoint_service_id') or task.get('checkpoint_service_id') or '-'}",
            f"Worker: {payload.get('worker_service_id') or task.get('worker_service_id') or '-'}",
            f"Required PPE: {required}",
            f"Missing required PPE: {missing}",
            f"Detected classes: {detected}",
            "",
            "The annotated photo is attached when available.",
        ]
    )


async def deliver_webhook(settings: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    channel = settings.get("channels", {}).get("webhook", {})
    if not channel.get("enabled", True):
        raise RuntimeError("Webhook channel is disabled")
    url = str(channel.get("url") or task["payload"].get("filter", {}).get("url") or "").strip()
    if not url:
        raise RuntimeError("Webhook URL is not configured")
    method = str(channel.get("method", "POST")).upper()
    headers = {str(key): str(value) for key, value in channel.get("headers", {}).items()}
    body = {
        "task_id": task["task_id"],
        "route_id": task["route_id"],
        "request_id": task["request_id"],
        "target_kind": task["target_kind"],
        "payload": task["payload"],
    }
    secret = str(channel.get("secret") or "")
    if secret:
        signature = hmac.new(secret.encode(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        headers[str(channel.get("secret_header") or "X-PPE-Signature")] = signature
    timeout = float(settings.get("send_timeout_sec", 10))
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(method, url, json=body, headers=headers)
    if response.status_code >= 400:
        raise RuntimeError(f"Webhook returned HTTP {response.status_code}: {response.text[:500]}")
    return {"channel": "webhook", "url": url, "status_code": response.status_code}


def _send_email_sync(channel: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    recipients = [str(item) for item in channel.get("to", []) if str(item).strip()]
    if not recipients:
        raise RuntimeError("Email recipients are not configured")
    sender = str(channel.get("from") or channel.get("username") or "").strip()
    if not sender:
        raise RuntimeError("Email sender is not configured")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = str(channel.get("subject_template", "PPE inspection: {decision}")).format(**task["payload"])
    message.set_content(_build_email_text(task))
    annotated_image_base64 = task["payload"].get("annotated_image_base64")
    if annotated_image_base64:
        image_bytes = base64.b64decode(annotated_image_base64, validate=True)
        media_type = task["payload"].get("annotated_image_media_type") or "image/jpeg"
        maintype, subtype = media_type.split("/", 1)
        filename = f"inspection-{task['request_id']}.{_image_extension(media_type)}"
        message.add_attachment(image_bytes, maintype=maintype, subtype=subtype, filename=filename)
    host = str(channel.get("smtp_host") or "").strip()
    if not host:
        raise RuntimeError("SMTP host is not configured")
    port = int(channel.get("smtp_port", 587))
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if channel.get("smtp_tls", True):
            smtp.starttls()
        username = str(channel.get("username") or "")
        password = str(channel.get("password") or "")
        if username:
            smtp.login(username, password)
        smtp.send_message(message)
    return {"channel": "email", "mode": "smtp", "to": recipients}


async def deliver_email(settings: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    channel = settings.get("channels", {}).get("email", {})
    if not channel.get("enabled", False):
        raise RuntimeError("Email channel is disabled")
    if channel.get("mode", "log") == "log":
        return {"channel": "email", "mode": "log", "to": channel.get("to", [])}
    return await asyncio.to_thread(_send_email_sync, channel, task)


async def execute_delivery(settings: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
    rule = delivery_rule_for_task(settings, task)
    if rule is None:
        return {"channel": "none", "skipped": True, "reason": "no matching delivery rule"}
    channel = rule.get("channel")
    if channel == "webhook":
        result = await deliver_webhook(settings, task)
    elif channel == "email":
        result = await deliver_email(settings, task)
    else:
        raise RuntimeError(f"Unsupported delivery channel: {channel}")
    return result | {"rule": rule.get("name", "")}


def build_test_delivery_task(target_kind: str, payload: DeliveryTestRequest) -> dict[str, Any]:
    task_payload = {
        "request_id": f"test-{utcnow()}",
        "decision": payload.decision,
        "reason_code": payload.reason_code,
        "reason_text": payload.reason_text,
        "required_ppe": ["hardhat", "safety_vest"],
        "detections": [{"class": "no_hardhat", "confidence": 0.93}],
    }
    if payload.include_sample_image:
        task_payload["annotated_image_base64"] = (
            "iVBORw0KGgoAAAANSUhEUgAAAUAAAAC0CAIAAABqhmJGAAAC9klEQVR42u3csQ2AIBRFUZewpLFgC1dxFV3OLVzDmNjgABgsQXJ+7gSE077hvG5JP23wBBLAkgCWBLAEsCSAJQEsCWAJYEkASwJYAlgSwJIAlgSwBLAkgCUBLAlgCWBJAEsCWAJYEsCSAJYEsASwJIAlASypAcBrCCrnjwpggAUwwAALYIABFsAAS40BPmIUwAIYYAEMMMACGGCABTDAEsAAC2CAARbAAAMsgAEWwAAD/Nq4zSoHMMAAAwwwwAADDDDAAAMMMMAAAwxwY4CnfRHAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAPcOOPV4AAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwADXBZw6PYABBhhggAEGGGCAAQYYYIABBhhgixwAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAAFvksMgBMMAAAwwwwAADDDDAAAMMMMAAAwwwwAADDDDAHQNWHsAAAwwwwAADDDDAAAMMMMAAAwwwwLUBq/0ABlgAAwywAAYYYAEMsAAGGGABDDDAAhhg6Ruw8gAWwAADLIABlgAGWAADDLAkgCWAJQEsCWBJAEsASwJYEsASwJIAlgSwJIAlgCUBLAlgCWBJAEsCWBLAEsCSAJYEsCSAJYAl1e4BCoAoPGzrWlMAAAAASUVORK5CYII="
        )
        task_payload["annotated_image_media_type"] = "image/png"
    return {
        "task_id": f"test-task-{utcnow()}",
        "route_id": "test-route",
        "request_id": task_payload["request_id"],
        "target_kind": target_kind,
        "payload": task_payload,
    }


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
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions for this delivery service")
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
            delivery_result = await execute_delivery(db.get("settings", {}), task)
            details = {
                "delivered_to": task["target_kind"],
                "target_service_id": task["target_service_id"],
                "payload_keys": sorted(task["payload"].keys()),
            } | delivery_result
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
        db.append_event("aaa", "error", "No access to this delivery service", {"username": payload.username})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this delivery service")
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


@app.post("/api/test/webhook")
async def test_webhook(payload: DeliveryTestRequest, _: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    db: Database = app.state.db
    task = build_test_delivery_task("webhook", payload)
    result = await deliver_webhook(db.get("settings", {}), task)
    await emit_runtime_event(db, "delivery", "delivery.test.webhook", "success", "Webhook test completed", result, request_id=task["request_id"])
    return {"ok": True, "task": task, "result": result}


@app.post("/api/test/email")
async def test_email(payload: DeliveryTestRequest, _: dict[str, Any] = Depends(require_mode("manage"))) -> dict[str, Any]:
    db: Database = app.state.db
    task = build_test_delivery_task("email", payload)
    result = await deliver_email(db.get("settings", {}), task)
    await emit_runtime_event(db, "delivery", "delivery.test.email", "success", "Email test completed", result, request_id=task["request_id"])
    return {"ok": True, "task": task, "result": result}


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
    if task.get("target_kind") not in {"webhook", "email"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Delivery service accepts only webhook/email tasks")
    await app.state.delivery_queue.put(task)
    await emit_runtime_event(db, "delivery", "delivery.task.accepted", "success", "Accepted pushed delivery task", {"task_id": task.get("task_id")})
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
