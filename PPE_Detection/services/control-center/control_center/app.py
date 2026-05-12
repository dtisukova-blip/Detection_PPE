import base64
import binascii
import asyncio
import json
from pathlib import Path
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4
import secrets

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import get_db_path, get_pki_dir, get_root_password, get_tls_public_hosts
from .db import Database, utcnow
from .dependencies import get_current_user, get_database, require_roles, require_service_access
from .pki import ensure_internal_ca, get_paths as get_pki_paths, root_certificate_pem, sign_service_csr
from .schemas import (
    AuditEventResponse,
    CreateUserRequest,
    GrantAccessRequest,
    LoginRequest,
    LoginResponse,
    RevokeAccessRequest,
    RouteBindingCreateRequest,
    RouteBindingResponse,
    RouteBindingUpdateRequest,
    RuntimeConfigProposeRequest,
    RuntimeConfigPullRequest,
    RuntimeConfigPullResponse,
    RuntimeDeliveryNextTaskRequest,
    RuntimeDeliveryResultRequest,
    RuntimeDeliveryTaskResponse,
    RuntimeEventRequest,
    RuntimeEventResponse,
    RuntimeHeartbeatRequest,
    RuntimeInspectionRequest,
    RuntimeInspectionResponse,
    RuntimePkiEnrollRequest,
    RuntimePkiEnrollResponse,
    RuntimePkiRevokeResponse,
    RuntimeRegisterRequest,
    RuntimeRegisterResponse,
    RuntimeWorkerJobResponse,
    RuntimeWorkerNextJobRequest,
    RuntimeWorkerResultRequest,
    ServiceCreateRequest,
    ServiceProvisionResponse,
    ServiceResponse,
    ServiceUpdateRequest,
    UpdateUserRequest,
    UserResponse,
)
from .service_config import merged_default_settings, validate_service_settings
from .security import hash_password, issue_token, verify_password


app = FastAPI(title="PPE Control Center AAA", version="0.1.0")
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _certificate_ttl_hours(db: Database) -> int:
    settings = _get_control_center_settings(db)
    return int(settings.get("service_certificate_ttl_hours", 24))


def _utc_cutoff(seconds: int | float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=float(seconds))).replace(microsecond=0).isoformat()


def _write_audit(
    db: Database,
    actor_user_id: int | None,
    action: str,
    target_type: str,
    target_id: str | None,
    details: dict[str, Any],
) -> None:
    """Write a normalized audit event for privileged API actions."""
    with db.transaction() as connection:
        connection.execute(
            """
            INSERT INTO audit_log (actor_user_id, action, target_type, target_id, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_user_id, action, target_type,
             target_id, json.dumps(details), utcnow()),
        )


def _serialize_user(db: Database, username: str) -> dict[str, Any]:
    """Return a user together with effective service grants."""
    user = db.fetchone(
        "SELECT id, username, role, is_active, created_at FROM users WHERE username = ?",
        (username,),
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    access_rows = db.fetchall(
        """
        SELECT s.service_id, usa.access_level
        FROM user_service_access usa
        JOIN services s ON s.id = usa.service_id
        JOIN users u ON u.id = usa.user_id
        WHERE u.username = ?
        ORDER BY s.service_id
        """,
        (username,),
    )
    return {
        "username": user["username"],
        "role": user["role"],
        "is_active": bool(user["is_active"]),
        "created_at": user["created_at"],
        "access": [dict(row) for row in access_rows],
    }


def _serialize_service(service_row: Any) -> dict[str, Any]:
    """Normalize a raw service row into the public response shape."""
    raw_admin_state = service_row["admin_state"] if "admin_state" in service_row.keys(
    ) else service_row["status"]
    admin_state = "disabled" if raw_admin_state == "disabled" else "active"
    service = {
        "service_id": service_row["service_id"],
        "service_type": service_row["service_type"],
        "display_name": service_row["display_name"],
        "admin_state": admin_state,
        "settings": json.loads(service_row["settings_json"]) if "settings_json" in service_row.keys() else service_row["settings"],
        "created_at": service_row["created_at"],
    }
    for key in (
        "registration_status",
        "last_seen_at",
        "local_url",
        "config_version",
        "settings_updated_at",
        "last_error",
        "certificate_status",
        "certificate_serial_hex",
        "certificate_expires_at",
        "certificate_revoked_at",
    ):
        if key in service_row.keys():
            service[key] = service_row[key]
    return service


def _service_expected_access_level(role: str) -> str:
    """Derive service access mode from the user's global role."""
    if role == "admin":
        return "manage"
    if role == "auditor":
        return "read"
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Root does not need scoped access")


def _sanitize_service_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Remove local secrets before settings are sent to runtime services or UI."""
    return {key: value for key, value in settings.items() if key != "service_secret"}


def _write_runtime_event(
    db: Database,
    event_id: str,
    event_class: str,
    event_type: str,
    source_service_id: str,
    source_service_type: str,
    severity: str,
    payload: dict[str, Any],
    created_at: str,
    request_id: str | None = None,
    job_id: str | None = None,
) -> None:
    with db.transaction() as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO runtime_event_log
            (event_id, event_class, event_type, source_service_id, source_service_type, request_id, job_id, severity, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, event_class, event_type, source_service_id, source_service_type,
             request_id, job_id, severity, json.dumps(payload), created_at),
        )


def _serialize_runtime_event(row: Any) -> dict[str, Any]:
    return {
        "event_id": row["event_id"],
        "event_class": row["event_class"],
        "event_type": row["event_type"],
        "source_service_id": row["source_service_id"],
        "source_service_type": row["source_service_type"],
        "request_id": row["request_id"],
        "job_id": row["job_id"],
        "severity": row["severity"],
        "payload": json.loads(row["payload_json"]),
        "created_at": row["created_at"],
    }


def _normalize_service_settings(service_type: str, settings: dict[str, Any]) -> dict[str, Any]:
    return validate_service_settings(service_type, settings)


def _get_control_center_settings(db: Database) -> dict[str, Any]:
    row = db.fetchone(
        "SELECT settings_json FROM services WHERE service_id = ?", ("control-center",))
    if row is None:
        return merged_default_settings("control_center")
    return _normalize_service_settings("control_center", json.loads(row["settings_json"]))


def _get_service_with_runtime(db: Database, service_id: str) -> dict[str, Any]:
    row = db.fetchone(
        """
        SELECT s.id, s.service_id, s.service_type, s.display_name, s.status AS admin_state, s.settings_json, s.created_at,
               rs.local_url, rs.last_seen_at, rs.registration_status, rs.config_version, rs.settings_updated_at, rs.last_error,
               sc.bootstrap_secret,
               cert.status AS certificate_status, cert.serial_hex AS certificate_serial_hex, cert.expires_at AS certificate_expires_at, cert.revoked_at AS certificate_revoked_at
        FROM services s
        LEFT JOIN service_runtime_state rs ON rs.service_id = s.id
        LEFT JOIN service_credentials sc ON sc.service_id = s.id
        LEFT JOIN (
            SELECT sc1.*
            FROM service_certificates sc1
            JOIN (
                SELECT service_id, MAX(issued_at) AS max_issued_at
                FROM service_certificates
                GROUP BY service_id
            ) latest ON latest.service_id = sc1.service_id AND latest.max_issued_at = sc1.issued_at
        ) cert ON cert.service_id = s.id
        WHERE s.service_id = ?
        """,
        (service_id,),
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
    service = dict(row)
    service["settings"] = json.loads(service.pop("settings_json"))
    return service


def _service_row_by_id(connection: Any, service_id: str, expected_type: str | None = None) -> Any:
    row = connection.execute(
        "SELECT id, service_id, service_type FROM services WHERE service_id = ?",
        (service_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Service not found: {service_id}")
    if expected_type and row["service_type"] != expected_type:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Service {service_id} must be of type {expected_type}")
    return row


def _expected_delivery_service_type(target_kind: str) -> str:
    if target_kind == "database":
        return "storage"
    if target_kind in {"webhook", "email"}:
        return "delivery_service"
    if target_kind == "viewer":
        return "viewer"
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Unsupported target kind: {target_kind}")


def _serialize_route_targets(connection: Any, route_internal_id: int) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT s.service_id AS target_service_id, rt.target_kind, rt.is_required, rt.order_index, rt.filter_json
        FROM route_targets rt
        JOIN services s ON s.id = rt.target_service_id
        WHERE rt.route_id = ?
        ORDER BY rt.order_index ASC, rt.id ASC
        """,
        (route_internal_id,),
    ).fetchall()
    return [
        {
            "target_service_id": row["target_service_id"],
            "target_kind": row["target_kind"],
            "is_required": bool(row["is_required"]),
            "order_index": row["order_index"],
            "filter": json.loads(row["filter_json"]),
        }
        for row in rows
    ]


def _serialize_route_row(connection: Any, row: Any) -> dict[str, Any]:
    checkpoint_service_id = None
    if row["checkpoint_service_id"]:
        checkpoint_row = connection.execute(
            "SELECT service_id FROM services WHERE id = ?", (row["checkpoint_service_id"],)).fetchone()
        checkpoint_service_id = checkpoint_row["service_id"] if checkpoint_row else None
    worker_row = connection.execute(
        "SELECT service_id FROM services WHERE id = ?", (row["worker_service_id"],)).fetchone()
    return {
        "route_id": row["route_id"],
        "name": row["name"],
        "checkpoint_service_id": checkpoint_service_id,
        "worker_service_id": worker_row["service_id"],
        "is_default": bool(row["is_default"]),
        "priority": row["priority"],
        "is_active": bool(row["is_active"]),
        "targets": _serialize_route_targets(connection, row["id"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _resolve_route(db: Database, checkpoint_service_id: str) -> dict[str, Any]:
    settings = _get_control_center_settings(db)
    default_worker = str(settings.get(
        "default_worker_service_id") or "").strip()
    if default_worker:
        targets = [
            {
                "target_service_id": service_id,
                "target_kind": "database",
                "is_required": True,
                "order_index": index * 10,
                "filter": {},
            }
            for index, service_id in enumerate(settings.get("default_storage_service_ids", []), start=1)
        ]
        delivery_order_base = len(targets)
        targets.extend(
            {
                "target_service_id": service_id,
                "target_kind": "webhook",
                "is_required": False,
                "order_index": (delivery_order_base + index) * 10,
                "filter": {},
            }
            for index, service_id in enumerate(settings.get("default_delivery_service_ids", []), start=1)
        )
        viewer_order_base = len(targets)
        targets.extend(
            {
                "target_service_id": service_id,
                "target_kind": "viewer",
                "is_required": False,
                "order_index": (viewer_order_base + index) * 10,
                "filter": {},
            }
            for index, service_id in enumerate(settings.get("default_viewer_service_ids", []), start=1)
        )
        return {
            "route_id": "global-default",
            "name": "Global default route",
            "checkpoint_service_id": checkpoint_service_id,
            "worker_service_id": default_worker,
            "is_default": True,
            "priority": 0,
            "is_active": True,
            "targets": targets,
            "created_at": "",
            "updated_at": "",
        }
    with db.connect() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM route_bindings
            WHERE is_active = 1
              AND checkpoint_service_id = (SELECT id FROM services WHERE service_id = ?)
            ORDER BY priority ASC, id ASC
            LIMIT 1
            """,
            (checkpoint_service_id,),
        ).fetchone()
        if row is None and settings.get("allow_default_route", False):
            row = connection.execute(
                """
                SELECT *
                FROM route_bindings
                WHERE is_active = 1 AND is_default = 1
                ORDER BY priority ASC, id ASC
                LIMIT 1
                """
            ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="route_not_found")
        return _serialize_route_row(connection, row)


def _authenticate_runtime_service(
    db: Database,
    service_id: str,
    service_type: str,
    service_secret: str,
) -> dict[str, Any]:
    """Validate a runtime service against the registered inventory and its secret."""
    service = _get_service_with_runtime(db, service_id)
    if service["service_type"] != service_type:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Service type mismatch")
    if service["admin_state"] == "disabled":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Service is disabled")
    expected_secret = service.get("bootstrap_secret")
    if not expected_secret or expected_secret != service_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid service credentials")
    return service


def _runtime_verify_arg(local_url: str) -> str | bool:
    if not local_url.startswith("https://"):
        return False
    root_cert = get_pki_paths(get_pki_dir()).root_cert
    return str(root_cert) if root_cert.exists() else True


def _post_to_runtime_service(service: dict[str, Any], path: str, payload: dict[str, Any], timeout: float = 10) -> dict[str, Any]:
    local_url = (service.get("local_url") or "").rstrip("/")
    if not local_url:
        raise RuntimeError(f"Service {service['service_id']} has no local_url")
    try:
        with httpx.Client(timeout=timeout, verify=_runtime_verify_arg(local_url)) as client:
            response = client.post(f"{local_url}{path}", json=payload)
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Service {service['service_id']} push failed: {exc}") from exc
    if response.status_code >= 400:
        raise RuntimeError(
            f"Service {service['service_id']} returned HTTP {response.status_code}: {response.text[:500]}")
    return response.json()


def _push_config_to_service(db: Database, service_id: str) -> dict[str, Any] | None:
    service = _get_service_with_runtime(db, service_id)
    if service["service_type"] == "control_center" or not service.get("local_url"):
        return None
    payload = {
        "service_id": service["service_id"],
        "service_secret": service["bootstrap_secret"],
        "config_version": service.get("config_version", 1),
        "settings": _sanitize_service_settings(service["settings"]),
    }
    return _post_to_runtime_service(service, "/api/internal/config/apply", payload)


def _checkpoint_required_ppe(service: dict[str, Any]) -> list[str]:
    required = service["settings"].get(
        "required_ppe", ["hardhat", "safety_vest"])
    return [str(item) for item in required]


def _worker_job_payload(row: dict[str, Any] | Any) -> dict[str, Any]:
    return {
        "job_id": row["job_id"],
        "request_id": row["request_id"],
        "checkpoint_service_id": row["checkpoint_service_id"],
        "image_base64": row["image_base64"],
        "required_ppe": json.loads(row["required_ppe_json"]) if isinstance(row["required_ppe_json"], str) else row["required_ppe_json"],
    }


def _push_worker_job(db: Database, worker_service_id: str, job: dict[str, Any]) -> dict[str, Any]:
    worker = _get_service_with_runtime(db, worker_service_id)
    return _post_to_runtime_service(
        worker,
        "/api/internal/jobs/enqueue",
        {
            "service_id": worker["service_id"],
            "service_secret": worker["bootstrap_secret"],
            "job": job,
        },
    )


def _push_delivery_task(db: Database, target_service_id: str, task: dict[str, Any]) -> dict[str, Any]:
    service = _get_service_with_runtime(db, target_service_id)
    return _post_to_runtime_service(
        service,
        "/api/internal/delivery/enqueue",
        {
            "service_id": service["service_id"],
            "service_secret": service["bootstrap_secret"],
            "task": task,
        },
    )


def _evaluate_ppe(required_ppe: list[str], detections: list[dict[str, Any]]) -> tuple[str, str, str]:
    detected_classes = {item.get("class") for item in detections}
    for required in required_ppe:
        if required not in detected_classes:
            return "deny-access", f"{required}_missing", f"Required PPE missing: {required}"
    return "permit-access", "all_required_ppe_present", "Required PPE detected"


def _missing_required_ppe(required_ppe: list[str], detections: list[dict[str, Any]]) -> list[str]:
    detected_classes = {item.get("class") for item in detections}
    return [item for item in required_ppe if item not in detected_classes]


def _decision_label(decision: str) -> str:
    if decision == "permit-access":
        return "Допуск разрешен"
    if decision == "deny-access":
        return "Обнаружено нарушение"
    return "Ошибка проверки"


def _enqueue_delivery_tasks(db: Database, route: dict[str, Any], result: dict[str, Any], checkpoint_service_id: str, worker_service_id: str | None) -> None:
    targets = route.get("targets", [])
    if not targets:
        return
    created_tasks: list[dict[str, Any]] = []
    leased_at = utcnow()
    with db.transaction() as connection:
        for target in targets:
            task_id = str(uuid4())
            payload = {
                "route_id": route["route_id"],
                "request_id": result["request_id"],
                "checkpoint_service_id": checkpoint_service_id,
                "worker_service_id": worker_service_id,
                "decision": result["decision"],
                "decision_label": _decision_label(result["decision"]),
                "reason_code": result["reason_code"],
                "reason_text": result["reason_text"],
                "required_ppe": result.get("required_ppe", []),
                "missing_required": result.get("missing_required", []),
                "detections": result["detections"],
                "annotated_image_base64": result.get("annotated_image_base64"),
                "annotated_image_media_type": result.get("annotated_image_media_type"),
                "inspection_created_at": result.get("created_at"),
                "inspection_processed_at": result.get("processed_at"),
                "inspection_completed_at": result.get("completed_at"),
                "target_kind": target["target_kind"],
                "filter": target["filter"],
            }
            task = {
                "task_id": task_id,
                "route_id": route["route_id"],
                "request_id": result["request_id"],
                "checkpoint_service_id": checkpoint_service_id,
                "worker_service_id": worker_service_id,
                "target_service_id": target["target_service_id"],
                "target_kind": target["target_kind"],
                "payload": payload,
            }
            connection.execute(
                """
                INSERT INTO delivery_tasks
                (task_id, route_id, request_id, checkpoint_service_id, worker_service_id, target_service_id, target_kind, is_required, attempt_count, status, payload_json, created_at, leased_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'leased', ?, ?, ?)
                """,
                (
                    task_id,
                    route["route_id"],
                    result["request_id"],
                    checkpoint_service_id,
                    worker_service_id,
                    target["target_service_id"],
                    target["target_kind"],
                    int(target["is_required"]),
                    json.dumps(payload),
                    leased_at,
                    leased_at,
                ),
            )
            created_tasks.append(task)
    for task in created_tasks:
        try:
            push_result = _push_delivery_task(
                db, task["target_service_id"], task)
        except Exception as exc:
            current = db.fetchone(
                "SELECT attempt_count FROM delivery_tasks WHERE task_id = ?", (task["task_id"],))
            attempt_count = int(current["attempt_count"]) if current else 1
            retry_limit = int(_get_control_center_settings(
                db).get("delivery_retry_limit", 5))
            next_status = "failed" if attempt_count >= retry_limit else "queued"
            with db.transaction() as connection:
                connection.execute(
                    "UPDATE delivery_tasks SET status = ?, leased_at = NULL, error_text = ? WHERE task_id = ?",
                    (next_status, f"Push failed: {exc}", task["task_id"]),
                )
            _write_runtime_event(
                db,
                event_id=str(uuid4()),
                event_class="delivery",
                event_type="delivery.task.dead_letter" if next_status == "failed" else "delivery.task.push_failed",
                source_service_id="control-center",
                source_service_type="control_center",
                severity="error",
                payload={"task_id": task["task_id"], "target_service_id": task["target_service_id"],
                         "attempt_count": attempt_count, "error": str(exc)},
                created_at=utcnow(),
                request_id=task["request_id"],
            )
        else:
            _write_runtime_event(
                db,
                event_id=str(uuid4()),
                event_class="delivery",
                event_type="delivery.task.pushed",
                source_service_id="control-center",
                source_service_type="control_center",
                severity="info",
                payload={
                    "task_id": task["task_id"], "target_service_id": task["target_service_id"], "push_result": push_result},
                created_at=utcnow(),
                request_id=task["request_id"],
            )


async def push_retry_loop() -> None:
    while True:
        db: Database = app.state.db
        settings = _get_control_center_settings(db)
        retry_limit = int(settings.get("delivery_retry_limit", 5))
        retry_delay = max(int(settings.get("delivery_retry_delay_sec", 5)), 1)
        with db.connect() as connection:
            worker_rows = connection.execute(
                """
                SELECT job_id, request_id, checkpoint_service_id, worker_service_id, image_base64, required_ppe_json
                FROM inspection_jobs
                WHERE status = 'queued'
                ORDER BY id ASC
                LIMIT 10
                """
            ).fetchall()
            delivery_rows = connection.execute(
                """
                SELECT task_id, route_id, request_id, checkpoint_service_id, worker_service_id, target_service_id, target_kind, payload_json, attempt_count
                FROM delivery_tasks
                WHERE status = 'queued' AND attempt_count < ?
                ORDER BY id ASC
                LIMIT 20
                """,
                (retry_limit,),
            ).fetchall()
        for row in worker_rows:
            job = _worker_job_payload(row)
            try:
                push_result = await asyncio.to_thread(_push_worker_job, db, row["worker_service_id"], job)
            except Exception as exc:
                _write_runtime_event(
                    db,
                    event_id=str(uuid4()),
                    event_class="processing",
                    event_type="processing.job.retry_failed",
                    source_service_id="control-center",
                    source_service_type="control_center",
                    severity="error",
                    payload={
                        "job_id": row["job_id"], "worker_service_id": row["worker_service_id"], "error": str(exc)},
                    created_at=utcnow(),
                    request_id=row["request_id"],
                    job_id=row["job_id"],
                )
            else:
                with db.transaction() as connection:
                    connection.execute(
                        "UPDATE inspection_jobs SET status = 'leased', leased_at = ? WHERE job_id = ? AND status = 'queued'", (utcnow(), row["job_id"]))
                _write_runtime_event(
                    db,
                    event_id=str(uuid4()),
                    event_class="processing",
                    event_type="processing.job.retry_pushed",
                    source_service_id="control-center",
                    source_service_type="control_center",
                    severity="info",
                    payload={
                        "job_id": row["job_id"], "worker_service_id": row["worker_service_id"], "push_result": push_result},
                    created_at=utcnow(),
                    request_id=row["request_id"],
                    job_id=row["job_id"],
                )
        for row in delivery_rows:
            task = {
                "task_id": row["task_id"],
                "route_id": row["route_id"],
                "request_id": row["request_id"],
                "checkpoint_service_id": row["checkpoint_service_id"],
                "worker_service_id": row["worker_service_id"],
                "target_service_id": row["target_service_id"],
                "target_kind": row["target_kind"],
                "payload": json.loads(row["payload_json"]),
            }
            try:
                push_result = await asyncio.to_thread(_push_delivery_task, db, row["target_service_id"], task)
            except Exception as exc:
                attempt_count = int(row["attempt_count"]) + 1
                next_status = "failed" if attempt_count >= retry_limit else "queued"
                with db.transaction() as connection:
                    connection.execute(
                        "UPDATE delivery_tasks SET attempt_count = ?, status = ?, error_text = ? WHERE task_id = ?",
                        (attempt_count, next_status,
                         f"Push failed: {exc}", row["task_id"]),
                    )
                _write_runtime_event(
                    db,
                    event_id=str(uuid4()),
                    event_class="delivery",
                    event_type="delivery.task.dead_letter" if next_status == "failed" else "delivery.task.retry_failed",
                    source_service_id="control-center",
                    source_service_type="control_center",
                    severity="error",
                    payload={"task_id": row["task_id"], "target_service_id": row["target_service_id"],
                             "attempt_count": attempt_count, "error": str(exc)},
                    created_at=utcnow(),
                    request_id=row["request_id"],
                )
            else:
                with db.transaction() as connection:
                    connection.execute(
                        "UPDATE delivery_tasks SET status = 'leased', leased_at = ?, attempt_count = attempt_count + 1, error_text = NULL WHERE task_id = ? AND status = 'queued'",
                        (utcnow(), row["task_id"]),
                    )
                _write_runtime_event(
                    db,
                    event_id=str(uuid4()),
                    event_class="delivery",
                    event_type="delivery.task.retry_pushed",
                    source_service_id="control-center",
                    source_service_type="control_center",
                    severity="info",
                    payload={
                        "task_id": row["task_id"], "target_service_id": row["target_service_id"], "push_result": push_result},
                    created_at=utcnow(),
                    request_id=row["request_id"],
                )
        await asyncio.sleep(retry_delay)


@app.on_event("startup")
async def startup() -> None:
    """Initialize the AAA database before the API starts serving requests."""
    db = Database(get_db_path())
    db.initialize(get_root_password())
    ensure_internal_ca(get_pki_dir(), get_tls_public_hosts())
    app.state.db = db
    app.state.push_retry_task = asyncio.create_task(push_retry_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    task = getattr(app.state, "push_retry_task", None)
    if task:
        task.cancel()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Serve the built-in operator UI."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    """Minimal healthcheck endpoint for probes and smoke tests."""
    return {"status": "ok"}


@app.post("/api/v1/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Database = Depends(get_database)) -> LoginResponse:
    """
    Authenticate a human operator and create a server-side session token.

    In this MVP the token is stored in SQLite, which keeps revocation and
    auditing straightforward before we introduce JWT or a separate AAA service.
    """
    user = db.fetchone(
        """
        SELECT id, username, password_salt, password_hash, role, is_active, created_at
        FROM users
        WHERE username = ?
        """,
        (payload.username,),
    )
    if user is None or not bool(user["is_active"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(payload.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = issue_token()
    with db.transaction() as connection:
        connection.execute(
            "INSERT INTO auth_tokens (user_id, token, issued_at) VALUES (?, ?, ?)",
            (user["id"], token, utcnow()),
        )

    _write_audit(db, user["id"], "auth.login", "user", user["username"], {})
    return LoginResponse(access_token=token, user=_serialize_user(db, user["username"]))


@app.get("/api/v1/auth/me", response_model=UserResponse)
def get_me(user: dict[str, Any] = Depends(get_current_user), db: Database = Depends(get_database)) -> UserResponse:
    """Return the authenticated user profile and visible service grants."""
    return UserResponse(**_serialize_user(db, user["username"]))


@app.post("/api/v1/users", response_model=UserResponse)
def create_user(
    payload: CreateUserRequest,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> UserResponse:
    """Create a new operator account. Only the global root can do this."""
    if payload.role == "root" and payload.username != "root":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Only one root user is allowed")

    existing = db.fetchone(
        "SELECT id FROM users WHERE username = ?", (payload.username,))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    salt, password_hash = hash_password(payload.password)
    with db.transaction() as connection:
        cursor = connection.execute(
            """
            INSERT INTO users (username, password_salt, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (payload.username, salt, password_hash, payload.role, utcnow()),
        )
        user_id = cursor.lastrowid

        for access in payload.access:
            service = connection.execute(
                "SELECT id FROM services WHERE service_id = ?",
                (access.service_id,),
            ).fetchone()
            if service is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Service not found: {access.service_id}",
                )
            connection.execute(
                """
                INSERT INTO user_service_access (user_id, service_id, access_level)
                VALUES (?, ?, ?)
                """,
                (user_id, service["id"],
                 _service_expected_access_level(payload.role)),
            )

    _write_audit(db, user["id"], "user.create", "user",
                 payload.username, {"role": payload.role})
    return UserResponse(**_serialize_user(db, payload.username))


@app.get("/api/v1/users", response_model=list[UserResponse])
def list_users(
    _: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> list[UserResponse]:
    """List all operator accounts known to the AAA server."""
    rows = db.fetchall("SELECT username FROM users ORDER BY username")
    return [UserResponse(**_serialize_user(db, row["username"])) for row in rows]


@app.patch("/api/v1/users/{username}", response_model=UserResponse)
def update_user(
    username: str,
    payload: UpdateUserRequest,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> UserResponse:
    """Update role, password, or active state for an operator."""
    existing = db.fetchone(
        "SELECT username, role, is_active FROM users WHERE username = ?", (username,))
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if username == "root" and payload.role and payload.role != "root":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Root role cannot be changed")
    if username == "root" and payload.is_active is False:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Root user cannot be disabled")

    next_role = payload.role if payload.role is not None else existing["role"]
    next_active = int(
        payload.is_active) if payload.is_active is not None else existing["is_active"]

    with db.transaction() as connection:
        connection.execute(
            "UPDATE users SET role = ?, is_active = ? WHERE username = ?",
            (next_role, next_active, username),
        )
        if next_role in ("admin", "auditor"):
            connection.execute(
                """
                UPDATE user_service_access
                SET access_level = ?
                WHERE user_id = (SELECT id FROM users WHERE username = ?)
                """,
                (_service_expected_access_level(next_role), username),
            )
        if payload.password:
            salt, password_hash = hash_password(payload.password)
            connection.execute(
                "UPDATE users SET password_salt = ?, password_hash = ? WHERE username = ?",
                (salt, password_hash, username),
            )

    _write_audit(
        db,
        user["id"],
        "user.update",
        "user",
        username,
        {"role": next_role, "is_active": bool(
            next_active), "password_updated": bool(payload.password)},
    )
    return UserResponse(**_serialize_user(db, username))


@app.delete("/api/v1/users/{username}")
def delete_user(
    username: str,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> dict[str, str]:
    """Delete an operator account except the built-in root user."""
    existing = db.fetchone(
        "SELECT id FROM users WHERE username = ?", (username,))
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if username == "root":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Root user cannot be deleted")

    with db.transaction() as connection:
        connection.execute("DELETE FROM users WHERE username = ?", (username,))

    _write_audit(db, user["id"], "user.delete", "user", username, {})
    return {"status": "deleted"}


@app.post("/api/v1/services", response_model=ServiceProvisionResponse)
def register_service(
    payload: ServiceCreateRequest,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> ServiceProvisionResponse:
    """Register a checkpoint, worker, storage, or delivery service."""
    existing = db.fetchone(
        "SELECT id FROM services WHERE service_id = ?", (payload.service_id,))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Service already exists")
    validated_settings = _normalize_service_settings(
        payload.service_type, payload.settings)

    with db.transaction() as connection:
        bootstrap_secret = secrets.token_urlsafe(24)
        connection.execute(
            """
            INSERT INTO services (service_id, service_type, display_name, status, settings_json, created_at)
            VALUES (?, ?, ?, 'active', ?, ?)
            """,
            (
                payload.service_id,
                payload.service_type,
                payload.display_name,
                json.dumps(validated_settings),
                utcnow(),
            ),
        )
        service_row = connection.execute(
            "SELECT id FROM services WHERE service_id = ?", (payload.service_id,)).fetchone()
        connection.execute(
            """
            INSERT INTO service_runtime_state (service_id, registration_status, config_version, settings_updated_at)
            VALUES (?, 'pending', 1, ?)
            """,
            (service_row["id"], utcnow()),
        )
        connection.execute(
            """
            INSERT INTO service_credentials (service_id, bootstrap_secret, rotated_at)
            VALUES (?, ?, ?)
            """,
            (service_row["id"], bootstrap_secret, utcnow()),
        )

    _write_audit(db, user["id"], "service.create", "service",
                 payload.service_id, {"type": payload.service_type})
    service = _get_service_with_runtime(db, payload.service_id)
    return ServiceProvisionResponse(
        **{
            k: service[k]
            for k in (
                "service_id",
                "service_type",
                "display_name",
                "admin_state",
                "settings",
                "created_at",
                "registration_status",
                "last_seen_at",
                "local_url",
                "config_version",
                "settings_updated_at",
                "last_error",
                "certificate_status",
                "certificate_serial_hex",
                "certificate_expires_at",
                "certificate_revoked_at",
            )
        },
        bootstrap_secret=bootstrap_secret,
    )


@app.get("/api/v1/services", response_model=list[ServiceResponse])
def list_services(
    user: dict[str, Any] = Depends(get_current_user),
    db: Database = Depends(get_database),
) -> list[ServiceResponse]:
    """List services visible to the current operator."""
    if user["role"] == "root":
        rows = db.fetchall(
            """
            SELECT s.service_id, s.service_type, s.display_name, s.status AS admin_state, s.settings_json, s.created_at,
                   rs.local_url, rs.last_seen_at, rs.registration_status, rs.config_version, rs.settings_updated_at, rs.last_error,
                   cert.status AS certificate_status, cert.serial_hex AS certificate_serial_hex, cert.expires_at AS certificate_expires_at, cert.revoked_at AS certificate_revoked_at
            FROM services s
            LEFT JOIN service_runtime_state rs ON rs.service_id = s.id
            LEFT JOIN (
                SELECT sc1.*
                FROM service_certificates sc1
                JOIN (
                    SELECT service_id, MAX(issued_at) AS max_issued_at
                    FROM service_certificates
                    GROUP BY service_id
                ) latest ON latest.service_id = sc1.service_id AND latest.max_issued_at = sc1.issued_at
            ) cert ON cert.service_id = s.id
            ORDER BY s.service_id
            """
        )
    else:
        rows = db.fetchall(
            """
            SELECT s.service_id, s.service_type, s.display_name, s.status AS admin_state, s.settings_json, s.created_at,
                   rs.local_url, rs.last_seen_at, rs.registration_status, rs.config_version, rs.settings_updated_at, rs.last_error,
                   cert.status AS certificate_status, cert.serial_hex AS certificate_serial_hex, cert.expires_at AS certificate_expires_at, cert.revoked_at AS certificate_revoked_at
            FROM services s
            LEFT JOIN service_runtime_state rs ON rs.service_id = s.id
            LEFT JOIN (
                SELECT sc1.*
                FROM service_certificates sc1
                JOIN (
                    SELECT service_id, MAX(issued_at) AS max_issued_at
                    FROM service_certificates
                    GROUP BY service_id
                ) latest ON latest.service_id = sc1.service_id AND latest.max_issued_at = sc1.issued_at
            ) cert ON cert.service_id = s.id
            JOIN user_service_access usa ON usa.service_id = s.id
            JOIN users u ON u.id = usa.user_id
            WHERE u.username = ?
            ORDER BY s.service_id
            """,
            (user["username"],),
        )
    return [ServiceResponse(**_serialize_service(row)) for row in rows]


@app.get("/api/v1/services/{service_id}", response_model=ServiceResponse)
def get_service(
    service_id: str,
    user: dict[str, Any] = Depends(get_current_user),
    db: Database = Depends(get_database),
) -> ServiceResponse:
    """Return one registered service if the user has at least read access."""
    require_service_access(service_id, "read", db, user)
    return ServiceResponse(**_get_service_with_runtime(db, service_id))


@app.patch("/api/v1/services/{service_id}", response_model=ServiceResponse)
def update_service(
    service_id: str,
    payload: ServiceUpdateRequest,
    user: dict[str, Any] = Depends(get_current_user),
    db: Database = Depends(get_database),
) -> ServiceResponse:
    """Update service settings or admin enablement for users with manage access."""
    service = require_service_access(service_id, "manage", db, user)
    updated = {
        "display_name": payload.display_name if payload.display_name is not None else service["display_name"],
        "admin_state": payload.admin_state if payload.admin_state is not None else service["admin_state"],
        "settings": _normalize_service_settings(service["service_type"], payload.settings) if payload.settings is not None else service["settings"],
    }
    next_config_version = service.get("config_version", 1)
    if payload.settings is not None:
        next_config_version += 1

    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE services
            SET display_name = ?, status = ?, settings_json = ?
            WHERE service_id = ?
            """,
            (updated["display_name"], updated["admin_state"],
             json.dumps(updated["settings"]), service_id),
        )
        if payload.settings is not None:
            connection.execute(
                """
                UPDATE service_runtime_state
                SET config_version = ?, settings_updated_at = ?, registration_status = 'approved'
                WHERE service_id = (SELECT id FROM services WHERE service_id = ?)
                """,
                (next_config_version, utcnow(), service_id),
            )

    _write_audit(db, user["id"], "service.update",
                 "service", service_id, updated)
    push_result = None
    if payload.settings is not None:
        try:
            push_result = _push_config_to_service(db, service_id)
        except Exception as exc:
            with db.transaction() as connection:
                connection.execute(
                    """
                    UPDATE service_runtime_state
                    SET last_error = ?
                    WHERE service_id = (SELECT id FROM services WHERE service_id = ?)
                    """,
                    (f"Config push failed: {exc}", service_id),
                )
            _write_audit(db, user["id"], "service.config.push.failed",
                         "service", service_id, {"error": str(exc)})
        else:
            if push_result is not None:
                _write_audit(
                    db, user["id"], "service.config.pushed", "service", service_id, push_result)
    refreshed = _get_service_with_runtime(db, service_id)
    return ServiceResponse(**_serialize_service(refreshed))


@app.delete("/api/v1/services/{service_id}")
def delete_service(
    service_id: str,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> dict[str, str]:
    """Delete a registered service except the built-in control-center."""
    existing = db.fetchone(
        "SELECT id FROM services WHERE service_id = ?", (service_id,))
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")
    if service_id == "control-center":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Built-in control-center cannot be deleted")

    with db.transaction() as connection:
        connection.execute(
            "DELETE FROM services WHERE service_id = ?", (service_id,))

    _write_audit(db, user["id"], "service.delete", "service", service_id, {})
    return {"status": "deleted"}


@app.post("/api/v1/services/{service_id}/credentials/rotate")
def rotate_service_credentials(
    service_id: str,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> dict[str, str]:
    """Rotate bootstrap credentials for a registered runtime service."""
    service = _get_service_with_runtime(db, service_id)
    if service["service_type"] == "control_center":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Built-in control-center credentials cannot be rotated here")

    bootstrap_secret = secrets.token_urlsafe(24)
    with db.transaction() as connection:
        connection.execute(
            """
            INSERT INTO service_credentials (service_id, bootstrap_secret, rotated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(service_id) DO UPDATE SET bootstrap_secret = excluded.bootstrap_secret, rotated_at = excluded.rotated_at
            """,
            (service["id"], bootstrap_secret, utcnow()),
        )

    _write_audit(db, user["id"], "service.credentials.rotate",
                 "service", service_id, {})
    return {"service_id": service_id, "bootstrap_secret": bootstrap_secret}


@app.get("/api/v1/pki/root-cert")
def get_root_certificate() -> Response:
    return Response(content=root_certificate_pem(get_pki_dir()), media_type="application/x-pem-file")


@app.post("/api/v1/pki/services/{service_id}/revoke", response_model=RuntimePkiRevokeResponse)
def revoke_service_certificates(
    service_id: str,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> RuntimePkiRevokeResponse:
    service = _get_service_with_runtime(db, service_id)
    rows = db.fetchall(
        """
        SELECT serial_hex FROM service_certificates
        WHERE service_id = (SELECT id FROM services WHERE service_id = ?) AND status = 'active'
        """,
        (service_id,),
    )
    serials = [row["serial_hex"] for row in rows]
    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE service_certificates
            SET status = 'revoked', revoked_at = ?, revoke_reason = ?
            WHERE service_id = (SELECT id FROM services WHERE service_id = ?) AND status = 'active'
            """,
            (utcnow(), "manual_revoke", service_id),
        )
    _write_audit(db, user["id"], "service.certificate.revoke", "service", service_id, {
                 "revoked_serials": serials, "service_type": service["service_type"]})
    return RuntimePkiRevokeResponse(service_id=service_id, status="revoked", revoked_serials=serials)


@app.post("/api/v1/routes", response_model=RouteBindingResponse)
def create_route(
    payload: RouteBindingCreateRequest,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> RouteBindingResponse:
    with db.transaction() as connection:
        existing = connection.execute(
            "SELECT id FROM route_bindings WHERE route_id = ?", (payload.route_id,)).fetchone()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Route already exists")
        if payload.is_default and payload.checkpoint_service_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Default route must not target a specific checkpoint")
        if not payload.is_default and not payload.checkpoint_service_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Exact route must include checkpoint_service_id")
        checkpoint_row = None
        if payload.checkpoint_service_id:
            checkpoint_row = _service_row_by_id(
                connection, payload.checkpoint_service_id, "checkpoint")
        worker_row = _service_row_by_id(
            connection, payload.worker_service_id, "worker")
        now = utcnow()
        cursor = connection.execute(
            """
            INSERT INTO route_bindings
            (route_id, name, checkpoint_service_id, worker_service_id, is_default, priority, is_active, match_rules_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.route_id,
                payload.name,
                checkpoint_row["id"] if checkpoint_row else None,
                worker_row["id"],
                int(payload.is_default),
                payload.priority,
                int(payload.is_active),
                "{}",
                now,
                now,
            ),
        )
        route_internal_id = cursor.lastrowid
        for target in payload.targets:
            target_row = _service_row_by_id(
                connection, target.target_service_id, _expected_delivery_service_type(target.target_kind))
            connection.execute(
                """
                INSERT INTO route_targets
                (route_id, target_service_id, target_kind, is_required, order_index, filter_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (route_internal_id, target_row["id"], target.target_kind, int(
                    target.is_required), target.order_index, json.dumps(target.filter), now),
            )
        route_row = connection.execute(
            "SELECT * FROM route_bindings WHERE id = ?", (route_internal_id,)).fetchone()
        response = _serialize_route_row(connection, route_row)
    _write_audit(db, user["id"], "route.create",
                 "route", payload.route_id, response)
    return RouteBindingResponse(**response)


@app.get("/api/v1/routes", response_model=list[RouteBindingResponse])
def list_routes(
    _: dict[str, Any] = Depends(require_roles("root", "admin", "auditor")),
    db: Database = Depends(get_database),
) -> list[RouteBindingResponse]:
    with db.connect() as connection:
        rows = connection.execute(
            "SELECT * FROM route_bindings ORDER BY priority ASC, route_id ASC").fetchall()
        return [RouteBindingResponse(**_serialize_route_row(connection, row)) for row in rows]


@app.patch("/api/v1/routes/{route_id}", response_model=RouteBindingResponse)
def update_route(
    route_id: str,
    payload: RouteBindingUpdateRequest,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> RouteBindingResponse:
    with db.transaction() as connection:
        existing = connection.execute(
            "SELECT * FROM route_bindings WHERE route_id = ?", (route_id,)).fetchone()
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Route not found")
        checkpoint_internal = existing["checkpoint_service_id"]
        if payload.checkpoint_service_id is not None:
            checkpoint_internal = _service_row_by_id(
                connection, payload.checkpoint_service_id, "checkpoint")["id"]
        worker_internal = existing["worker_service_id"]
        if payload.worker_service_id is not None:
            worker_internal = _service_row_by_id(
                connection, payload.worker_service_id, "worker")["id"]
        updated = {
            "name": payload.name if payload.name is not None else existing["name"],
            "checkpoint_service_id": checkpoint_internal,
            "worker_service_id": worker_internal,
            "is_default": int(payload.is_default) if payload.is_default is not None else existing["is_default"],
            "priority": payload.priority if payload.priority is not None else existing["priority"],
            "is_active": int(payload.is_active) if payload.is_active is not None else existing["is_active"],
            "updated_at": utcnow(),
        }
        if updated["is_default"] and updated["checkpoint_service_id"] is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Default route must not target a specific checkpoint")
        if not updated["is_default"] and updated["checkpoint_service_id"] is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Exact route must include checkpoint_service_id")
        connection.execute(
            """
            UPDATE route_bindings
            SET name = ?, checkpoint_service_id = ?, worker_service_id = ?, is_default = ?, priority = ?, is_active = ?, updated_at = ?
            WHERE route_id = ?
            """,
            (
                updated["name"],
                updated["checkpoint_service_id"],
                updated["worker_service_id"],
                updated["is_default"],
                updated["priority"],
                updated["is_active"],
                updated["updated_at"],
                route_id,
            ),
        )
        if payload.targets is not None:
            connection.execute(
                "DELETE FROM route_targets WHERE route_id = ?", (existing["id"],))
            now = utcnow()
            for target in payload.targets:
                target_row = _service_row_by_id(
                    connection, target.target_service_id, _expected_delivery_service_type(target.target_kind))
                connection.execute(
                    """
                    INSERT INTO route_targets
                    (route_id, target_service_id, target_kind, is_required, order_index, filter_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (existing["id"], target_row["id"], target.target_kind, int(
                        target.is_required), target.order_index, json.dumps(target.filter), now),
                )
        route_row = connection.execute(
            "SELECT * FROM route_bindings WHERE route_id = ?", (route_id,)).fetchone()
        response = _serialize_route_row(connection, route_row)
    _write_audit(db, user["id"], "route.update", "route", route_id, response)
    return RouteBindingResponse(**response)


@app.delete("/api/v1/routes/{route_id}")
def delete_route(
    route_id: str,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> dict[str, str]:
    with db.transaction() as connection:
        deleted = connection.execute(
            "DELETE FROM route_bindings WHERE route_id = ?", (route_id,))
        if deleted.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Route not found")
    _write_audit(db, user["id"], "route.delete", "route", route_id, {})
    return {"status": "deleted"}


@app.post("/api/v1/access/grants", response_model=UserResponse)
def grant_access(
    payload: GrantAccessRequest,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> UserResponse:
    """Grant or replace a scoped permission for an operator on a service."""
    target_user = db.fetchone(
        "SELECT id, role FROM users WHERE username = ?", (payload.username,))
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target_user["role"] == "root":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Root does not need scoped access")

    target_service = db.fetchone(
        "SELECT id FROM services WHERE service_id = ?", (payload.service_id,))
    if target_service is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    with db.transaction() as connection:
        connection.execute(
            """
            INSERT INTO user_service_access (user_id, service_id, access_level)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, service_id) DO UPDATE SET access_level = excluded.access_level
            """,
            (target_user["id"], target_service["id"],
             _service_expected_access_level(target_user["role"])),
        )

    _write_audit(
        db,
        user["id"],
        "access.grant",
        "service",
        payload.service_id,
        {"username": payload.username,
            "access_level": _service_expected_access_level(target_user["role"])},
    )
    return UserResponse(**_serialize_user(db, payload.username))


@app.delete("/api/v1/access/grants", response_model=UserResponse)
def revoke_access(
    payload: RevokeAccessRequest,
    user: dict[str, Any] = Depends(require_roles("root")),
    db: Database = Depends(get_database),
) -> UserResponse:
    """Remove a scoped permission from a user."""
    target_user = db.fetchone(
        "SELECT id, role FROM users WHERE username = ?", (payload.username,))
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target_user["role"] == "root":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Root does not use scoped access")

    target_service = db.fetchone(
        "SELECT id FROM services WHERE service_id = ?", (payload.service_id,))
    if target_service is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    with db.transaction() as connection:
        deleted = connection.execute(
            "DELETE FROM user_service_access WHERE user_id = ? AND service_id = ?",
            (target_user["id"], target_service["id"]),
        )
        if deleted.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Access grant not found")

    _write_audit(db, user["id"], "access.revoke", "service",
                 payload.service_id, {"username": payload.username})
    return UserResponse(**_serialize_user(db, payload.username))


@app.post("/api/v1/runtime/register", response_model=RuntimeRegisterResponse)
def runtime_register(payload: RuntimeRegisterRequest, db: Database = Depends(get_database)) -> RuntimeRegisterResponse:
    """Approve a runtime service and return the current effective settings."""
    service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    heartbeat_interval = int(
        service["settings"].get("heartbeat_interval_sec", 10))

    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE service_runtime_state
            SET local_url = ?, last_seen_at = ?, registration_status = 'approved', last_error = NULL
            WHERE service_id = ?
            """,
            (payload.local_url, utcnow(), service["id"]),
        )
    _write_runtime_event(
        db,
        event_id=str(uuid4()),
        event_class="registration",
        event_type="runtime.registration.approved",
        source_service_id=payload.service_id,
        source_service_type=payload.service_type,
        severity="info",
        payload={"local_url": payload.local_url,
                 "status_snapshot": payload.status_snapshot},
        created_at=utcnow(),
    )

    return RuntimeRegisterResponse(
        approved=True,
        service_id=payload.service_id,
        heartbeat_interval_sec=heartbeat_interval,
        config_version=service.get("config_version", 1) or 1,
        settings=_sanitize_service_settings(service["settings"]),
    )


@app.post("/api/v1/runtime/pki/enroll", response_model=RuntimePkiEnrollResponse)
def runtime_pki_enroll(payload: RuntimePkiEnrollRequest, db: Database = Depends(get_database)) -> RuntimePkiEnrollResponse:
    service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    cert_pem, serial_hex, expires_at = sign_service_csr(
        get_pki_dir(), payload.csr_pem, _certificate_ttl_hours(db))
    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE service_certificates
            SET status = 'replaced'
            WHERE service_id = ? AND status = 'active'
            """,
            (service["id"],),
        )
        connection.execute(
            """
            INSERT INTO service_certificates (service_id, serial_hex, cert_pem, status, issued_at, expires_at)
            VALUES (?, ?, ?, 'active', ?, ?)
            """,
            (service["id"], serial_hex, cert_pem, utcnow(), expires_at),
        )
    _write_runtime_event(
        db,
        event_id=str(uuid4()),
        event_class="security",
        event_type="security.certificate.issued",
        source_service_id=payload.service_id,
        source_service_type=payload.service_type,
        severity="info",
        payload={"serial_hex": serial_hex, "expires_at": expires_at},
        created_at=utcnow(),
    )
    return RuntimePkiEnrollResponse(
        service_id=payload.service_id,
        cert_pem=cert_pem,
        root_cert_pem=root_certificate_pem(get_pki_dir()),
        serial_hex=serial_hex,
        expires_at=expires_at,
    )


@app.post("/api/v1/runtime/events")
def runtime_event_ingest(payload: RuntimeEventRequest, db: Database = Depends(get_database)) -> dict[str, str]:
    service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    _write_runtime_event(
        db,
        event_id=payload.event_id,
        event_class=payload.event_class,
        event_type=payload.event_type,
        source_service_id=payload.service_id,
        source_service_type=payload.service_type,
        severity=payload.severity,
        payload=payload.payload,
        created_at=payload.created_at,
        request_id=payload.request_id,
        job_id=payload.job_id,
    )
    if payload.event_class in {"security", "config", "registration"}:
        _write_audit(
            db,
            None,
            f"runtime.{payload.event_type}",
            "service",
            payload.service_id,
            {"severity": payload.severity, "payload": payload.payload,
                "service_type": service["service_type"]},
        )
    return {"status": "accepted"}


@app.post("/api/v1/runtime/heartbeat")
def runtime_heartbeat(payload: RuntimeHeartbeatRequest, db: Database = Depends(get_database)) -> dict[str, Any]:
    """Keep a runtime service marked online in control center."""
    service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE service_runtime_state
            SET local_url = ?, last_seen_at = ?, registration_status = 'approved', last_error = NULL
            WHERE service_id = ?
            """,
            (payload.local_url, utcnow(), service["id"]),
        )
    return {"status": "ok", "service_id": payload.service_id, "config_version": service.get("config_version", 1) or 1}


@app.post("/api/v1/runtime/config/pull", response_model=RuntimeConfigPullResponse)
def runtime_config_pull(
    payload: RuntimeConfigPullRequest,
    db: Database = Depends(get_database),
) -> RuntimeConfigPullResponse:
    """Pull the latest validated settings for a runtime service."""
    service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    current_version = service.get("config_version", 1) or 1
    return RuntimeConfigPullResponse(
        service_id=payload.service_id,
        config_version=current_version,
        changed=current_version > payload.current_version,
        settings=_sanitize_service_settings(service["settings"]),
    )


@app.post("/api/v1/runtime/config/propose")
def runtime_config_propose(
    payload: RuntimeConfigProposeRequest,
    db: Database = Depends(get_database),
) -> dict[str, Any]:
    """Accept a service-side settings proposal if it is newer than the stored one."""
    service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    current_updated_at = service.get("settings_updated_at") or ""
    if payload.proposed_at <= current_updated_at:
        return {"accepted": False, "reason": "stale_settings", "config_version": service.get("config_version", 1) or 1}

    merged_settings = dict(service["settings"])
    merged_settings.update(payload.settings)
    merged_settings = _normalize_service_settings(
        service["service_type"], merged_settings)
    next_version = (service.get("config_version", 1) or 1) + 1
    with db.transaction() as connection:
        connection.execute(
            "UPDATE services SET settings_json = ? WHERE id = ?",
            (json.dumps(merged_settings), service["id"]),
        )
        connection.execute(
            """
            UPDATE service_runtime_state
            SET config_version = ?, settings_updated_at = ?, registration_status = 'approved'
            WHERE service_id = ?
            """,
            (next_version, payload.proposed_at, service["id"]),
        )

    return {"accepted": True, "config_version": next_version, "settings": _sanitize_service_settings(merged_settings)}


@app.post("/api/v1/runtime/inspections", response_model=RuntimeInspectionResponse)
def runtime_create_inspection(
    payload: RuntimeInspectionRequest,
    db: Database = Depends(get_database),
) -> RuntimeInspectionResponse:
    """Create an inspection job from a checkpoint and wait for a worker result."""
    checkpoint = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    if checkpoint["service_type"] != "checkpoint":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only checkpoints can submit inspections")
    try:
        image_bytes = base64.b64decode(payload.image_base64, validate=True)
    except binascii.Error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="image_base64 is not valid base64")
    max_size = int(checkpoint["settings"].get(
        "max_image_size_bytes", 10_000_000))
    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="image_base64 is empty")
    if len(image_bytes) > max_size:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"Image is too large: {len(image_bytes)} bytes, limit is {max_size}")

    existing = db.fetchone(
        "SELECT result_json, status FROM inspection_jobs WHERE request_id = ?", (payload.request_id,))
    if existing is not None:
        if existing["result_json"]:
            result = json.loads(existing["result_json"])
            return RuntimeInspectionResponse(**result)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Inspection already in progress")

    try:
        route = _resolve_route(db, payload.service_id)
    except HTTPException as exc:
        _write_runtime_event(
            db,
            event_id=str(uuid4()),
            event_class="routing",
            event_type="routing.not_found",
            source_service_id=payload.service_id,
            source_service_type=payload.service_type,
            severity="error",
            payload={"detail": exc.detail},
            created_at=utcnow(),
            request_id=payload.request_id,
        )
        raise
    _write_runtime_event(
        db,
        event_id=str(uuid4()),
        event_class="routing",
        event_type="routing.resolved",
        source_service_id=payload.service_id,
        source_service_type=payload.service_type,
        severity="info",
        payload={"route_id": route["route_id"], "worker_service_id":
                 route["worker_service_id"], "targets": route["targets"]},
        created_at=utcnow(),
        request_id=payload.request_id,
    )
    required_ppe = _checkpoint_required_ppe(checkpoint)
    job_id = str(uuid4())
    leased_at = utcnow()
    created_at = leased_at
    with db.transaction() as connection:
        connection.execute(
            """
            INSERT INTO inspection_jobs (job_id, request_id, checkpoint_service_id, worker_service_id, image_base64, required_ppe_json, status, created_at, leased_at)
            VALUES (?, ?, ?, ?, ?, ?, 'leased', ?, ?)
            """,
            (job_id, payload.request_id, payload.service_id,
             route["worker_service_id"], payload.image_base64, json.dumps(required_ppe), created_at, leased_at),
        )
    job_payload = {
        "job_id": job_id,
        "request_id": payload.request_id,
        "checkpoint_service_id": payload.service_id,
        "image_base64": payload.image_base64,
        "required_ppe": required_ppe,
    }
    try:
        push_result = _push_worker_job(
            db, route["worker_service_id"], job_payload)
    except Exception as exc:
        with db.transaction() as connection:
            connection.execute(
                "UPDATE inspection_jobs SET status = 'queued', leased_at = NULL WHERE job_id = ?", (job_id,))
        _write_runtime_event(
            db,
            event_id=str(uuid4()),
            event_class="processing",
            event_type="processing.job.push_failed",
            source_service_id="control-center",
            source_service_type="control_center",
            severity="error",
            payload={"job_id": job_id, "worker_service_id": route["worker_service_id"], "error": str(
                exc), "retry_scheduled": True},
            created_at=utcnow(),
            request_id=payload.request_id,
            job_id=job_id,
        )
    else:
        _write_runtime_event(
            db,
            event_id=str(uuid4()),
            event_class="processing",
            event_type="processing.job.pushed",
            source_service_id="control-center",
            source_service_type="control_center",
            severity="info",
            payload={"job_id": job_id, "worker_service_id":
                     route["worker_service_id"], "push_result": push_result},
            created_at=utcnow(),
            request_id=payload.request_id,
            job_id=job_id,
        )

    deadline = time.time() + \
        float(checkpoint["settings"].get("inspection_timeout_sec", 10))
    while time.time() < deadline:
        row = db.fetchone(
            "SELECT status, result_json FROM inspection_jobs WHERE request_id = ?", (payload.request_id,))
        if row and row["status"] in ("completed", "failed") and row["result_json"]:
            return RuntimeInspectionResponse(**json.loads(row["result_json"]))
        time.sleep(0.25)

    with db.transaction() as connection:
        connection.execute(
            "UPDATE inspection_jobs SET status = 'timeout', completed_at = ? WHERE request_id = ? AND status IN ('queued', 'leased')",
            (utcnow(), payload.request_id),
        )
    return RuntimeInspectionResponse(
        request_id=payload.request_id,
        decision="error",
        reason_code="inspection_timeout",
        reason_text="Worker result was not received in time",
        required_ppe=required_ppe,
        missing_required=required_ppe,
        detections=[],
        annotated_image_base64=None,
        annotated_image_media_type=None,
        worker_service_id=None,
        created_at=created_at,
        processed_at=None,
        completed_at=utcnow(),
    )


@app.post("/api/v1/runtime/worker/jobs/next", response_model=RuntimeWorkerJobResponse)
def runtime_worker_next_job(
    payload: RuntimeWorkerNextJobRequest,
    db: Database = Depends(get_database),
) -> RuntimeWorkerJobResponse | Response:
    """Lease the next queued inspection job to a worker."""
    worker = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    if worker["service_type"] != "worker":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only workers can lease jobs")

    lease_timeout = int(_get_control_center_settings(
        db).get("worker_result_timeout_sec", 10))
    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE inspection_jobs
            SET status = 'queued', leased_at = NULL
            WHERE status = 'leased' AND leased_at < ?
            """,
            (_utc_cutoff(lease_timeout),),
        )
        row = connection.execute(
            """
            SELECT job_id, request_id, checkpoint_service_id, image_base64, required_ppe_json
            FROM inspection_jobs
            WHERE status = 'queued' AND worker_service_id = ?
            ORDER BY id ASC
            LIMIT 1
            """,
            (payload.service_id,),
        ).fetchone()
        if row is None:
            return Response(status_code=status.HTTP_204_NO_CONTENT)

        leased = connection.execute(
            """
            UPDATE inspection_jobs
            SET status = 'leased', worker_service_id = ?, leased_at = ?
            WHERE job_id = ? AND status = 'queued'
            """,
            (payload.service_id, utcnow(), row["job_id"]),
        )
        if leased.rowcount == 0:
            return Response(status_code=status.HTTP_204_NO_CONTENT)

    return RuntimeWorkerJobResponse(
        job_id=row["job_id"],
        request_id=row["request_id"],
        checkpoint_service_id=row["checkpoint_service_id"],
        image_base64=row["image_base64"],
        required_ppe=json.loads(row["required_ppe_json"]),
    )


@app.post("/api/v1/runtime/worker/jobs/result")
def runtime_worker_submit_result(
    payload: RuntimeWorkerResultRequest,
    db: Database = Depends(get_database),
) -> dict[str, Any]:
    """Store worker detections and convert them into a final checkpoint decision."""
    worker = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    if worker["service_type"] != "worker":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only workers can submit results")

    job = db.fetchone(
        """
        SELECT request_id, checkpoint_service_id, required_ppe_json, status, created_at
        FROM inspection_jobs
        WHERE job_id = ? AND worker_service_id = ?
        """,
        (payload.job_id, payload.service_id),
    )
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    if job["status"] == "timeout":
        return {"status": "late_result"}

    completed_at = utcnow()
    if payload.error:
        result = {
            "request_id": job["request_id"],
            "decision": "error",
            "reason_code": "worker_error",
            "reason_text": payload.error,
            "required_ppe": json.loads(job["required_ppe_json"]),
            "missing_required": json.loads(job["required_ppe_json"]),
            "detections": [],
            "annotated_image_base64": payload.annotated_image_base64,
            "annotated_image_media_type": payload.annotated_image_media_type,
            "worker_service_id": payload.service_id,
            "created_at": job["created_at"],
            "processed_at": payload.processed_at,
            "completed_at": completed_at,
        }
        next_status = "failed"
    else:
        detections = payload.detections
        required_ppe = json.loads(job["required_ppe_json"])
        decision, reason_code, reason_text = _evaluate_ppe(
            required_ppe, detections)
        missing_required = _missing_required_ppe(required_ppe, detections)
        result = {
            "request_id": job["request_id"],
            "decision": decision,
            "reason_code": reason_code,
            "reason_text": reason_text,
            "required_ppe": required_ppe,
            "missing_required": missing_required,
            "detections": detections,
            "annotated_image_base64": payload.annotated_image_base64,
            "annotated_image_media_type": payload.annotated_image_media_type,
            "worker_service_id": payload.service_id,
            "created_at": job["created_at"],
            "processed_at": payload.processed_at,
            "completed_at": completed_at,
        }
        next_status = "completed"

    route = _resolve_route(db, job["checkpoint_service_id"])

    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE inspection_jobs
            SET status = ?, result_json = ?, completed_at = ?
            WHERE job_id = ?
            """,
            (next_status, json.dumps(result), completed_at, payload.job_id),
        )
    _enqueue_delivery_tasks(
        db, route, result, job["checkpoint_service_id"], payload.service_id)
    _write_runtime_event(
        db,
        event_id=str(uuid4()),
        event_class="processing",
        event_type="processing.job.completed" if not payload.error else "processing.job.failed",
        source_service_id=payload.service_id,
        source_service_type=payload.service_type,
        severity="error" if payload.error else "info",
        payload={"job_id": payload.job_id,
                 "route_id": route["route_id"], "decision": result["decision"]},
        created_at=utcnow(),
        request_id=job["request_id"],
        job_id=payload.job_id,
    )
    return {"status": next_status}


@app.post("/api/v1/runtime/delivery/tasks/next", response_model=RuntimeDeliveryTaskResponse)
def runtime_delivery_next_task(
    payload: RuntimeDeliveryNextTaskRequest,
    db: Database = Depends(get_database),
) -> RuntimeDeliveryTaskResponse | Response:
    delivery_service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    if delivery_service["service_type"] not in {"storage", "delivery_service", "viewer"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only storage, delivery_service, or viewer services can lease delivery tasks")
    accepted_target_kinds = delivery_service["settings"].get(
        "accepted_target_kinds",
        ["database"] if delivery_service["service_type"] == "storage" else (["viewer"] if delivery_service["service_type"] == "viewer" else ["webhook", "email"]),
    )
    accepted_target_kinds = [kind for kind in accepted_target_kinds if kind in {
        "database", "webhook", "email", "viewer"}]
    if not accepted_target_kinds:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    placeholders = ", ".join("?" for _ in accepted_target_kinds)

    row = db.fetchone(
        f"""
        SELECT task_id, route_id, request_id, checkpoint_service_id, worker_service_id, target_service_id, target_kind, payload_json
        FROM delivery_tasks
        WHERE status = 'queued' AND target_service_id = ? AND target_kind IN ({placeholders})
        ORDER BY id ASC
        LIMIT 1
        """,
        (payload.service_id, *accepted_target_kinds),
    )
    if row is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE delivery_tasks
            SET status = 'leased', leased_at = ?, attempt_count = attempt_count + 1
            WHERE task_id = ? AND status = 'queued'
            """,
            (utcnow(), row["task_id"]),
        )
    return RuntimeDeliveryTaskResponse(
        task_id=row["task_id"],
        route_id=row["route_id"],
        request_id=row["request_id"],
        checkpoint_service_id=row["checkpoint_service_id"],
        worker_service_id=row["worker_service_id"],
        target_service_id=row["target_service_id"],
        target_kind=row["target_kind"],
        payload=json.loads(row["payload_json"]),
    )


@app.post("/api/v1/runtime/delivery/tasks/result")
def runtime_delivery_submit_result(
    payload: RuntimeDeliveryResultRequest,
    db: Database = Depends(get_database),
) -> dict[str, str]:
    delivery_service = _authenticate_runtime_service(
        db, payload.service_id, payload.service_type, payload.service_secret)
    if delivery_service["service_type"] not in {"storage", "delivery_service", "viewer"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only storage, delivery_service, or viewer services can submit delivery results")

    task = db.fetchone(
        """
        SELECT task_id, request_id, target_service_id, status
        FROM delivery_tasks
        WHERE task_id = ? AND target_service_id = ?
        """,
        (payload.task_id, payload.service_id),
    )
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Delivery task not found")

    retry_limit = int(_get_control_center_settings(
        db).get("delivery_retry_limit", 5))
    if payload.error and task["status"] != "failed":
        current = db.fetchone(
            "SELECT attempt_count, is_required FROM delivery_tasks WHERE task_id = ?", (payload.task_id,))
        attempt_count = int(current["attempt_count"]) if current else 0
        should_retry = attempt_count < retry_limit
        next_status = "queued" if should_retry else "failed"
    else:
        should_retry = False
        next_status = "completed"

    with db.transaction() as connection:
        connection.execute(
            """
            UPDATE delivery_tasks
            SET status = ?, completed_at = ?, error_text = ?
            WHERE task_id = ?
            """,
            (next_status, payload.delivered_at, payload.error, payload.task_id),
        )
    _write_runtime_event(
        db,
        event_id=str(uuid4()),
        event_class="delivery",
        event_type="delivery.task.retry_scheduled" if should_retry else (
            "delivery.task.failed" if payload.error else "delivery.task.completed"),
        source_service_id=payload.service_id,
        source_service_type=payload.service_type,
        severity="error" if payload.error and not should_retry else "info",
        payload={"task_id": payload.task_id, "details": payload.details,
                 "error": payload.error, "retry_scheduled": should_retry},
        created_at=payload.delivered_at,
        request_id=task["request_id"],
    )
    return {"status": next_status}


@app.get("/api/v1/audit", response_model=list[AuditEventResponse])
def list_audit_events(
    user: dict[str, Any] = Depends(require_roles("root", "admin", "auditor")),
    db: Database = Depends(get_database),
    action: str | None = Query(default=None),
    target_type: str | None = Query(default=None),
    target_id: str | None = Query(default=None),
) -> list[AuditEventResponse]:
    """
    Return recent audit events.

    Root sees the full stream. Admins and auditors only see service-scoped
    events for services that are assigned to them.
    """
    filters = []
    params: list[Any] = []
    if action:
        filters.append("action = ?")
        params.append(action)
    if target_type:
        filters.append("target_type = ?")
        params.append(target_type)
    if target_id:
        filters.append("target_id = ?")
        params.append(target_id)
    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    if user["role"] == "root":
        rows = db.fetchall(
            f"""
            SELECT action, target_type, target_id, details_json, created_at
            FROM audit_log
            {where_clause}
            ORDER BY id DESC
            LIMIT 200
            """,
            tuple(params),
        )
    else:
        scoped_filters = filters + \
            ["al.target_type = 'service'", "u.username = ?"]
        scoped_params = params + [user["username"]]
        rows = db.fetchall(
            f"""
            SELECT al.action, al.target_type, al.target_id, al.details_json, al.created_at
            FROM audit_log al
            JOIN services s ON s.service_id = al.target_id
            JOIN user_service_access usa ON usa.service_id = s.id
            JOIN users u ON u.id = usa.user_id
            WHERE {' AND '.join(scoped_filters)}
            ORDER BY al.id DESC
            LIMIT 200
            """,
            tuple(scoped_params),
        )
    return [
        AuditEventResponse(
            action=row["action"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            details=json.loads(row["details_json"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]


@app.get("/api/v1/runtime-events", response_model=list[RuntimeEventResponse])
def list_runtime_events(
    _: dict[str, Any] = Depends(require_roles("root", "admin", "auditor")),
    db: Database = Depends(get_database),
    request_id: str | None = Query(default=None),
    event_class: str | None = Query(default=None),
    source_service_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
) -> list[RuntimeEventResponse]:
    filters = []
    params: list[Any] = []
    if request_id:
        filters.append("request_id = ?")
        params.append(request_id)
    if event_class:
        filters.append("event_class = ?")
        params.append(event_class)
    if source_service_id:
        filters.append("source_service_id = ?")
        params.append(source_service_id)
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    rows = db.fetchall(
        f"""
        SELECT event_id, event_class, event_type, source_service_id, source_service_type, request_id, job_id, severity, payload_json, created_at
        FROM runtime_event_log
        {where_clause}
        ORDER BY id DESC
        LIMIT 500
        """,
        tuple(params),
    )
    return [RuntimeEventResponse(**_serialize_runtime_event(row)) for row in rows]


@app.get("/api/v1/requests/{request_id}/timeline", response_model=list[RuntimeEventResponse])
def request_timeline(
    request_id: str,
    _: dict[str, Any] = Depends(require_roles("root", "admin", "auditor")),
    db: Database = Depends(get_database),
) -> list[RuntimeEventResponse]:
    rows = db.fetchall(
        """
        SELECT event_id, event_class, event_type, source_service_id, source_service_type, request_id, job_id, severity, payload_json, created_at
        FROM runtime_event_log
        WHERE request_id = ?
        ORDER BY created_at ASC, id ASC
        LIMIT 500
        """,
        (request_id,),
    )
    return [RuntimeEventResponse(**_serialize_runtime_event(row)) for row in rows]
