import copy
from numbers import Number
from typing import Any

from fastapi import HTTPException, status


DEFAULT_LOGGING_POLICY = {
    "enabled": True,
    "store_local_events": True,
    "forward_to_control_center": True,
    "include_payloads": True,
    "classes": {
        "aaa": {"enabled": True, "mode": "all"},
        "bootstrap": {"enabled": True, "mode": "all"},
        "registration": {"enabled": True, "mode": "all"},
        "heartbeat": {"enabled": True, "mode": "all"},
        "routing": {"enabled": True, "mode": "all"},
        "processing": {"enabled": True, "mode": "all"},
        "inspection": {"enabled": True, "mode": "all"},
        "delivery": {"enabled": True, "mode": "all"},
        "config": {"enabled": True, "mode": "all"},
        "security": {"enabled": True, "mode": "errors_only"},
        "system": {"enabled": True, "mode": "all"},
    },
}


DEFAULT_SERVICE_SETTINGS: dict[str, dict[str, Any]] = {
    "control_center": {
        "inspection_timeout_sec": 10,
        "worker_result_timeout_sec": 10,
        "allow_default_route": False,
        "delivery_retry_limit": 5,
        "delivery_retry_delay_sec": 5,
        "runtime_offline_threshold_sec": 90,
        "service_certificate_ttl_hours": 24,
        "default_worker_service_id": "",
        "default_storage_service_ids": [],
        "default_delivery_service_ids": [],
        "default_viewer_service_ids": [],
        "logging": copy.deepcopy(DEFAULT_LOGGING_POLICY),
    },
    "checkpoint": {
        "heartbeat_interval_sec": 10,
        "inspection_timeout_sec": 10,
        "request_retry_count": 0,
        "request_retry_delay_ms": 250,
        "max_image_size_bytes": 10_000_000,
        "allowed_mime_types": ["image/jpeg", "image/png", "image/webp"],
        "image_source_mode": "upload",
        "required_ppe": ["hardhat", "safety_vest"],
        "logging": copy.deepcopy(DEFAULT_LOGGING_POLICY),
    },
    "worker": {
        "heartbeat_interval_sec": 10,
        "max_local_queue_size": 10,
        "processing": {
            "mode": "ultralytics",
            "model_name": "hansung-yolov8-ppe",
            "model_source": "huggingface",
            "confidence_threshold": 0.5,
            "image_size": 640,
            "model_repo": "Hansung-Cho/yolov8-ppe-detection",
            "model_file": "best.pt",
            "class_map": {
                "Hardhat": "hardhat",
                "No-Hardhat": "no_hardhat",
                "Mask": "mask",
                "No-Mask": "no_mask",
                "Safety Vest": "safety_vest",
                "NO-Safety Vest": "no_safety_vest",
                "No-Safety Vest": "no_safety_vest",
                "Person": "person",
            },
            "violation_classes": ["no_hardhat", "no_mask", "no_safety_vest"],
            "available_models": [
                {
                    "name": "hansung-yolov8-ppe",
                    "source": "huggingface",
                    "repo": "Hansung-Cho/yolov8-ppe-detection",
                    "file": "best.pt",
                    "description": "PPE detector trained for hardhat/mask/safety vest classes",
                },
                {
                    "name": "hexmon-vyra-yolo-ppe",
                    "source": "huggingface",
                    "repo": "Hexmon/vyra-yolo-ppe-detection",
                    "file": "best.pt",
                    "description": "YOLOv8m PPE detector with hardhat, vest, mask, gloves and goggles compliance classes",
                },
            ],
        },
        "logging": copy.deepcopy(DEFAULT_LOGGING_POLICY),
    },
    "storage": {
        "heartbeat_interval_sec": 10,
        "write_timeout_sec": 10,
        "max_local_queue_size": 20,
        "backend": {
            "type": "sqlite",
            "sqlite_path": "/data/storage_records.db",
            "dsn": "",
            "table_name": "inspection_results",
            "create_table": True,
            "connect_timeout_sec": 10,
        },
        "accepted_target_kinds": ["database"],
        "logging": copy.deepcopy(DEFAULT_LOGGING_POLICY),
    },
    "delivery_service": {
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
        "logging": copy.deepcopy(DEFAULT_LOGGING_POLICY),
    },
    "viewer": {
        "heartbeat_interval_sec": 10,
        "max_local_queue_size": 200,
        "accepted_target_kinds": ["viewer"],
        "logging": copy.deepcopy(DEFAULT_LOGGING_POLICY),
    },
}


def merged_default_settings(service_type: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    defaults = copy.deepcopy(DEFAULT_SERVICE_SETTINGS[service_type])
    if overrides:
        defaults = deep_merge(defaults, overrides)
    return defaults


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def validate_logging_policy(logging_policy: Any) -> dict[str, Any]:
    if not isinstance(logging_policy, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="logging must be an object")
    merged = deep_merge(copy.deepcopy(DEFAULT_LOGGING_POLICY), logging_policy)
    classes = merged.get("classes")
    if not isinstance(classes, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="logging.classes must be an object")
    for event_class, config in classes.items():
        if not isinstance(config, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"logging.classes.{event_class} must be an object")
        if config.get("mode") not in {"all", "errors_only", "state_changes_only", "sampled"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"logging.classes.{event_class}.mode must be one of all/errors_only/state_changes_only/sampled",
            )
        sample_rate = config.get("sample_rate", 1.0)
        if not isinstance(sample_rate, Number) or sample_rate < 0 or sample_rate > 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"logging.classes.{event_class}.sample_rate must be between 0 and 1",
            )
    for flag_name in ("enabled", "store_local_events", "forward_to_control_center", "include_payloads"):
        if not isinstance(merged.get(flag_name), bool):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"logging.{flag_name} must be boolean")
    return merged


def validate_service_settings(service_type: str, settings: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(settings, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="settings must be an object")

    merged = merged_default_settings(service_type, settings)
    merged["logging"] = validate_logging_policy(merged.get("logging", {}))

    int_fields = {
        "checkpoint": ["heartbeat_interval_sec", "inspection_timeout_sec", "request_retry_count", "request_retry_delay_ms", "max_image_size_bytes"],
        "worker": ["heartbeat_interval_sec", "max_local_queue_size"],
        "storage": ["heartbeat_interval_sec", "write_timeout_sec", "max_local_queue_size"],
        "delivery_service": ["heartbeat_interval_sec", "send_timeout_sec", "max_local_queue_size"],
        "viewer": ["heartbeat_interval_sec", "max_local_queue_size"],
        "control_center": ["inspection_timeout_sec", "worker_result_timeout_sec", "delivery_retry_limit", "delivery_retry_delay_sec", "runtime_offline_threshold_sec", "service_certificate_ttl_hours"],
    }
    for field_name in int_fields.get(service_type, []):
        value = merged.get(field_name)
        if not isinstance(value, int) or value < 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be a non-negative integer")

    if service_type == "checkpoint":
        required_ppe = merged.get("required_ppe")
        if not isinstance(required_ppe, list) or any(not isinstance(item, str) for item in required_ppe):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="required_ppe must be a list of strings")
        mime_types = merged.get("allowed_mime_types")
        if not isinstance(mime_types, list) or any(not isinstance(item, str) for item in mime_types):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="allowed_mime_types must be a list of strings")
        if merged.get("image_source_mode") not in {"upload", "camera", "both"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="image_source_mode must be one of upload/camera/both")

    if service_type == "worker":
        processing = merged.get("processing")
        if not isinstance(processing, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="processing must be an object")
        if processing.get("mode") != "ultralytics":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="processing.mode must be ultralytics")
        if not isinstance(processing.get("confidence_threshold"), (int, float)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="processing.confidence_threshold must be numeric")
        if not isinstance(processing.get("image_size"), int) or processing["image_size"] <= 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="processing.image_size must be a positive integer")
        if processing.get("model_source") != "huggingface":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="processing.model_source must be huggingface")
        for field_name in ("model_name", "model_repo", "model_file"):
            if not isinstance(processing.get(field_name), str):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"processing.{field_name} must be a string")
        if not isinstance(processing.get("class_map"), dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="processing.class_map must be an object")
        if not isinstance(processing.get("violation_classes"), list) or any(not isinstance(item, str) for item in processing["violation_classes"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="processing.violation_classes must be a list of strings")

    if service_type == "storage":
        backend = merged.get("backend")
        if not isinstance(backend, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="backend must be an object")
        if backend.get("type") not in {"sqlite", "postgres", "mysql"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="backend.type must be one of sqlite/postgres/mysql")
        for field_name in ("sqlite_path", "dsn", "table_name"):
            if not isinstance(backend.get(field_name), str):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"backend.{field_name} must be a string")
        if not isinstance(backend.get("create_table"), bool):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="backend.create_table must be boolean")
        if not isinstance(backend.get("connect_timeout_sec"), int) or backend["connect_timeout_sec"] <= 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="backend.connect_timeout_sec must be a positive integer")
        accepted = merged.get("accepted_target_kinds")
        if not isinstance(accepted, list) or any(item != "database" for item in accepted):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="accepted_target_kinds for storage must contain only database")

    if service_type == "delivery_service":
        accepted = merged.get("accepted_target_kinds")
        if not isinstance(accepted, list) or any(item not in {"webhook", "email"} for item in accepted):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="accepted_target_kinds for delivery_service must contain webhook/email")
        channels = merged.get("channels")
        if not isinstance(channels, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="channels must be an object")
        webhook = channels.get("webhook", {})
        email = channels.get("email", {})
        if not isinstance(webhook, dict) or not isinstance(email, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="channels.webhook and channels.email must be objects")
        if webhook.get("method") not in {"POST", "PUT", "PATCH"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="channels.webhook.method must be POST/PUT/PATCH")
        if not isinstance(webhook.get("headers"), dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="channels.webhook.headers must be an object")
        if email.get("mode") not in {"log", "smtp"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="channels.email.mode must be log/smtp")
        if not isinstance(email.get("smtp_port"), int) or email["smtp_port"] <= 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="channels.email.smtp_port must be a positive integer")
        if not isinstance(email.get("to"), list) or any(not isinstance(item, str) for item in email["to"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="channels.email.to must be a list of strings")
        rules = merged.get("rules")
        if not isinstance(rules, list):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="rules must be a list")
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"rules[{index}] must be an object")
            if rule.get("channel") not in {"webhook", "email"}:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"rules[{index}].channel must be webhook/email")

    if service_type == "viewer":
        accepted = merged.get("accepted_target_kinds")
        if not isinstance(accepted, list) or any(item != "viewer" for item in accepted):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="accepted_target_kinds for viewer must contain only viewer")

    if service_type == "control_center":
        if not isinstance(merged.get("allow_default_route"), bool):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="allow_default_route must be boolean")
        if not isinstance(merged.get("default_worker_service_id"), str):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="default_worker_service_id must be a string")
        for field_name in ("default_storage_service_ids", "default_delivery_service_ids", "default_viewer_service_ids"):
            if not isinstance(merged.get(field_name), list) or any(not isinstance(item, str) for item in merged[field_name]):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be a list of strings")

    return merged
