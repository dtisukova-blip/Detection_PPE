from __future__ import annotations

import base64
import binascii
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any


@lru_cache(maxsize=8)
def _load_ultralytics_model(model_repo: str, model_file: str):
    try:
        from huggingface_hub import hf_hub_download
        from ultralytics import YOLO
    except ImportError as exc:
        raise RuntimeError(
            "Ultralytics processing requires 'ultralytics' and 'huggingface_hub' packages in the worker image"
        ) from exc

    model_path = hf_hub_download(repo_id=model_repo, filename=model_file)
    return YOLO(model_path)


def check_model_health(settings: dict[str, Any]) -> dict[str, Any]:
    processing = settings.get("processing", {})
    model = _load_ultralytics_model(
        processing.get("model_repo", ""),
        processing.get("model_file", "best.pt"),
    )
    names = getattr(model, "names", {})
    return {
        "ok": True,
        "mode": processing.get("mode", "ultralytics"),
        "model_name": processing.get("model_name"),
        "model_source": "huggingface",
        "model_file": processing.get("model_file"),
        "classes": names,
    }


def _image_suffix(image_bytes: bytes) -> str:
    if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if image_bytes.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if image_bytes.startswith(b"RIFF") and image_bytes[8:12] == b"WEBP":
        return ".webp"
    return ".jpg"


def _image_media_type(image_bytes: bytes) -> str:
    if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if image_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if image_bytes.startswith(b"RIFF") and image_bytes[8:12] == b"WEBP":
        return "image/webp"
    return "image/jpeg"


def _decode_image_to_temp_file(image_base64: str) -> Path:
    try:
        image_bytes = base64.b64decode(image_base64, validate=True)
    except binascii.Error as exc:
        raise ValueError("image_base64 is not valid base64") from exc
    if not image_bytes:
        raise ValueError("image_base64 is empty")
    temp_file = tempfile.NamedTemporaryFile(prefix="ppe-worker-", suffix=_image_suffix(image_bytes), delete=False)
    try:
        temp_file.write(image_bytes)
        return Path(temp_file.name)
    finally:
        temp_file.close()


def _normalize_class(label: str, class_map: dict[str, Any]) -> str:
    mapped = class_map.get(label, label)
    return str(mapped).strip().lower().replace(" ", "_").replace("-", "_")


def _encode_annotated_image(plot_result: Any, image_suffix: str) -> str | None:
    try:
        import cv2
    except ImportError:
        return None
    encoded, buffer = cv2.imencode(image_suffix, plot_result)
    if not encoded:
        return None
    return base64.b64encode(buffer.tobytes()).decode("ascii")


def _ppe_family(class_name: str) -> str:
    return class_name.removeprefix("no_")


def _detection_state(class_name: str, required_ppe: set[str]) -> tuple[str, str]:
    if class_name in required_ppe:
        return "present", "green"
    if class_name.startswith("no_") and _ppe_family(class_name) in required_ppe:
        return "violation", "red"
    return "unrelated", "gray"


def _draw_annotated_image(plot_source: Any, detections: list[dict[str, Any]], missing_required: list[str], image_suffix: str) -> str | None:
    try:
        import cv2
    except ImportError:
        return None

    image = getattr(plot_source, "orig_img", None)
    if image is None:
        return None
    image = image.copy()
    height, width = image.shape[:2]
    thickness = max(2, round(min(width, height) / 320))
    font_scale = max(0.55, min(width, height) / 900)
    colors = {
        "green": (94, 197, 34),
        "red": (68, 68, 239),
        "gray": (184, 163, 148),
    }
    for item in detections:
        bbox = item.get("bbox") or []
        if len(bbox) != 4:
            continue
        x1, y1, x2, y2 = [int(round(value)) for value in bbox]
        x1, x2 = max(0, min(x1, width - 1)), max(0, min(x2, width - 1))
        y1, y2 = max(0, min(y1, height - 1)), max(0, min(y2, height - 1))
        color = colors.get(str(item.get("box_color") or "gray"), colors["gray"])
        cv2.rectangle(image, (x1, y1), (x2, y2), color, thickness)
        label = f"{item.get('class', 'object')} {float(item.get('confidence', 0)):.2f}"
        (label_w, label_h), baseline = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, font_scale, thickness)
        label_y = max(label_h + baseline + 4, y1)
        cv2.rectangle(image, (x1, label_y - label_h - baseline - 6), (min(width - 1, x1 + label_w + 8), label_y + 2), color, -1)
        cv2.putText(image, label, (x1 + 4, label_y - baseline - 2), cv2.FONT_HERSHEY_SIMPLEX, font_scale, (255, 255, 255), max(1, thickness - 1), cv2.LINE_AA)

    if missing_required:
        text = f"Missing required PPE: {', '.join(missing_required)}"
        banner_h = max(34, int(46 * font_scale))
        cv2.rectangle(image, (0, 0), (width, banner_h), colors["red"], -1)
        cv2.putText(image, text, (12, max(24, banner_h - 12)), cv2.FONT_HERSHEY_SIMPLEX, font_scale, (255, 255, 255), max(1, thickness - 1), cv2.LINE_AA)

    return _encode_annotated_image(image, image_suffix)


def run_ultralytics_detection(image_base64: str, processing: dict[str, Any], required_ppe: list[str] | None = None) -> dict[str, Any]:
    image_path = _decode_image_to_temp_file(image_base64)
    image_bytes = base64.b64decode(image_base64, validate=True)
    image_suffix = _image_suffix(image_bytes)
    required_set = {str(item) for item in (required_ppe or [])}
    try:
        model = _load_ultralytics_model(
            processing.get("model_repo", ""),
            processing["model_file"],
        )
        results = model(
            str(image_path),
            conf=float(processing.get("confidence_threshold", 0.5)),
            imgsz=int(processing.get("image_size", 640)),
            verbose=False,
        )
        result = results[0]
        detections: list[dict[str, Any]] = []
        class_map = processing.get("class_map", {})
        for box in result.boxes:
            cls_id = int(box.cls[0])
            source_class = str(model.names[cls_id])
            bbox = [float(value) for value in box.xyxy[0].tolist()]
            normalized_class = _normalize_class(source_class, class_map)
            ppe_state, box_color = _detection_state(normalized_class, required_set)
            detections.append(
                {
                    "class": normalized_class,
                    "source_class": source_class,
                    "confidence": float(box.conf[0]),
                    "bbox": bbox,
                    "model_name": processing.get("model_name", "ultralytics"),
                    "ppe_state": ppe_state,
                    "box_color": box_color,
                }
            )
        detected_required = {item["class"] for item in detections if item["class"] in required_set}
        missing_required = [item for item in (required_ppe or []) if item not in detected_required]
        annotated_image_base64 = _draw_annotated_image(result, detections, missing_required, image_suffix)
        return {
            "detections": detections,
            "missing_required": missing_required,
            "annotated_image_base64": annotated_image_base64,
            "annotated_image_media_type": _image_media_type(image_bytes) if annotated_image_base64 else None,
        }
    finally:
        image_path.unlink(missing_ok=True)


def process_inspection_job(job: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    processing = settings.get("processing", {})
    mode = processing.get("mode", "ultralytics")
    if mode == "ultralytics":
        return run_ultralytics_detection(job["image_base64"], processing, job.get("required_ppe", []))
    raise ValueError(f"Unsupported processing.mode: {mode}")
