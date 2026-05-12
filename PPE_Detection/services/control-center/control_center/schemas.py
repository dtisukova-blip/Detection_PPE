from typing import Any, Literal

from pydantic import BaseModel, Field


# Global RBAC roles for human operators.
RoleName = Literal["root", "admin", "auditor"]
# Types of services that can be registered in the ecosystem.
ServiceType = Literal["checkpoint", "worker", "storage", "delivery_service", "viewer", "control_center"]
# Types of services that operators are allowed to register manually.
CreatableServiceType = Literal["checkpoint", "worker", "storage", "delivery_service", "viewer"]
# Administrative switch for whether runtime interaction with the service is allowed.
AdminState = Literal["active", "disabled"]
# Downstream delivery point kinds.
TargetKind = Literal["database", "webhook", "email", "viewer"]
# Scope level for service-specific permissions.
AccessLevel = Literal["read", "manage"]


class LoginRequest(BaseModel):
    """Credentials used to start an operator session."""
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    """Session token together with a compact user profile."""
    access_token: str
    token_type: str = "bearer"
    user: dict


class CreateUserAccess(BaseModel):
    """Initial scoped permission that can be granted during user creation."""
    service_id: str
    access_level: AccessLevel | None = None


class CreateUserRequest(BaseModel):
    """Payload for creating a new operator account."""
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=256)
    role: RoleName
    access: list[CreateUserAccess] = Field(default_factory=list)


class UpdateUserRequest(BaseModel):
    """Partial update for an operator account."""
    password: str | None = Field(default=None, min_length=8, max_length=256)
    role: RoleName | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    """Public representation of a user account."""
    username: str
    role: RoleName
    is_active: bool
    created_at: str
    access: list[dict]


class ServiceCreateRequest(BaseModel):
    """Payload used by root to register a new manageable service."""
    service_id: str = Field(min_length=1, max_length=128)
    service_type: CreatableServiceType
    display_name: str = Field(min_length=1, max_length=256)
    settings: dict = Field(default_factory=dict)


class ServiceUpdateRequest(BaseModel):
    """Partial service update for display name, admin mode, or settings."""
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    admin_state: AdminState | None = None
    settings: dict | None = None


class ServiceResponse(BaseModel):
    """Public representation of a registered service and its runtime state."""
    service_id: str
    service_type: ServiceType
    display_name: str
    admin_state: AdminState
    settings: dict
    created_at: str
    registration_status: Literal["pending", "approved", "denied"] | None = None
    last_seen_at: str | None = None
    local_url: str | None = None
    config_version: int | None = None
    settings_updated_at: str | None = None
    last_error: str | None = None
    certificate_status: Literal["active", "revoked", "replaced"] | None = None
    certificate_serial_hex: str | None = None
    certificate_expires_at: str | None = None
    certificate_revoked_at: str | None = None


class ServiceProvisionResponse(ServiceResponse):
    """Service representation that also contains bootstrap credentials."""
    bootstrap_secret: str


class GrantAccessRequest(BaseModel):
    """Grant or update a user's scoped permission for one service."""
    username: str = Field(min_length=1, max_length=128)
    service_id: str = Field(min_length=1, max_length=128)
    access_level: AccessLevel | None = None


class RevokeAccessRequest(BaseModel):
    """Remove a scoped permission from a user."""
    username: str = Field(min_length=1, max_length=128)
    service_id: str = Field(min_length=1, max_length=128)


class AuditEventResponse(BaseModel):
    """Compact audit event returned by the audit API."""
    action: str
    target_type: str
    target_id: str | None
    details: dict
    created_at: str


class RouteTargetCreateRequest(BaseModel):
    target_service_id: str = Field(min_length=1, max_length=128)
    target_kind: TargetKind
    is_required: bool = False
    order_index: int = 0
    filter: dict[str, Any] = Field(default_factory=dict)


class RouteBindingCreateRequest(BaseModel):
    route_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    checkpoint_service_id: str | None = Field(default=None, min_length=1, max_length=128)
    worker_service_id: str = Field(min_length=1, max_length=128)
    is_default: bool = False
    priority: int = 100
    is_active: bool = True
    targets: list[RouteTargetCreateRequest] = Field(default_factory=list)


class RouteBindingUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=256)
    checkpoint_service_id: str | None = Field(default=None, min_length=1, max_length=128)
    worker_service_id: str | None = Field(default=None, min_length=1, max_length=128)
    is_default: bool | None = None
    priority: int | None = None
    is_active: bool | None = None
    targets: list[RouteTargetCreateRequest] | None = None


class RouteBindingResponse(BaseModel):
    route_id: str
    name: str
    checkpoint_service_id: str | None
    worker_service_id: str
    is_default: bool
    priority: int
    is_active: bool
    targets: list[dict[str, Any]]
    created_at: str
    updated_at: str


class RuntimeEventRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=128)
    service_id: str = Field(min_length=1, max_length=128)
    service_type: ServiceType
    service_secret: str = Field(min_length=1, max_length=256)
    event_class: str = Field(min_length=1, max_length=64)
    event_type: str = Field(min_length=1, max_length=128)
    severity: Literal["debug", "info", "warn", "error"] = "info"
    request_id: str | None = None
    job_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class RuntimeEventResponse(BaseModel):
    event_id: str
    event_class: str
    event_type: str
    source_service_id: str
    source_service_type: str
    request_id: str | None = None
    job_id: str | None = None
    severity: str
    payload: dict[str, Any]
    created_at: str


class ServiceRuntimeAuth(BaseModel):
    """Credentials used by runtime services when talking to control center."""
    service_id: str = Field(min_length=1, max_length=128)
    service_type: ServiceType
    service_secret: str = Field(min_length=1, max_length=256)


class RuntimeRegisterRequest(ServiceRuntimeAuth):
    """Registration request sent by worker/checkpoint/storage/delivery services."""
    local_url: str | None = None
    status_snapshot: dict[str, Any] = Field(default_factory=dict)


class RuntimeRegisterResponse(BaseModel):
    """Registration decision returned to a runtime service."""
    approved: bool
    service_id: str
    heartbeat_interval_sec: int
    config_version: int
    settings: dict[str, Any]
    reason: str | None = None


class RuntimeHeartbeatRequest(ServiceRuntimeAuth):
    """Keep-alive message from a runtime service."""
    local_url: str | None = None
    status_snapshot: dict[str, Any] = Field(default_factory=dict)


class RuntimeConfigPullRequest(ServiceRuntimeAuth):
    """Request current service settings from control center."""
    current_version: int = 0


class RuntimeConfigPullResponse(BaseModel):
    """Current effective settings for a runtime service."""
    service_id: str
    config_version: int
    changed: bool
    settings: dict[str, Any]


class RuntimeConfigProposeRequest(ServiceRuntimeAuth):
    """Propose a new settings blob from the service side."""
    proposed_at: str
    settings: dict[str, Any] = Field(default_factory=dict)


class RuntimeInspectionRequest(ServiceRuntimeAuth):
    """Checkpoint inspection request sent to control center."""
    request_id: str = Field(min_length=1, max_length=128)
    image_base64: str = Field(min_length=1)


class RuntimeInspectionResponse(BaseModel):
    """Final decision returned to a checkpoint after worker processing."""
    request_id: str
    decision: Literal["permit-access", "deny-access", "error"]
    reason_code: str
    reason_text: str
    required_ppe: list[str] = Field(default_factory=list)
    missing_required: list[str] = Field(default_factory=list)
    detections: list[dict[str, Any]] = Field(default_factory=list)
    annotated_image_base64: str | None = None
    annotated_image_media_type: str | None = None
    worker_service_id: str | None = None
    created_at: str | None = None
    processed_at: str | None = None
    completed_at: str | None = None


class RuntimeWorkerNextJobRequest(ServiceRuntimeAuth):
    """Poll the next pending inspection job for a worker."""
    queue_capacity: int = 1


class RuntimeWorkerJobResponse(BaseModel):
    """Leased job payload returned to a worker."""
    job_id: str
    request_id: str
    checkpoint_service_id: str
    image_base64: str
    required_ppe: list[str]


class RuntimeWorkerResultRequest(ServiceRuntimeAuth):
    """Worker result for a leased inspection job."""
    job_id: str
    detections: list[dict[str, Any]] = Field(default_factory=list)
    missing_required: list[str] = Field(default_factory=list)
    annotated_image_base64: str | None = None
    annotated_image_media_type: str | None = None
    processed_at: str
    error: str | None = None


class RuntimeDeliveryNextTaskRequest(ServiceRuntimeAuth):
    queue_capacity: int = 1


class RuntimeDeliveryTaskResponse(BaseModel):
    task_id: str
    route_id: str
    request_id: str
    checkpoint_service_id: str
    worker_service_id: str | None = None
    target_service_id: str
    target_kind: TargetKind
    payload: dict[str, Any]


class RuntimeDeliveryResultRequest(ServiceRuntimeAuth):
    task_id: str
    delivered_at: str
    details: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class RuntimePkiEnrollRequest(ServiceRuntimeAuth):
    csr_pem: str = Field(min_length=1)


class RuntimePkiEnrollResponse(BaseModel):
    service_id: str
    cert_pem: str
    root_cert_pem: str
    serial_hex: str
    expires_at: str


class RuntimePkiRevokeResponse(BaseModel):
    service_id: str
    status: str
    revoked_serials: list[str]
