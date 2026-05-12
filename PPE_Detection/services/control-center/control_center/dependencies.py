import json
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from .db import Database


def get_database(request: Request) -> Database:
    """Expose the shared database handle through FastAPI dependency injection."""
    return request.app.state.db


def _load_user_by_token(db: Database, token: str | None) -> dict[str, Any]:
    """Resolve an active operator session from a bearer token."""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    row = db.fetchone(
        """
        SELECT u.id, u.username, u.role, u.is_active, t.token
        FROM auth_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token = ? AND t.revoked_at IS NULL
        """,
        (token,),
    )
    if row is None or not row["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    return dict(row)


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Database = Depends(get_database),
) -> dict[str, Any]:
    """Parse the Authorization header and return the authenticated user."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    return _load_user_by_token(db, token)


def require_roles(*roles: str):
    """Build a dependency that restricts an endpoint to selected global roles."""
    def dependency(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency


def get_service_for_user(db: Database, user: dict[str, Any], service_id: str) -> dict[str, Any]:
    """
    Load a service and verify visibility within the caller's service scope.

    Root bypasses scoped checks. Other roles must have an explicit grant in
    user_service_access.
    """
    service = db.fetchone(
        "SELECT id, service_id, service_type, display_name, status AS admin_state, settings_json, created_at FROM services WHERE service_id = ?",
        (service_id,),
    )
    if service is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found")

    service_dict = dict(service)
    service_dict["settings"] = json.loads(service_dict.pop("settings_json"))

    if user["role"] == "root":
        return service_dict

    access = db.fetchone(
        """
        SELECT access_level
        FROM user_service_access usa
        JOIN users u ON u.id = usa.user_id
        JOIN services s ON s.id = usa.service_id
        WHERE u.username = ? AND s.service_id = ?
        """,
        (user["username"], service_id),
    )
    if access is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to service")

    service_dict["access_level"] = access["access_level"]
    return service_dict


def require_service_access(service_id: str, mode: str, db: Database, user: dict[str, Any]) -> dict[str, Any]:
    """Enforce read or manage access for a concrete registered service."""
    service = get_service_for_user(db, user, service_id)
    if user["role"] == "root":
        return service
    if mode == "read":
        return service
    if service.get("access_level") != "manage":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Manage access required")
    return service
