"""Security decision and admin security-center routes."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from cyberguard_api.gateway import get_settings, require_api_key
from cyberguard_api.services import security_decision_engine as engine


class LoginSecurityRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    user_id: str = Field(..., min_length=2, max_length=64)
    ip_address: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    device_type: str | None = None
    browser: str | None = None
    os: str | None = None
    login_successful: bool = True
    timestamp: datetime | None = None
    failed_logins: int = Field(default=0, ge=0, le=10000)
    successful_logins: int = Field(default=0, ge=0, le=10000)
    unique_ips: list[str] = Field(default_factory=list, max_length=100)
    unique_ip_count: int | None = Field(default=None, ge=0, le=100)
    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    model_score: float | None = Field(default=None, ge=0, le=1)
    ip_risk: float | None = Field(default=None, ge=0, le=1)
    device_changed: bool = False
    location_changed: bool = False
    new_device: bool = False
    geo_velocity_violation: bool = False
    login_hour: int | None = Field(default=None, ge=0, le=23)
    login_features: dict[str, Any] | None = None


class ContainmentRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


public_router = APIRouter(tags=["security"])
admin_router = APIRouter(prefix="/admin", tags=["admin-security"], dependencies=[Depends(require_api_key)])


@public_router.post("/auth/login", summary="Analyze a login event")
def security_login(payload: LoginSecurityRequest) -> dict[str, Any]:
    """Analyze a synthetic login and return an application-level decision."""
    event = payload.model_dump(exclude_none=True)
    login_features = event.pop("login_features", None)
    if login_features is not None:
        from cyberguard_api.routes_webmcp import _run_login_rf

        try:
            model_result = _run_login_rf(login_features)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Login model inference unavailable") from exc
        event["model_score"] = model_result["attack_score"]
    try:
        assessment = engine.assess_login(event)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if assessment["access_decision"] == "DENIED_DEMO_CONTAINED":
        return {
            "login_allowed": False,
            "status": "DEMO_CONTAINED",
            "message": "Access denied by CyberGuard security policy.",
            "incident_id": assessment.get("incident_id"),
            "reason": "High-risk security incident",
            "assessment": assessment,
        }
    return assessment


@admin_router.get("/security/summary")
def admin_security_summary() -> dict[str, Any]:
    return engine.security_center_summary()


@admin_router.get("/security/events")
def admin_security_events() -> dict[str, Any]:
    return {"events": engine.list_events()}


@admin_router.get("/security/suspicious-users")
def admin_suspicious_users() -> dict[str, Any]:
    events = [event for event in engine.list_events() if event.get("status") != "SAFE"]
    return {"users": events}


@admin_router.get("/incidents")
def admin_incidents() -> dict[str, Any]:
    return {"incidents": engine.list_incidents()}


@admin_router.get("/incidents/{incident_id}")
def admin_incident(incident_id: str) -> dict[str, Any]:
    incident = engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@admin_router.get("/users/{user_id}/security")
def admin_user_security(user_id: str) -> dict[str, Any]:
    events = [event for event in engine.list_events() if event.get("user_id") == user_id]
    if not events:
        raise HTTPException(status_code=404, detail="User has no security events")
    return {"user_id": user_id, "events": events, "access": engine.access_status(user_id)}


@admin_router.get("/audit-logs")
def admin_audit_logs() -> dict[str, Any]:
    return {"events": engine.audit_events()}


@admin_router.get("/access-control/{user_id}")
def admin_access_status(user_id: str) -> dict[str, Any]:
    return engine.access_status(user_id)


@admin_router.post("/access-control/deny")
def admin_deny_access(payload: ContainmentRequest, request: Request, user_id: str | None = None) -> dict[str, Any]:
    if not user_id:
        raise HTTPException(status_code=422, detail="user_id query parameter is required")
    actor = get_settings().admin_username or "admin"
    try:
        return engine.deny_access(user_id, actor, payload.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Active incident not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@admin_router.post("/access-control/restore")
def admin_restore_access(request: Request, user_id: str | None = None) -> dict[str, Any]:
    if not user_id:
        raise HTTPException(status_code=422, detail="user_id query parameter is required")
    try:
        return engine.restore_access(user_id, get_settings().admin_username or "admin")
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
