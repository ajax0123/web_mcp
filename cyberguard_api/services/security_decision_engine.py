"""Unified login risk decisions and demo security-center state."""
from __future__ import annotations

from datetime import datetime, timezone
from threading import RLock
from typing import Any
import uuid
import os

from cyberguard_api.services import telemetry

RISK_WEIGHTS = {
    "ml_attack": 0.30,
    "anomaly": 0.20,
    "ip_risk": 0.15,
    "auth_failures": 0.15,
    "device_change": 0.10,
    "location_anomaly": 0.05,
    "attack_pattern": 0.05,
}

_lock = RLock()
_incidents: dict[str, dict[str, Any]] = {}
_audit_log: list[dict[str, Any]] = []
_access_state: dict[str, dict[str, Any]] = {}
_login_events: list[dict[str, Any]] = []


def demo_mode_enabled() -> bool:
    return os.getenv("DEMO_MODE", "true").strip().lower() in {"1", "true", "yes", "on"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level(score: int) -> str:
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def _status(score: int) -> tuple[str, str, str]:
    if score >= 80:
        return "HIGH_RISK", "REQUIRE_ADMIN_REVIEW", "REVIEW"
    if score >= 30:
        return "SUSPICIOUS", "PENDING_REVIEW", "FLAG_FOR_REVIEW"
    return "SAFE", "ALLOWED", "ALLOW"


def _audit(event_type: str, user_id: str, actor: str, reason: str, **metadata: Any) -> dict[str, Any]:
    entry = {
        "event_id": f"EVT-{uuid.uuid4().hex[:10].upper()}",
        "timestamp": _now(), "event_type": event_type, "user_id": user_id,
        "incident_id": metadata.pop("incident_id", None), "risk_score": metadata.pop("risk_score", None),
        "actor": actor, "reason": reason, "metadata": metadata,
    }
    _audit_log.append(entry)
    return entry


def assess_login(event: dict[str, Any]) -> dict[str, Any]:
    user_id = str(event.get("user_id", "")).strip()
    if not user_id:
        raise ValueError("user_id is required")
    with _lock:
        existing = telemetry.get_user(user_id) or {}
        contained = _access_state.get(user_id, {}).get("status") == "DEMO_CONTAINED"
        failed = int(event.get("failed_logins", existing.get("failed_logins", 0)) or 0)
        successful = int(event.get("successful_logins", existing.get("successful_logins", 0)) or 0)
        anomaly = float(event.get("anomaly_score", existing.get("anomaly_score", 0.0)) or 0.0)
        ip_count = int(event.get("unique_ip_count", len(event.get("unique_ips", existing.get("unique_ips", [])) or [])) or 0)
        device_changed = bool(event.get("device_changed", event.get("new_device", existing.get("device_changes", 0) > 0)))
        location_changed = bool(event.get("location_changed", event.get("geo_velocity_violation", existing.get("geo_velocity_violation", False))))
        login_successful = bool(event.get("login_successful", True))
        hour = event.get("login_hour", event.get("timestamp", ""))
        unusual_hour = isinstance(hour, int) and (hour < 6 or hour >= 22)
        ip_risk = float(event.get("ip_risk", min(1.0, max(0, (ip_count - 1) * 0.25 + (0.35 if location_changed else 0)))))
        model_score = float(event["model_score"]) if event.get("model_score") is not None else None
        ml_signal = model_score if model_score is not None else min(1.0, (0.65 if failed >= 20 else 0.35 if failed >= 5 else 0.0) + (0.2 if not login_successful else 0.0))
        attack_score = min(1.0, float(ml_signal))
        attack_type = "Possible Account Takeover" if login_successful and (device_changed or location_changed) and failed >= 5 else "Brute Force" if failed >= 20 and not login_successful else "Suspicious Authentication Activity" if failed >= 5 or anomaly >= 0.5 else "Normal"
        pattern_signal = 1.0 if attack_type != "Normal" else 0.0
        failure_signal = min(1.0, failed / 30)
        signals = {"ml_attack": attack_score, "anomaly": anomaly, "ip_risk": ip_risk, "auth_failures": failure_signal, "device_change": 1.0 if device_changed else 0.0, "location_anomaly": 1.0 if location_changed or unusual_hour else 0.0, "attack_pattern": pattern_signal}
        score = max(0, min(100, round(sum(signals[name] * weight for name, weight in RISK_WEIGHTS.items()) * 100)))
        if contained:
            status, access, action = "HIGH_RISK", "DENIED_DEMO_CONTAINED", "DENY_ACCESS"
        else:
            status, access, action = _status(score)
        evidence = []
        if failed: evidence.append(f"{failed} failed login attempts on record")
        if device_changed: evidence.append("Login from a previously unseen device")
        if ip_count > 1: evidence.append(f"Authentication associated with {ip_count} source IP addresses")
        if location_changed: evidence.append("Unusual location or impossible-travel signal")
        if unusual_hour: evidence.append("Unusual login hour")
        if anomaly >= 0.5: evidence.append(f"Behavior anomaly score is elevated ({anomaly:.2f})")
        result = {"user_id": user_id, "session_id": f"SESSION-{uuid.uuid4().hex[:10].upper()}", "status": status, "risk_score": score, "risk_level": _risk_level(score), "attack_type": attack_type, "model_score": round(model_score, 4) if model_score is not None else None, "model_signal": round(attack_score, 4), "model_source": "provided_model_output" if model_score is not None else "deterministic_rule_fallback", "anomaly_score": round(anomaly, 4), "confidence": round(max(0.0, min(1.0, 0.5 + abs(score - 50) / 100)), 4), "recommended_action": action, "access_decision": access, "login_allowed": access == "ALLOWED", "evidence": evidence or ["No elevated security indicators detected"], "risk_signal_contribution": {name: round(signals[name] * RISK_WEIGHTS[name] * 100) for name in signals}, "created_at": _now()}
        _login_events.append({**event, **result})
        _audit("LOGIN_DETECTED", user_id, "system", attack_type, risk_score=score)
        if status == "SAFE": _audit("LOGIN_ALLOWED", user_id, "system", "Risk below review threshold", risk_score=score)
        else:
            if contained:
                existing_incident = next((item for item in _incidents.values() if item["user_id"] == user_id and item["containment_status"] == "DEMO_CONTAINED"), None)
                if existing_incident:
                    result["incident_id"] = existing_incident["incident_id"]
                    _audit("LOGIN_FLAGGED", user_id, "system", "Access denied by demo containment", incident_id=existing_incident["incident_id"], risk_score=score)
                    return result
            incident = create_incident(result, actor="system")
            result["incident_id"] = incident["incident_id"]
        return result


def create_incident(assessment: dict[str, Any], actor: str = "system") -> dict[str, Any]:
    incident_id = assessment.get("incident_id") or f"INC-2026-{uuid.uuid4().hex[:8].upper()}"
    incident = {"incident_id": incident_id, "user_id": assessment["user_id"], "created_at": _now(), "updated_at": _now(), "status": "ACTIVE", "severity": assessment["risk_level"], "risk_score": assessment["risk_score"], "attack_type": assessment["attack_type"], "model_score": assessment.get("model_score"), "anomaly_score": assessment.get("anomaly_score"), "evidence": list(assessment.get("evidence", [])), "recommended_action": assessment.get("recommended_action"), "containment_status": "NOT_CONTAINED"}
    _incidents[incident_id] = incident
    _access_state.setdefault(assessment["user_id"], {"status": "REVIEW_REQUIRED" if assessment["risk_score"] >= 30 else "ACTIVE"})
    _audit("INCIDENT_CREATED", assessment["user_id"], actor, assessment["attack_type"], incident_id=incident_id, risk_score=assessment["risk_score"])
    return incident


def list_incidents() -> list[dict[str, Any]]:
    with _lock: return list(reversed(list(_incidents.values())))


def get_incident(incident_id: str) -> dict[str, Any] | None:
    with _lock: return _incidents.get(incident_id)


def list_events() -> list[dict[str, Any]]:
    with _lock:
        projected = []
        for event in reversed(_login_events):
            safe_event = {key: value for key, value in event.items() if key not in {"ip_address", "unique_ips"}}
            if event.get("ip_address"):
                safe_event["ip_address_masked"] = telemetry.mask_ip(event["ip_address"])
            if event.get("unique_ips"):
                safe_event["unique_ips_masked"] = [telemetry.mask_ip(ip) for ip in event["unique_ips"]]
            projected.append(safe_event)
        return projected


def deny_access(user_id: str, actor: str, reason: str | None = None) -> dict[str, Any]:
    with _lock:
        if not demo_mode_enabled():
            raise RuntimeError("Demo containment is disabled")
        incident = next((item for item in _incidents.values() if item["user_id"] == user_id and item["status"] == "ACTIVE"), None)
        if not incident: raise KeyError("active incident not found")
        if _access_state.get(user_id, {}).get("status") == "DEMO_CONTAINED": raise RuntimeError("user is already demo-contained")
        _access_state[user_id] = {"status": "DEMO_CONTAINED", "incident_id": incident["incident_id"], "updated_at": _now()}
        incident.update({"status": "CONTAINED", "updated_at": _now(), "containment_status": "DEMO_CONTAINED"})
        _audit("ACCESS_DENIED_DEMO", user_id, actor, reason or incident["attack_type"], incident_id=incident["incident_id"], risk_score=incident["risk_score"], mode="DEMO")
        return {"user_id": user_id, "incident_id": incident["incident_id"], "action": "DENY_ACCESS", "mode": "DEMO", "authorized_by": actor, "reason": reason or incident["attack_type"], "timestamp": _now(), "status": "CONTAINED"}


def access_status(user_id: str) -> dict[str, Any]:
    with _lock: return {"user_id": user_id, **_access_state.get(user_id, {"status": "ACTIVE"})}


def restore_access(user_id: str, actor: str) -> dict[str, Any]:
    with _lock:
        current = _access_state.get(user_id, {})
        if current.get("status") != "DEMO_CONTAINED":
            raise RuntimeError("user is not demo-contained")
        _access_state[user_id] = {"status": "ACTIVE", "updated_at": _now()}
        _audit("INCIDENT_RESOLVED", user_id, actor, "Demo containment restored")
        return {"user_id": user_id, "status": "ACTIVE", "mode": "DEMO"}


def audit_events() -> list[dict[str, Any]]:
    with _lock: return list(reversed(_audit_log))


def security_center_summary() -> dict[str, Any]:
    with _lock:
        events = _login_events
        return {"total_logins": len(events), "safe_logins": sum(1 for e in events if e.get("status") == "SAFE"), "suspicious_logins": sum(1 for e in events if e.get("status") == "SUSPICIOUS"), "high_risk_events": sum(1 for e in events if e.get("status") == "HIGH_RISK"), "active_incidents": sum(1 for i in _incidents.values() if i["status"] == "ACTIVE"), "contained": sum(1 for state in _access_state.values() if state.get("status") == "DEMO_CONTAINED"), "risk_distribution": {level: sum(1 for e in events if e.get("risk_level") == level) for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}}
