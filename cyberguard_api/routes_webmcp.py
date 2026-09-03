"""
routes_webmcp.py
================================================================================
REST surface for the browser WebMCP bridge (../webmcp_bridge.js), Phase 2.

Mounts under `/api/v1` and mirrors the six CyberGuard MCP tools defined in
`cyberguard_mcp_server.py`:

    GET  /api/v1/security/summary              -> get_security_summary()
    GET  /api/v1/users/suspicious?limit=5      -> get_suspicious_users(limit)
    GET  /api/v1/users/{user_id}/investigate   -> investigate_user(user_id)
    GET  /api/v1/users/{user_id}/risk-score    -> get_user_risk_score(user_id)
    POST /api/v1/analyze/attack-pattern        -> ML inference (see below)
    POST /api/v1/reports/incident             -> generate_incident_report(...)

`POST /api/v1/analyze/attack-pattern` runs REAL model inference when the caller
supplies a feature vector:
  * `login_event`  (32 login features)  -> models/cyberguard_rf_final.pkl
                                           + models/cyberguard_preprocessor_final.pkl
  * `network_flow` (65 CICIDS features) -> models/network_attack_model.pkl
                                           + models/bot_specialist_model.pkl
                                           (via services.network_detector)
  * neither supplied -> grounded heuristic over the telemetry store
                        (`inference_mode: "heuristic_fallback"`).

Wire it into the app from main.py with one line:

    from cyberguard_api.routes_webmcp import register_webmcp_routes
    register_webmcp_routes(app)                       # adds dev CORS + router

SAFETY: analytical only. `generate_incident_report` records recommendations;
it never executes remediation.
================================================================================
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

__all__ = [
    "router",
    "configure_cors",
    "register_webmcp_routes",
    "DEFAULT_DEV_ORIGINS",
]

MODEL_DIR = Path(__file__).resolve().parent / "models"

# ============================================================================
# CORS — local frontend dev servers
# ============================================================================

DEFAULT_DEV_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


def configure_cors(app: FastAPI, extra_origins: list[str] | None = None) -> list[str]:
    """Attach CORSMiddleware allowing the local dev origins (ports 3000 / 5173)."""
    origins = list(DEFAULT_DEV_ORIGINS) + list(extra_origins or [])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
    return origins


# ============================================================================
# Telemetry store
# ----------------------------------------------------------------------------
# Mirrors MOCK_TELEMETRY + tool logic in cyberguard_mcp_server.py.
# Keep the two in sync (or extract to a shared module later).
# ============================================================================

MOCK_TELEMETRY: dict[str, dict[str, Any]] = {
    "USR-402": {
        "user_id": "USR-402",
        "username": "alex.chen@enterprise.internal",
        "failed_logins": 47,
        "successful_logins": 1,
        "unique_ips": ["198.51.100.23", "203.0.113.88", "192.0.2.14"],
        "anomaly_score": 0.93,
        "device_changes": 4,
        "geo_velocity_violation": True,
    },
    "USR-108": {
        "user_id": "USR-108",
        "username": "sarah.admin@enterprise.internal",
        "failed_logins": 12,
        "successful_logins": 2,
        "unique_ips": ["198.51.100.12"],
        "anomaly_score": 0.68,
        "device_changes": 1,
        "geo_velocity_violation": False,
    },
}


def _security_summary() -> dict[str, Any]:
    return {
        "monitored_users": 150,
        "flagged_suspicious_users": 2,
        "high_severity_alerts": 1,
        "status": "ELEVATED_RISK",
    }


def _suspicious_users(limit: int = 5) -> list[dict[str, Any]]:
    ranked = sorted(
        MOCK_TELEMETRY.values(),
        key=lambda u: u["anomaly_score"],
        reverse=True,
    )
    return ranked[:limit]


def _get_user_or_404(user_id: str) -> dict[str, Any]:
    user = MOCK_TELEMETRY.get(user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"User {user_id} not found in current telemetry log.",
        )
    return user


def _risk_score(user_id: str) -> dict[str, Any]:
    user = _get_user_or_404(user_id)
    score = int(user["anomaly_score"] * 100)
    return {
        "user_id": user_id,
        "risk_score": score,
        "risk_level": (
            "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM"
        ),
        "top_contributing_factors": [
            f"{user['failed_logins']} failed authentication attempts within 10 minutes",
            "Geographical impossible travel detected across 3 ASN networks",
            "New unrecognized device fingerprint observed",
        ],
    }


def _incident_id(user_id: str) -> str:
    # Deterministic (differs from the MCP server's process-salted hash()) so the
    # REST API returns a stable id for the same user across restarts.
    digest = int(hashlib.sha256(user_id.encode("utf-8")).hexdigest(), 16)
    return f"INC-2026-{digest % 10000:04d}"


def _generate_incident_report(
    user_id: str, threat_type: str, severity: str, recommendations: list[str]
) -> dict[str, Any]:
    return {
        "incident_id": _incident_id(user_id),
        "status": "LOGGED",
        "target_entity": user_id,
        "severity": severity,
        "threat_type": threat_type,
        "recommended_actions": recommendations,
    }


# ============================================================================
# ML inference — attack-pattern
# ============================================================================

# Exact training feature order for the login RF (from main.analyze_ip).
LOGIN_FEATURE_COLS = [
    "login_hour",
    "Login Successful",
    "Country",
    "Device Type",
    "Browser Name and Version",
    "OS Name and Version",
    "ip_total_logins",
    "ip_unique_users",
    "ip_failure_rate",
    "ip_logins_1h",
    "ip_failed_1h",
    "ip_failure_rate_1h",
    "ip_unique_users_1h",
    "ip_logins_24h",
    "ip_failed_24h",
    "ip_failure_rate_24h",
    "ip_unique_users_24h",
    "ip_logins_7d",
    "ip_failed_7d",
    "ip_failure_rate_7d",
    "ip_unique_users_7d",
    "user_prev_logins",
    "user_prev_failed_logins",
    "user_prev_failure_rate",
    "user_prev_unique_ips",
    "user_prev_unique_countries",
    "user_prev_unique_devices",
    "user_prev_unique_asns",
    "user_account_age_days",
    "user_hour_diff",
    "user_device_changed",
    "user_is_first_event",
]

# API field name -> training column name.
LOGIN_RENAME = {
    "country": "Country",
    "device_type": "Device Type",
    "browser_name_and_version": "Browser Name and Version",
    "os_name_and_version": "OS Name and Version",
    "login_successful": "Login Successful",
}

LOGIN_THRESHOLD = 0.55

# Attack label -> MITRE ATT&CK technique id (best-effort mapping).
NETWORK_MITRE = {
    "BENIGN": None,
    "Bot": "T1071",
    "DDoS": "T1498",
    "DoS GoldenEye": "T1499",
    "DoS Hulk": "T1499",
    "DoS Slowhttptest": "T1499",
    "DoS slowloris": "T1499",
    "FTP-Patator": "T1110.001",
    "SSH-Patator": "T1110.001",
    "Heartbleed": "T1190",
    "Infiltration": "T1078",
    "PortScan": "T1046",
    "Brute Force": "T1110",
    "Sql Injection": "T1190",
    "XSS": "T1059.007",
}


@lru_cache(maxsize=1)
def _login_models():
    """Lazy-load + cache the login RF and its preprocessor."""
    import joblib

    rf = joblib.load(MODEL_DIR / "cyberguard_rf_final.pkl")
    preprocessor = joblib.load(MODEL_DIR / "cyberguard_preprocessor_final.pkl")
    return rf, preprocessor


def _run_login_rf(login_event: dict[str, Any]) -> dict[str, Any]:
    """cyberguard_rf_final.pkl inference on a single login event."""
    import pandas as pd

    rf, preprocessor = _login_models()

    df = pd.DataFrame([login_event]).rename(columns=LOGIN_RENAME)
    missing = [c for c in LOGIN_FEATURE_COLS if c not in df.columns]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"login_event missing required features: {missing}",
        )

    X = df[LOGIN_FEATURE_COLS]
    X_processed = preprocessor.transform(X)
    score = float(rf.predict_proba(X_processed)[:, 1][0])
    return {
        "attack_score": round(score, 4),
        "attack_detected": score >= LOGIN_THRESHOLD,
        "threshold": LOGIN_THRESHOLD,
        "model": "cyberguard_rf_final.pkl",
    }


def _run_network_rf(network_flow: dict[str, Any]) -> dict[str, Any]:
    """network_attack_model.pkl + bot_specialist_model.pkl inference on a flow."""
    from cyberguard_api.services.network_detector import detect_network_attack

    try:
        res = detect_network_attack(network_flow)
    except ValueError as exc:  # missing / malformed features
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    label = str(res["attack_type"])
    normalized = label.replace("�", "").replace("Web Attack", "").strip()
    mitre = None
    for key, technique in NETWORK_MITRE.items():
        if key.lower() in normalized.lower() or key.lower() in label.lower():
            mitre = technique
            break

    return {
        "classified_pattern": label,
        "confidence": res["model_score"],
        "attack_detected": bool(res["is_attack"]),
        "mitre_technique_id": mitre,
        "model_scores": {
            "main_model_score": res["model_score"],
            "bot_specialist_score": res["bot_specialist_score"],
            "bot_override": res["bot_override"],
        },
        "signature_details": (
            f"network_attack_model.pkl -> {label} "
            f"(p={res['model_score']}); bot_specialist p={res['bot_specialist_score']}"
            + (" [bot override applied]" if res["bot_override"] else "")
        ),
    }


def _name_login_pattern(user_id: str, score: float, detected: bool) -> tuple[str, str | None]:
    """Name the login attack from the RF verdict + this user's telemetry."""
    u = MOCK_TELEMETRY.get(user_id, {})
    failed = u.get("failed_logins", 0)
    success = u.get("successful_logins", 0)
    ips = len(u.get("unique_ips", []))
    geo = u.get("geo_velocity_violation", False)
    dev = u.get("device_changes", 0)

    if success >= 1 and (geo or dev >= 3) and failed >= 10:
        return "Account Takeover (ATO)", "T1078.004"
    if failed >= 20 and success == 0 and ips <= 2:
        return "Brute Force", "T1110.001"
    if ips >= 3 and failed >= 10:
        return "Credential Stuffing", "T1110.004"
    if detected:
        return "Anomalous Authentication", "T1078"
    return "Normal", None


def _heuristic_pattern(user_id: str) -> dict[str, Any]:
    """
    Grounded fallback when no feature vector is supplied: classify purely from
    the telemetry store's counters. Every field below is cited in `evidence`.
    """
    u = _get_user_or_404(user_id)
    failed = u["failed_logins"]
    success = u["successful_logins"]
    ips = len(u["unique_ips"])
    geo = u["geo_velocity_violation"]
    dev = u["device_changes"]
    anom = u["anomaly_score"]

    if success >= 1 and geo and (failed >= 10 or dev >= 3):
        pattern, mitre, confidence = "Account Takeover (ATO)", "T1078.004", anom
        signature = (
            f"{failed} failed then {success} successful auth; impossible travel "
            f"across {ips} distinct IPs; {dev} device changes."
        )
    elif failed >= 20 and success == 0 and ips <= 2:
        pattern, mitre = "Brute Force", "T1110.001"
        confidence = min(0.97, 0.50 + failed / 100)
        signature = f"{failed} consecutive failed auth from {ips} IP(s); no successful login."
    elif ips >= 3 and failed >= 10:
        pattern, mitre = "Credential Stuffing", "T1110.004"
        confidence = min(0.95, 0.40 + ips * 0.10)
        signature = f"{failed} failed auth spread across {ips} distinct source IPs."
    elif failed <= 3 and anom < 0.40:
        pattern, mitre, confidence = "Normal", None, round(1 - anom, 4)
        signature = f"{failed} failed / {success} successful auth; anomaly score {anom}."
    else:
        pattern, mitre, confidence = "Suspicious Authentication Activity", "T1078", anom
        signature = (
            f"{failed} failed / {success} successful auth; anomaly score {anom}; "
            f"{ips} unique IPs; {dev} device changes."
        )

    return {
        "classified_pattern": pattern,
        "confidence": round(float(confidence), 4),
        "attack_detected": pattern != "Normal",
        "mitre_technique_id": mitre,
        "signature_details": signature,
        "evidence": {
            "failed_logins": failed,
            "successful_logins": success,
            "unique_ip_count": ips,
            "geo_velocity_violation": geo,
            "device_changes": dev,
            "anomaly_score": anom,
        },
    }


# ============================================================================
# Request models
# ============================================================================

class AttackPatternRequest(BaseModel):
    user_id: str = Field(..., min_length=2, max_length=64)
    # Optional feature vectors — presence selects the inference path.
    login_event: dict[str, Any] | None = Field(
        default=None, description="32 login features -> cyberguard_rf_final.pkl"
    )
    network_flow: dict[str, Any] | None = Field(
        default=None, description="65 CICIDS flow features -> network_attack_model.pkl"
    )


class IncidentRequest(BaseModel):
    user_id: str = Field(..., min_length=2, max_length=64)
    threat_type: str = Field(..., min_length=2, max_length=120)
    severity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    recommendations: list[str] = Field(..., min_length=1, max_length=25)


class AgentInvestigateRequest(BaseModel):
    # Optional — omit (or send {}) to let the agent auto-select via triage.
    user_id: str | None = Field(default=None, min_length=2, max_length=64)


# ============================================================================
# Router
# ============================================================================

router = APIRouter(prefix="/api/v1", tags=["webmcp"])


@router.get("/security/summary")
def webmcp_security_summary() -> dict[str, Any]:
    return _security_summary()


@router.get("/users/suspicious")
def webmcp_suspicious_users(
    limit: int = Query(default=5, ge=1, le=100),
) -> dict[str, Any]:
    return {"result": _suspicious_users(limit)}


@router.get("/users/{user_id}/investigate")
def webmcp_investigate_user(user_id: str) -> dict[str, Any]:
    return _get_user_or_404(user_id)


@router.get("/users/{user_id}/risk-score")
def webmcp_user_risk_score(user_id: str) -> dict[str, Any]:
    return _risk_score(user_id)


@router.post("/analyze/attack-pattern")
def webmcp_analyze_attack_pattern(req: AttackPatternRequest) -> dict[str, Any]:
    # 1. Network flow supplied -> multiclass RF + bot specialist.
    if req.network_flow:
        try:
            result = _run_network_rf(req.network_flow)
        except HTTPException:
            raise
        except Exception as exc:  # model load / runtime failure
            raise HTTPException(
                status_code=503, detail=f"network model inference unavailable: {exc}"
            ) from exc
        return {"user_id": req.user_id, "inference_mode": "network_rf+bot_specialist", **result}

    # 2. Login event supplied -> login attack RF.
    if req.login_event:
        try:
            rf_out = _run_login_rf(req.login_event)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail=f"login model inference unavailable: {exc}"
            ) from exc
        pattern, mitre = _name_login_pattern(
            req.user_id, rf_out["attack_score"], rf_out["attack_detected"]
        )
        confidence = (
            rf_out["attack_score"]
            if rf_out["attack_detected"]
            else round(1 - rf_out["attack_score"], 4)
        )
        return {
            "user_id": req.user_id,
            "inference_mode": "login_rf",
            "classified_pattern": pattern,
            "confidence": confidence,
            "attack_detected": rf_out["attack_detected"],
            "mitre_technique_id": mitre,
            "model_scores": rf_out,
            "signature_details": (
                f"cyberguard_rf_final.pkl attack probability {rf_out['attack_score']} "
                f"(threshold {LOGIN_THRESHOLD})"
            ),
        }

    # 3. No features -> grounded heuristic over the telemetry store.
    return {
        "user_id": req.user_id,
        "inference_mode": "heuristic_fallback",
        **_heuristic_pattern(req.user_id),
    }


@router.post("/reports/incident")
def webmcp_incident_report(req: IncidentRequest) -> dict[str, Any]:
    return _generate_incident_report(
        req.user_id, req.threat_type, req.severity, req.recommendations
    )


@router.post("/agent/investigate")
async def webmcp_agent_investigate(
    req: AgentInvestigateRequest | None = Body(default=None),
) -> dict[str, Any]:
    """
    Phase 3 — run the autonomous multi-step investigation loop end to end.

    Body is optional: `{"user_id": "USR-402"}` targets a user; an empty body
    lets the agent triage and pick the highest-anomaly user itself.
    """
    from cyberguard_api.services.agent_controller import run_autonomous_investigation

    target = req.user_id if req else None
    return await run_autonomous_investigation(target)


@router.get("/webmcp/manifest")
def webmcp_manifest() -> dict[str, Any]:
    """Tool -> route map for the browser bridge (webmcp_bridge.js DEFAULT_ROUTES)."""
    return {
        "service": "CyberGuard WebMCP REST bridge",
        "version": "1.0.0",
        "base_path": "/api/v1",
        "tools": {
            "get_security_summary": {"method": "GET", "path": "/api/v1/security/summary"},
            "get_suspicious_users": {
                "method": "GET",
                "path": "/api/v1/users/suspicious",
                "query": ["limit"],
            },
            "investigate_user": {
                "method": "GET",
                "path": "/api/v1/users/{user_id}/investigate",
            },
            "get_user_risk_score": {
                "method": "GET",
                "path": "/api/v1/users/{user_id}/risk-score",
            },
            "detect_attack_pattern": {
                "method": "POST",
                "path": "/api/v1/analyze/attack-pattern",
            },
            "generate_incident_report": {
                "method": "POST",
                "path": "/api/v1/reports/incident",
            },
        },
        "orchestration": {
            "agent_investigate": {
                "method": "POST",
                "path": "/api/v1/agent/investigate",
                "body": {"user_id": "optional string"},
                "description": "Autonomous multi-step investigation loop (Phase 3).",
            },
        },
        "cors_dev_origins": DEFAULT_DEV_ORIGINS,
    }


# ============================================================================
# One-call wiring
# ============================================================================

def register_webmcp_routes(
    app: FastAPI, extra_origins: list[str] | None = None
) -> FastAPI:
    """Attach dev CORS and mount the WebMCP router on `app`."""
    configure_cors(app, extra_origins)
    app.include_router(router)
    return app
