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

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from typing import Annotated

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, StringConstraints

from cyberguard_api.gateway import get_settings, require_api_key
from cyberguard_api.observability import sanitized_error
from cyberguard_api.services import telemetry as _tele
from cyberguard_api.services.telemetry import MOCK_TELEMETRY
from cyberguard_api.services import security_decision_engine as _security_engine

_LOG = logging.getLogger("cyberguard.webmcp")

# Bounded free-text: at most 500 chars per recommendation, 1-25 items (PP-M2 / PP-M3).
RecommendationStr = Annotated[str, StringConstraints(min_length=3, max_length=500)]

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

# Strict, explicit CORS surface (M-8) — no wildcards alongside credentials.
# `X-Scope-Token` is gone with the decommissioned ?scope=full bypass (M-5).
ALLOWED_CORS_METHODS = ["GET", "POST", "OPTIONS"]
ALLOWED_CORS_HEADERS = ["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"]


def _parse_cors_origins(raw: str | None) -> list[str]:
    """Parse CORS_ORIGINS: a JSON array (`["https://a","https://b"]`) or a
    comma-delimited list (`https://a, https://b`). Returns [] when unset."""
    if not raw or not raw.strip():
        return []
    raw = raw.strip()
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(o).strip() for o in parsed if str(o).strip()]
        except (ValueError, TypeError):
            pass
    return [part.strip() for part in raw.split(",") if part.strip()]


def configure_cors(app: FastAPI, extra_origins: list[str] | None = None) -> list[str]:
    """
    Attach CORSMiddleware (M-8).

    Origins come from the ``CORS_ORIGINS`` env var (JSON array or comma-delimited).
    When it is unset we fall back to the local dev origins so a `vite`/`http.server`
    frontend keeps working, and log that we did. Methods are limited to
    GET/POST/OPTIONS and headers to an explicit allow-list — never ``"*"`` while
    ``allow_credentials`` is on.
    """
    env_origins = _parse_cors_origins(os.getenv("CORS_ORIGINS"))
    if env_origins:
        origins = env_origins + list(extra_origins or [])
        source = "CORS_ORIGINS env var"
    elif get_settings().is_production:
        # L-5: never ship the permissive localhost fallback with credentials.
        raise RuntimeError(
            "CORS_ORIGINS must be set to an explicit origin list when "
            "APP_ENV=production (no wildcard / dev fallback)."
        )
    else:
        origins = list(DEFAULT_DEV_ORIGINS) + list(extra_origins or [])
        source = "DEFAULT_DEV_ORIGINS fallback — set CORS_ORIGINS for production"
    if "*" in origins:
        raise RuntimeError("wildcard CORS origin is not allowed with credentials")
    _LOG.info("cors allow_origins configured", extra={"origins": origins, "source": source})

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=ALLOWED_CORS_METHODS,
        allow_headers=ALLOWED_CORS_HEADERS,
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    return origins


# ============================================================================
# Telemetry store + PII projection + scoring
# ----------------------------------------------------------------------------
# All of this now lives in cyberguard_api.services.telemetry (L-7) and is
# shared verbatim with agent_controller.py and cyberguard_mcp_server.py, so a
# record is masked identically on every transport (M-6).
#
# `project_user()` is the ONLY user shape allowed in a response and it always
# masks the username + IPs — there is no unmasked path and the `?scope=full` /
# X-Scope-Token bypass has been removed (C-5 / M-5).
# ============================================================================

_generate_incident_report = _tele.generate_incident_report


def _project_user(user: dict[str, Any]) -> dict[str, Any]:
    """Always-masked projection (kept as a local alias for the route bodies)."""
    return _tele.project_user(user)


def _store_call(fn, *args):
    """
    Run a telemetry-store read, converting an upstream connection failure / 5xx
    into a clean sanitised 503 with a correlation id (A-M4). ``HTTPException``
    (e.g. the 404 for an unknown user) passes straight through.
    """
    try:
        return fn(*args)
    except HTTPException:
        raise
    except Exception as exc:  # httpx errors, JSON decode, backend down, ...
        raise sanitized_error(
            "telemetry backend read",
            exc,
            status_code=503,
            client_message="Telemetry backend unavailable",
        ) from exc


def _security_summary() -> dict[str, Any]:
    return _store_call(_tele.security_summary)


def _suspicious_users(limit: int = 5) -> list[dict[str, Any]]:
    return _store_call(_tele.suspicious_users, limit)


def _get_user_or_404(user_id: str) -> dict[str, Any]:
    user = _store_call(_tele.get_user, user_id)
    if user is None:
        raise HTTPException(
            status_code=404,
            detail=f"User {user_id} not found in current telemetry log.",
        )
    return user


def _risk_score(user_id: str) -> dict[str, Any]:
    _get_user_or_404(user_id)  # 404 for an unknown user
    return _store_call(_tele.risk_score, user_id)


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

# Login-RF operating threshold. Raised from the 0.55 development point to 0.70 to
# cut false positives (precision was ~0.30 at 0.55). Override with LOGIN_THRESHOLD.
# `_run_login_rf` always returns the raw probability AND this threshold so a
# consumer can apply its own alert boundary (M-10).
try:
    LOGIN_THRESHOLD = float(os.getenv("LOGIN_THRESHOLD", "0.70"))
except ValueError:
    LOGIN_THRESHOLD = 0.70

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
    """Lazy-load + cache the login RF and its preprocessor (SHA-256 verified, C-4)."""
    from cyberguard_api.services.model_loader import load_verified

    rf = load_verified("cyberguard_rf_final.pkl")
    preprocessor = load_verified("cyberguard_preprocessor_final.pkl")
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
        "attack_score": round(score, 4),      # raw model probability of "attack"
        "raw_score": score,                    # full-precision, for custom boundaries
        "attack_detected": score >= LOGIN_THRESHOLD,
        "threshold": LOGIN_THRESHOLD,
        "threshold_source": "LOGIN_THRESHOLD env var (default 0.70)",
        "model": "cyberguard_rf_final.pkl",
    }


def _run_network_rf(network_flow: dict[str, Any]) -> dict[str, Any]:
    """network_attack_model.pkl + bot_specialist_model.pkl inference on a flow."""
    from cyberguard_api.services.network_detector import detect_network_attack

    try:
        res = detect_network_attack(network_flow)
    except ValueError as exc:  # missing / malformed features
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # `attack_type` is already a canonical ASCII label (network_detector.clean_label),
    # so no mojibake stripping is needed for the MITRE lookup (L-4).
    label = str(res["attack_type"])
    label_lc = label.lower()
    mitre = None
    for key, technique in NETWORK_MITRE.items():
        if key.lower() in label_lc:
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
    Grounded fallback when no feature vector is supplied: the shared, deterministic
    classifier over this user's telemetry counters. Every field is cited in
    ``evidence`` (see cyberguard_api.services.telemetry.classify_pattern).
    """
    return _tele.classify_pattern(_get_user_or_404(user_id))


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
    # PP-M3: bound BOTH the list length AND each item's length.
    recommendations: list[RecommendationStr] = Field(..., min_length=1, max_length=25)


class AgentInvestigateRequest(BaseModel):
    # Optional — omit (or send {}) to let the agent auto-select via triage.
    user_id: str | None = Field(default=None, min_length=2, max_length=64)


# ============================================================================
# Router
# ============================================================================

# Every /api/v1/* route requires a valid API key / Bearer token (C-3). In dev
# with API_KEYS unset the dependency is a no-op (logs a warning once).
router = APIRouter(
    prefix="/api/v1", tags=["webmcp"], dependencies=[Depends(require_api_key)]
)


@router.get("/security/summary")
def webmcp_security_summary() -> dict[str, Any]:
    return _security_summary()


@router.get("/users/suspicious")
def webmcp_suspicious_users(
    limit: int = Query(default=5, ge=1, le=100),
) -> dict[str, Any]:
    # Always masked — no ?scope=full / X-Scope-Token bypass (C-5 / M-5).
    return {
        "scope": "masked",
        "result": [_project_user(u) for u in _suspicious_users(limit)],
    }


@router.get("/users/{user_id}/investigate")
def webmcp_investigate_user(user_id: str) -> dict[str, Any]:
    projected = _project_user(_get_user_or_404(user_id))
    projected["scope"] = "masked"
    return projected


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
        except Exception as exc:  # model load / runtime failure (PP-H2: no str(exc))
            raise sanitized_error(
                "network model inference", exc,
                status_code=503, client_message="Network model inference unavailable",
            ) from exc
        return {"user_id": req.user_id, "inference_mode": "network_rf+bot_specialist", **result}

    # 2. Login event supplied -> login attack RF.
    if req.login_event:
        try:
            rf_out = _run_login_rf(req.login_event)
        except HTTPException:
            raise
        except Exception as exc:  # PP-H2: no str(exc) in the client body
            raise sanitized_error(
                "login model inference", exc,
                status_code=503, client_message="Login model inference unavailable",
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


@router.get("/incidents")
def webmcp_active_incidents() -> dict[str, Any]:
    return {"incidents": _security_engine.list_incidents()}


@router.get("/incidents/{incident_id}")
def webmcp_incident_details(incident_id: str) -> dict[str, Any]:
    incident = _security_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/users/{user_id}/access-control")
def webmcp_access_control_status(user_id: str) -> dict[str, Any]:
    return _security_engine.access_status(user_id)


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
            "get_active_incidents": {
                "method": "GET",
                "path": "/api/v1/incidents",
            },
            "get_incident_details": {
                "method": "GET",
                "path": "/api/v1/incidents/{incident_id}",
            },
            "get_access_control_status": {
                "method": "GET",
                "path": "/api/v1/users/{user_id}/access-control",
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
