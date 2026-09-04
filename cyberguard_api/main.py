"""
CyberGuard ML Scoring API
CyberGuard Attack Detector v1.1.0

Architecture:

LOGIN ATTACK DETECTION
32 engineered features
        ↓
Saved preprocessing pipeline
        ↓
1037 encoded features
        ↓
Final Random Forest
        ↓
Attack Score


NETWORK ATTACK DETECTION
65 network-flow features
        ↓
Saved median imputer
        ↓
Final Random Forest
        ↓
Attack Type
        ↓
Bot Specialist Validation


BEHAVIORAL ANOMALY DETECTION
13 behavioral features
        ↓
Saved scaler
        ↓
Isolation Forest
        ↓
Anomaly Score

Run (from the repo root, web_mcp/):
    uvicorn cyberguard_api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from typing import List

import logging
import os

import pandas as pd

from cyberguard_api.services.model_loader import (
    ModelIntegrityError,
    check_serialization_env,
    load_verified,
    startup_integrity_gate,
)
from cyberguard_api.services import network_detector
from cyberguard_api.services import telemetry as _telemetry
from cyberguard_api.services.network_detector import (
    detect_network_attack,
    load_network_models,
)
from cyberguard_api.observability import (
    configure_logging,
    install_observability,
    sanitized_error,
)

configure_logging(os.getenv("LOG_LEVEL", "INFO"))

# Bounded, dedicated pool for CPU-heavy sync model inference (PP-H5). Kept off
# the shared Starlette threadpool so a burst of predict_proba() cannot starve
# liveness / readiness probes.
_INFERENCE_POOL_SIZE = max(1, int(os.getenv("INFERENCE_POOL_SIZE", "4")))
_INFERENCE_TIMEOUT = float(os.getenv("INFERENCE_TIMEOUT_SECONDS", "5.0"))
INFERENCE_POOL = ThreadPoolExecutor(
    max_workers=_INFERENCE_POOL_SIZE, thread_name_prefix="cg-infer"
)
# Request-shape cap (rejected before any work) and, separately, the number of
# rows a single inference task may carry into the pool (A-H2: keep one task short).
_MAX_BATCH = max(1, int(os.getenv("ML_MAX_BATCH", "200")))
_MAX_INFERENCE_ROWS = max(1, int(os.getenv("INFERENCE_MAX_ROWS", "50")))

# Admission control (A-H2). A worker thread cannot be cancelled, so a timed-out
# `predict_proba` keeps running and holds its slot until it finishes. This
# semaphore bounds how many tasks are ever handed to the pool: when every slot is
# occupied (including by abandoned-but-still-running work) new inference requests
# are FAST-REJECTED with a 503 instead of queueing behind the stuck task.
_INFERENCE_SLOTS = asyncio.Semaphore(_INFERENCE_POOL_SIZE)


async def _run_inference(fn, *args):
    """
    Execute a sync inference callable in the dedicated pool with a wall clock and
    bounded admission. Never queues; a saturated pool -> immediate 503 (A-H2).
    """
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(_INFERENCE_SLOTS.acquire(), timeout=0.05)
    except asyncio.TimeoutError:
        raise sanitized_error(
            "inference saturated",
            status_code=503,
            client_message="Inference capacity exhausted, retry shortly",
        )

    fut = loop.run_in_executor(INFERENCE_POOL, fn, *args)
    released = False
    try:
        result = await asyncio.wait_for(asyncio.shield(fut), timeout=_INFERENCE_TIMEOUT)
        _INFERENCE_SLOTS.release()
        released = True
        return result
    except asyncio.TimeoutError as exc:
        # Cannot kill the thread — free the slot only once the abandoned task
        # actually completes, so the pool self-heals without permanently latching.
        fut.add_done_callback(lambda _f: _INFERENCE_SLOTS.release())
        released = True
        raise sanitized_error(
            "inference timeout", exc, status_code=503, client_message="Inference timed out"
        ) from exc
    except BaseException:
        if not released:
            _INFERENCE_SLOTS.release()
        raise

# Login-RF operating threshold (M-10). Raised from the 0.55 development point to
# 0.70 to cut false positives; override with the LOGIN_THRESHOLD env var. Every
# /analyze_ip result also carries the raw score and this threshold so consumers
# can apply their own alert boundary.
try:
    LOGIN_THRESHOLD = float(os.getenv("LOGIN_THRESHOLD", "0.70"))
except ValueError:
    LOGIN_THRESHOLD = 0.70

logger = logging.getLogger("cyberguard.api")

_MODELS_UNAVAILABLE_DETAIL = "Model artifacts currently unavailable"


def _sanitized_500(kind: str, exc: BaseException) -> HTTPException:
    """M-1 / PP-L5: log the real exception, return a generic envelope whose
    ``correlation_id`` matches the response ``X-Request-ID``."""
    return sanitized_error(kind, exc, status_code=500, client_message="Internal inference error")


def _require_models(*models: object) -> None:
    """
    M-9 / A-M5: respond 503 with the STANDARD envelope
    ``{"error": ..., "correlation_id": ...}`` when a required model artifact
    never loaded.
    """
    if any(model is None for model in models):
        raise sanitized_error(
            "models unavailable",
            status_code=503,
            client_message=_MODELS_UNAVAILABLE_DETAIL,
        )


def _reject_bad_batch(items: list, noun: str) -> None:
    """
    PP-H5 / A-H2: reject empty or oversized batches with 422 before any work, so
    one request can neither monopolise the inference pool nor run a single task
    long enough to hold a slot past the timeout.
    """
    if not items:
        raise HTTPException(status_code=422, detail=f"at least one {noun} entry is required")
    if len(items) > _MAX_INFERENCE_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"batch too large: {len(items)} {noun} entries "
                f"(max {_MAX_INFERENCE_ROWS} per request)"
            ),
        )


from cyberguard_api.security.auth_defense.integration import (
    create_auth_defense_middleware,
    AuthDefenseConfig,
)
from cyberguard_api.security.auth_defense import (
    telemetry_manager,
)
from cyberguard_api.security.init_security import (
    initialize_security_architecture,
    shutdown_security_architecture,
)

from cyberguard_api.gateway import (
    create_limiter,
    get_settings,
    install_middleware,
    rate_limit_exempt,
    require_api_key,
    authenticate_admin,
    revoke_session,
    valid_session,
)

_settings = get_settings()


# ================================================================
# APPLICATION
# ================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan with full security architecture initialization."""
    # Fail closed: a production process must have auth configured (C-3 / L-5).
    if _settings.is_production and not _settings.api_key_set:
        raise RuntimeError(
            "APP_ENV=production but API_KEYS is empty. Configure API_KEYS "
            "(and CORS_ORIGINS) before starting the service."
        )

    # FE-2: warn loudly when the built-in demo admin login is active.
    if _settings.dev_admin_fallback_enabled:
        logger.warning(
            "ADMIN_PASSWORD_HASH is unset and APP_ENV=%s — the dashboard admin "
            "console accepts the DEMO login 'admin' / 'demo1234'. Set "
            "ADMIN_USERNAME + ADMIN_PASSWORD_HASH before any non-dev deploy.",
            _settings.app_env,
        )

    # PP-C2: a production process must not run on the two-record demo store.
    _telemetry.verify_store_config()
    _telemetry.get_store()  # bind + log the backend now, not on first request

    # A-H1 / A-M6: production manifest-location + signature checks and the
    # fail-closed integrity gate run HERE (not at import), so `docker build`'s
    # `import cyberguard_api.main` does not need the production manifest env. A
    # tampered / mismatched artifact raises out of lifespan -> process aborts.
    startup_integrity_gate()

    # PP-C5: refuse to start on an interpreter whose scikit-learn minor differs
    # from the one the model artifacts were serialised with (production only);
    # otherwise emit warnings.
    for _w in check_serialization_env():
        logger.warning("serialization env drift: %s", _w)

    # Initialize enterprise security architecture
    await initialize_security_architecture()

    # Load ML models (M-11: explicit lifecycle load, not import-time). Each .pkl is
    # SHA-256 verified against the manifest before joblib.load runs (C-4). The
    # integrity gate above has already hard-failed on any mismatch in production;
    # here a load error only degrades the affected endpoints to 503.
    global rf_model, preprocessor, iso_forest, scaler
    try:
        rf_model = load_verified("cyberguard_rf_final.pkl")
        preprocessor = load_verified("cyberguard_preprocessor_final.pkl")
        iso_forest = load_verified("isolation_forest_model.pkl")
        scaler = load_verified("feature_scaler.pkl")
        logger.info("login/behavioural models loaded (integrity verified)")
    except ModelIntegrityError:
        logger.error("login/behavioural model integrity failure — endpoints will 503", exc_info=True)
    except Exception:
        logger.warning("login/behavioural models unavailable — endpoints will 503", exc_info=True)

    try:
        load_network_models()
    except Exception:
        logger.warning("network models unavailable — /detect_attack_pattern will 503", exc_info=True)

    yield
    # Graceful shutdown
    logger.info("shutting down: draining inference pool + telemetry store")
    INFERENCE_POOL.shutdown(wait=True, cancel_futures=True)
    await _telemetry.aclose_store()
    await shutdown_security_architecture()


app = FastAPI(
    title="CyberGuard ML Scoring API",
    description=(
        "Cybersecurity ML API for login attack detection, "
        "network attack classification, and behavioral anomaly detection."
    ),
    version="1.1.0",
    lifespan=lifespan,
    docs_url=_settings.docs_url,
    redoc_url=_settings.redoc_url,
)

from cyberguard_api.security_routes import admin_router, public_router

app.include_router(public_router)
app.include_router(admin_router)


class AdminLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)


@app.post("/api/auth/login")
async def admin_login(payload: AdminLoginRequest, response: Response) -> dict[str, str]:
    # FE-2: 503 only when auth is genuinely unavailable — i.e. no hash configured
    # AND the dev demo fallback ('admin' / 'demo1234') is not in effect.
    if not _settings.admin_auth_configured and not _settings.dev_admin_fallback_enabled:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Administrator authentication is not configured.")
    session_id = authenticate_admin(payload.username, payload.password)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid administrator credentials.")
    response.set_cookie(
        "cyberguard_session", session_id, httponly=True, secure=_settings.is_production,
        samesite="lax", max_age=max(60, _settings.auth_session_ttl_seconds), path="/",
    )
    return {"status": "authenticated"}


@app.get("/api/auth/me")
async def admin_session(request: Request) -> dict[str, bool]:
    # `demo_login` lets the dashboard prefill + hint the built-in credentials (FE-2).
    return {
        "authenticated": valid_session(request.cookies.get("cyberguard_session")),
        "demo_login": _settings.dev_admin_fallback_enabled,
    }


@app.post("/api/auth/logout")
async def admin_logout(request: Request, response: Response) -> dict[str, str]:
    revoke_session(request.cookies.get("cyberguard_session"))
    response.delete_cookie("cyberguard_session", path="/")
    return {"status": "logged_out"}

# Rate limiter must exist before route definitions use `rate_limit_exempt` (C-3).
create_limiter(app, _settings)


# ================================================================
# AUTH DEFENSE MIDDLEWARE
# Enterprise-grade authentication protection (brute-force, credential stuffing, bot mitigation)
# ================================================================

auth_defense_config = AuthDefenseConfig(
    enabled=True,
    protected_routes=[
        "/login", "/signup", "/password-reset", "/api/token",
        "/mfa/challenge", "/mfa/verify", "/password-change",
        "/account-recovery",
        "/analyze_ip",  # Protect ML inference endpoints too
        "/get_user_risk_score",
        "/detect_attack_pattern",
    ],
    excluded_paths=[
        "/health", "/", "/docs", "/openapi.json", "/redoc",
        "/api/v1/security/summary",  # WebMCP read-only endpoints
        "/api/v1/users/suspicious",
        "/api/v1/users/",
        "/api/v1/webmcp/manifest",
    ],
    enable_rate_limiting=True,
    enable_bot_detection=True,
    enable_credential_intel=True,
    enable_step_up=True,
    enable_telemetry=True,
)

create_auth_defense_middleware(app, auth_defense_config)


# ================================================================
# WEBMCP REST BRIDGE (Phase 2)
# Mounts /api/v1/* for webmcp_bridge.js and enables dev CORS
# (localhost:3000 / localhost:5173).
# ================================================================

from cyberguard_api.routes_webmcp import register_webmcp_routes

register_webmcp_routes(app)


# ================================================================
# EDGE MIDDLEWARE (added last -> outermost): body-size cap (M-11),
# security headers (H-4), per-client rate limiting (C-3),
# request-id + structured logging + /metrics (PP-H4).
# ================================================================

install_middleware(app, _settings)
install_observability(app)


# ================================================================
# MODEL PATHS
# ================================================================

MODEL_DIR = os.path.join(
    os.path.dirname(__file__),
    "models"
)


# Login attack model
RF_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "cyberguard_rf_final.pkl"
)

PREPROCESSOR_PATH = os.path.join(
    MODEL_DIR,
    "cyberguard_preprocessor_final.pkl"
)


# Behavioral anomaly model
ISO_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "isolation_forest_model.pkl"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "feature_scaler.pkl"
)


# ================================================================
# GLOBAL MODELS
# ================================================================

rf_model = None
preprocessor = None
iso_forest = None
scaler = None


# ================================================================
# LOAD MODELS (loaded in lifespan)
# ================================================================


# ================================================================
# LOGIN EVENT SCHEMA
# ================================================================

class LoginEvent(BaseModel):

    # Identification
    user_id: str
    ip_address: str

    # Current event
    country: str
    device_type: str
    browser_name_and_version: str
    os_name_and_version: str

    login_hour: int
    login_successful: bool

    # Historical IP features

    ip_total_logins: int
    ip_unique_users: int
    ip_failure_rate: float

    ip_logins_1h: int
    ip_failed_1h: int
    ip_failure_rate_1h: float
    ip_unique_users_1h: int

    ip_logins_24h: int
    ip_failed_24h: int
    ip_failure_rate_24h: float
    ip_unique_users_24h: int

    ip_logins_7d: int
    ip_failed_7d: int
    ip_failure_rate_7d: float
    ip_unique_users_7d: int

    # Historical USER features

    user_prev_logins: int
    user_prev_failed_logins: int
    user_prev_failure_rate: float

    user_prev_unique_ips: int
    user_prev_unique_countries: int
    user_prev_unique_devices: int
    user_prev_unique_asns: int

    user_account_age_days: float

    user_hour_diff: float

    user_device_changed: int

    user_is_first_event: int


# ================================================================
# LOGIN ATTACK RESULT
# ================================================================

class AttackAnalysisResult(BaseModel):

    user_id: str
    ip_address: str

    # Raw model probability of "attack" (0-1), rounded to 4dp.
    attack_score: float

    # Threshold actually applied for `attack_detected` (LOGIN_THRESHOLD env var).
    # Returned so a consumer can re-derive detection at its own boundary.
    threshold: float

    attack_detected: bool

    risk_level: str


# ================================================================
# USER BEHAVIOR INPUT
# ================================================================

class UserBehaviorInput(BaseModel):

    user_id: str

    total_logins: int
    successful_logins: int
    failed_logins: int
    failure_rate: float

    unique_ips: int
    unique_countries: int
    unique_devices: int
    unique_asns: int

    avg_hour_diff: float
    max_hour_diff: float

    device_change_count: int

    account_span_days: float

    logins_per_day: float


# ================================================================
# USER BEHAVIOR RESULT
# ================================================================

class UserBehaviorResult(BaseModel):

    user_id: str

    anomaly_score: float

    is_anomaly: bool


# ================================================================
# NETWORK FLOW INPUT
# ================================================================

class NetworkFlowInput(BaseModel):

    data: dict


# ================================================================
# ROOT
# ================================================================

@app.get("/")
async def root():
    # PP-L3: minimal, no capability/version disclosure to unauthenticated callers.
    return {"status": "online"}


# ================================================================
# HEALTH (liveness) + READINESS (M-9)
# ================================================================
# `/health` is a pure process-liveness probe: it is 200 as long as the event
# loop can answer. `/readyz` is the traffic gate — 503 until every ML artifact
# has loaded and passed its integrity check.

@app.get("/health")
@rate_limit_exempt(app)
async def health():
    # PP-H5: async so a saturated inference pool cannot block liveness.
    return {"status": "ok"}


def _model_readiness() -> dict[str, bool]:
    return {
        "random_forest": rf_model is not None,
        "preprocessor": preprocessor is not None,
        "isolation_forest": iso_forest is not None,
        "scaler": scaler is not None,
        "network_attack_model": network_detector.network_model is not None,
        "bot_specialist_model": network_detector.bot_specialist is not None,
        "network_label_encoder": network_detector.label_encoder is not None,
    }


@app.get("/readyz")
@rate_limit_exempt(app)
async def readyz():
    checks = _model_readiness()
    missing = sorted(name for name, ok in checks.items() if not ok)

    # A-M1: readiness must reflect the telemetry backend too — a healthy-looking
    # model set is useless if /api/v1/users/* and the agent can't reach the store.
    store_ok, store_detail = await _telemetry.check_store_health(timeout=2.0)
    checks["telemetry_store"] = store_ok
    if not store_ok:
        missing.append("telemetry_store")

    if missing:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "missing": sorted(missing),
                "checks": checks,
                "telemetry_store": store_detail,
            },
        )
    return {"status": "ready", "checks": checks, "telemetry_store": store_detail}


# ================================================================
# LOGIN / IP ATTACK DETECTION
# ================================================================

# Exact training feature order for the login RF preprocessor.
_LOGIN_FEATURE_COLS = [
    "login_hour", "Login Successful",
    "Country", "Device Type", "Browser Name and Version", "OS Name and Version",
    "ip_total_logins", "ip_unique_users", "ip_failure_rate",
    "ip_logins_1h", "ip_failed_1h", "ip_failure_rate_1h", "ip_unique_users_1h",
    "ip_logins_24h", "ip_failed_24h", "ip_failure_rate_24h", "ip_unique_users_24h",
    "ip_logins_7d", "ip_failed_7d", "ip_failure_rate_7d", "ip_unique_users_7d",
    "user_prev_logins", "user_prev_failed_logins", "user_prev_failure_rate",
    "user_prev_unique_ips", "user_prev_unique_countries", "user_prev_unique_devices",
    "user_prev_unique_asns", "user_account_age_days", "user_hour_diff",
    "user_device_changed", "user_is_first_event",
]

_LOGIN_RENAME = {
    "country": "Country",
    "device_type": "Device Type",
    "browser_name_and_version": "Browser Name and Version",
    "os_name_and_version": "OS Name and Version",
    "login_successful": "Login Successful",
}


def _score_login_events(events: List[LoginEvent]) -> List[AttackAnalysisResult]:
    """CPU-bound: preprocess + RF predict_proba. Runs in INFERENCE_POOL (PP-H5)."""
    rows = []
    for event in events:
        data = event.model_dump()
        data.pop("user_id")
        data.pop("ip_address")
        rows.append(data)

    df = pd.DataFrame(rows).rename(columns=_LOGIN_RENAME)
    X = df[_LOGIN_FEATURE_COLS]
    X_processed = preprocessor.transform(X)
    attack_scores = rf_model.predict_proba(X_processed)[:, 1]

    threshold = LOGIN_THRESHOLD
    out: List[AttackAnalysisResult] = []
    for event, score in zip(events, attack_scores):
        score = float(score)
        out.append(
            AttackAnalysisResult(
                user_id=event.user_id,
                ip_address=event.ip_address,
                attack_score=round(score, 4),
                threshold=threshold,
                attack_detected=score >= threshold,
                risk_level=risk_bucket(score, threshold),
            )
        )
    return out


@app.post(
    "/analyze_ip",
    response_model=List[AttackAnalysisResult],
    dependencies=[Depends(require_api_key)],
)
async def analyze_ip(events: List[LoginEvent]):
    _reject_bad_batch(events, "login events")
    _require_models(rf_model, preprocessor)
    try:
        return await _run_inference(_score_login_events, events)
    except HTTPException:
        raise
    except Exception as e:
        raise _sanitized_500("login attack analysis", e)


# ================================================================
# BEHAVIORAL ANOMALY DETECTION
# ================================================================

_BEHAVIOUR_FEATURE_COLS = [
    "total_logins", "successful_logins", "failed_logins", "failure_rate",
    "unique_ips", "unique_countries", "unique_devices", "unique_asns",
    "avg_hour_diff", "max_hour_diff", "device_change_count",
    "account_span_days", "logins_per_day",
]


def _score_behaviour(users: List[UserBehaviorInput]) -> List[UserBehaviorResult]:
    """CPU-bound: scale + IsolationForest. Runs in INFERENCE_POOL (PP-H5)."""
    df = pd.DataFrame([u.model_dump() for u in users])
    X = df[_BEHAVIOUR_FEATURE_COLS]
    X_scaled = scaler.transform(X)
    raw_scores = iso_forest.decision_function(X_scaled)
    labels = iso_forest.predict(X_scaled)
    return [
        UserBehaviorResult(
            user_id=user.user_id,
            anomaly_score=round(float(-raw_score), 4),  # higher = more anomalous
            is_anomaly=(label == -1),
        )
        for user, raw_score, label in zip(users, raw_scores, labels)
    ]


@app.post(
    "/get_user_risk_score",
    response_model=List[UserBehaviorResult],
    dependencies=[Depends(require_api_key)],
)
async def get_user_risk_score(users: List[UserBehaviorInput]):
    _reject_bad_batch(users, "users")
    _require_models(iso_forest, scaler)
    try:
        return await _run_inference(_score_behaviour, users)
    except HTTPException:
        raise
    except Exception as e:
        raise _sanitized_500("behavioural anomaly analysis", e)


# ================================================================
# NETWORK ATTACK DETECTION
# ================================================================

@app.post("/detect_attack_pattern", dependencies=[Depends(require_api_key)])
async def detect_attack_pattern_endpoint(request: NetworkFlowInput):
    try:
        result = await _run_inference(detect_network_attack, request.data)
        return {"status": "success", "result": result}

    except HTTPException:
        raise

    except ValueError as e:
        # Strict schema validation rejected the payload (M-11): malformed,
        # non-numeric, non-finite, or missing features. Caller-supplied
        # validation feedback, not internal state.
        raise HTTPException(status_code=422, detail=str(e))

    except (ModelIntegrityError, RuntimeError) as e:
        logger.warning("network models unavailable: %s", e)
        raise HTTPException(status_code=503, detail=_MODELS_UNAVAILABLE_DETAIL)

    except Exception as e:
        raise _sanitized_500("network attack detection", e)


# ================================================================
# RISK BUCKET
# ================================================================

def risk_bucket(
    score: float,
    threshold: float = 0.70,
) -> str:
    """Bucket a raw score relative to the applied operating threshold (M-10)."""

    if score >= threshold:

        return "high"

    elif score >= threshold * 0.8:

        return "medium"

    return "low"


# ================================================================
# CONTAINER / PaaS ENTRYPOINT
# ================================================================
# Preferred invocation stays `uvicorn cyberguard_api.main:app` (Dockerfile CMD,
# scripts/run.sh, render.yaml, Procfile). This block only adds a fallback so
# `python -m cyberguard_api.main` also works, binding 0.0.0.0 and reading the
# platform-assigned $PORT (Render / Railway / Heroku) with an 8000 default.

def _run() -> None:
    import uvicorn

    uvicorn.run(
        "cyberguard_api.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "*"),
        access_log=False,
    )


if __name__ == "__main__":
    _run()