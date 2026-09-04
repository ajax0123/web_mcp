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

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List

import pandas as pd
import joblib
import os
import sys

# Ensure repository root is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cyberguard_api.services.network_detector import detect_network_attack


# ================================================================
# APPLICATION
# ================================================================

app = FastAPI(
    title="CyberGuard ML Scoring API",
    description=(
        "Cybersecurity ML API for login attack detection, "
        "network attack classification, and behavioral anomaly detection."
    ),
    version="1.1.0",
)


# ================================================================
# WEBMCP REST BRIDGE (Phase 2)
# Mounts /api/v1/* for webmcp_bridge.js and enables dev CORS
# (localhost:3000 / localhost:5173).
# ================================================================

from cyberguard_api.routes_webmcp import register_webmcp_routes

register_webmcp_routes(app)


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
# LOAD MODELS
# ================================================================

@app.on_event("startup")
def load_models():

    global rf_model
    global preprocessor
    global iso_forest
    global scaler

    try:

        # --------------------------------------------------------
        # LOGIN RANDOM FOREST
        # --------------------------------------------------------

        rf_model = joblib.load(
            RF_MODEL_PATH
        )

        # --------------------------------------------------------
        # LOGIN PREPROCESSOR
        # --------------------------------------------------------

        preprocessor = joblib.load(
            PREPROCESSOR_PATH
        )

        # --------------------------------------------------------
        # ISOLATION FOREST
        # --------------------------------------------------------

        iso_forest = joblib.load(
            ISO_MODEL_PATH
        )

        # --------------------------------------------------------
        # BEHAVIOR SCALER
        # --------------------------------------------------------

        scaler = joblib.load(
            SCALER_PATH
        )

        print("========================================")
        print("CyberGuard models loaded successfully")
        print("========================================")

        print(
            f"RF model: {type(rf_model).__name__}"
        )

        print(
            f"Preprocessor: {type(preprocessor).__name__}"
        )

        print(
            f"Isolation Forest: {type(iso_forest).__name__}"
        )

        print(
            f"Scaler: {type(scaler).__name__}"
        )

        print("========================================")

    except Exception as e:

        print("========================================")
        print("MODEL LOADING ERROR")
        print("========================================")
        print(str(e))

        raise


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

    attack_score: float

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
def root():

    return {
        "service": "CyberGuard ML Scoring API",
        "version": "1.1.0",
        "status": "online",
        "capabilities": [
            "login_attack_detection",
            "behavioral_anomaly_detection",
            "network_attack_detection"
        ]
    }


# ================================================================
# HEALTH
# ================================================================

@app.get("/health")
def health():

    return {
        "status": "ok",

        "models_loaded": {

            "random_forest": (
                rf_model is not None
            ),

            "preprocessor": (
                preprocessor is not None
            ),

            "isolation_forest": (
                iso_forest is not None
            ),

            "scaler": (
                scaler is not None
            )
        }
    }


# ================================================================
# LOGIN / IP ATTACK DETECTION
# ================================================================

@app.post(
    "/analyze_ip",
    response_model=List[AttackAnalysisResult]
)
def analyze_ip(events: List[LoginEvent]):

    if not events:

        raise HTTPException(
            status_code=400,
            detail="No login events provided"
        )

    try:

        # --------------------------------------------------------
        # Convert request → DataFrame
        # --------------------------------------------------------

        rows = []

        for event in events:

            data = event.model_dump()

            # Remove API-only identification fields
            data.pop("user_id")
            data.pop("ip_address")

            rows.append(data)

        df = pd.DataFrame(rows)

        # --------------------------------------------------------
        # EXACT TRAINING FEATURE ORDER
        # --------------------------------------------------------

        feature_cols = [

            "login_hour",
            "Login Successful",

            "Country",
            "Device Type",
            "Browser Name and Version",
            "OS Name and Version",

            # IP history
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

            # User history
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
            "user_is_first_event"
        ]

        # --------------------------------------------------------
        # Rename API fields → training fields
        # --------------------------------------------------------

        df = df.rename(
            columns={

                "country":
                    "Country",

                "device_type":
                    "Device Type",

                "browser_name_and_version":
                    "Browser Name and Version",

                "os_name_and_version":
                    "OS Name and Version",

                "login_successful":
                    "Login Successful"
            }
        )

        X = df[feature_cols]

        # --------------------------------------------------------
        # PREPROCESS
        # --------------------------------------------------------

        X_processed = preprocessor.transform(X)

        # --------------------------------------------------------
        # RANDOM FOREST
        # --------------------------------------------------------

        attack_scores = rf_model.predict_proba(
            X_processed
        )[:, 1]

        # --------------------------------------------------------
        # DEVELOPMENT THRESHOLD
        # --------------------------------------------------------

        THRESHOLD = 0.55

        results = []

        for event, score in zip(
            events,
            attack_scores
        ):

            score = float(score)

            detected = (
                score >= THRESHOLD
            )

            results.append(
                AttackAnalysisResult(

                    user_id=event.user_id,

                    ip_address=event.ip_address,

                    attack_score=round(
                        score,
                        4
                    ),

                    attack_detected=detected,

                    risk_level=risk_bucket(
                        score
                    )
                )
            )

        return results

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Attack analysis failed: {str(e)}"
            )
        )


# ================================================================
# BEHAVIORAL ANOMALY DETECTION
# ================================================================

@app.post(
    "/get_user_risk_score",
    response_model=List[UserBehaviorResult]
)
def get_user_risk_score(
    users: List[UserBehaviorInput]
):

    if not users:

        raise HTTPException(
            status_code=400,
            detail="No users provided"
        )

    try:

        feature_cols = [

            "total_logins",
            "successful_logins",
            "failed_logins",
            "failure_rate",

            "unique_ips",
            "unique_countries",
            "unique_devices",
            "unique_asns",

            "avg_hour_diff",
            "max_hour_diff",

            "device_change_count",

            "account_span_days",

            "logins_per_day"
        ]

        # --------------------------------------------------------
        # Convert request → DataFrame
        # --------------------------------------------------------

        rows = [
            user.model_dump()
            for user in users
        ]

        df = pd.DataFrame(rows)

        X = df[feature_cols]

        # --------------------------------------------------------
        # SCALE
        # --------------------------------------------------------

        X_scaled = scaler.transform(
            X
        )

        # --------------------------------------------------------
        # ISOLATION FOREST
        # --------------------------------------------------------

        raw_scores = iso_forest.decision_function(
            X_scaled
        )

        labels = iso_forest.predict(
            X_scaled
        )

        results = []

        for user, raw_score, label in zip(
            users,
            raw_scores,
            labels
        ):

            results.append(
                UserBehaviorResult(

                    user_id=user.user_id,

                    # Higher = more anomalous
                    anomaly_score=round(
                        float(-raw_score),
                        4
                    ),

                    is_anomaly=(
                        label == -1
                    )
                )
            )

        return results

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Behavior analysis failed: {str(e)}"
            )
        )


# ================================================================
# NETWORK ATTACK DETECTION
# ================================================================

@app.post("/detect_attack_pattern")
def detect_attack_pattern_endpoint(
    request: NetworkFlowInput
):

    try:

        result = detect_network_attack(
            request.data
        )

        return {

            "status": "success",

            "result": result
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Network attack detection failed: "
                f"{str(e)}"
            )
        )


# ================================================================
# RISK BUCKET
# ================================================================

def risk_bucket(
    score: float
) -> str:

    if score >= 0.70:

        return "high"

    elif score >= 0.55:

        return "medium"

    return "low"