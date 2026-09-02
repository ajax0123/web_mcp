"""
CyberGuard ML Scoring API
Wraps the trained Isolation Forest (behavioral anomaly) and Random Forest
(attack-IP classification) models behind a FastAPI service.

Run with: uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
import pandas as pd
import numpy as np
import joblib
import os

app = FastAPI(title="CyberGuard ML Scoring API", version="0.1.0")

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

# ---- Load models once at startup ----
rf_model = None
iso_forest = None
scaler = None
encoders = None

@app.on_event("startup")
def load_models():
    global rf_model, iso_forest, scaler, encoders
    rf_model = joblib.load(os.path.join(MODEL_DIR, "rf_attack_ip_model.pkl"))
    iso_forest = joblib.load(os.path.join(MODEL_DIR, "isolation_forest_model.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "feature_scaler.pkl"))
    encoders = joblib.load(os.path.join(MODEL_DIR, "label_encoders.pkl"))
    print("Models loaded successfully")


# ==================================================================
# Schemas
# ==================================================================

class LoginEvent(BaseModel):
    """A single raw login event, as it would come from your app's logs."""
    user_id: str
    ip_address: str
    country: str
    device_type: str
    browser: str = Field(..., alias="browser_name_and_version")
    os: str = Field(..., alias="os_name_and_version")
    login_hour: int
    login_successful: bool
    # Precomputed per-IP behavioral stats (your backend/DB should supply these
    # from recent log aggregation - see note at bottom of file)
    ip_total_logins: int
    ip_unique_users: int
    ip_failure_rate: float
    # Optional: how many hours off this user's typical login hour this is
    hour_diff: Optional[float] = 0.0

    class Config:
        populate_by_name = True


class IPAnalysisResult(BaseModel):
    ip_address: str
    user_id: str
    attack_probability: float
    risk_level: str


class UserBehaviorInput(BaseModel):
    """Aggregated behavioral stats for a user, computed over some time window."""
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


class UserRiskResult(BaseModel):
    user_id: str
    anomaly_score: float          # normalized 0-1, higher = more anomalous
    is_anomaly: bool
    risk_score: int                # combined 0-100 score


# ==================================================================
# Endpoints
# ==================================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "models_loaded": all([rf_model, iso_forest, scaler, encoders])
    }


@app.post("/analyze_ip", response_model=List[IPAnalysisResult])
def analyze_ip(events: List[LoginEvent]):
    """
    Batch-score login events for attack-IP likelihood using the Random Forest model.
    Maps to the analyze_ip() WebMCP tool in the project spec.
    """
    if not events:
        raise HTTPException(status_code=400, detail="No login events provided")

    try:
        df = pd.DataFrame([e.dict(by_alias=False) for e in events])

        # Encode categoricals using the SAME encoders from training
        df["Country_enc"] = safe_encode(encoders["Country"], df["country"])
        df["Device Type_enc"] = safe_encode(encoders["Device Type"], df["device_type"])
        df["Browser Name and Version_enc"] = safe_encode(encoders["Browser Name and Version"], df["browser"])
        df["OS Name and Version_enc"] = safe_encode(encoders["OS Name and Version"], df["os"])

        feature_cols = [
            "Country_enc", "Device Type_enc", "Browser Name and Version_enc",
            "OS Name and Version_enc", "login_hour", "login_successful", "hour_diff",
            "ip_total_logins", "ip_unique_users", "ip_failure_rate"
        ]
        X = df[feature_cols].rename(columns={"login_successful": "Login Successful"})
        X = X[["Country_enc", "Device Type_enc", "Browser Name and Version_enc",
               "OS Name and Version_enc", "login_hour", "Login Successful", "hour_diff",
               "ip_total_logins", "ip_unique_users", "ip_failure_rate"]]

        probabilities = rf_model.predict_proba(X)[:, 1]

        results = []
        for event, proba in zip(events, probabilities):
            results.append(IPAnalysisResult(
                ip_address=event.ip_address,
                user_id=event.user_id,
                attack_probability=round(float(proba), 4),
                risk_level=risk_bucket(proba)
            ))
        return results

    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing or invalid field: {e}")


@app.post("/get_user_risk_score", response_model=List[UserRiskResult])
def get_user_risk_score(users: List[UserBehaviorInput]):
    """
    Batch-score users for behavioral anomaly using the Isolation Forest model,
    and combine into a 0-100 risk score.
    Maps to the get_user_risk_score() WebMCP tool in the project spec.
    """
    if not users:
        raise HTTPException(status_code=400, detail="No users provided")

    feature_cols = [
        "total_logins", "successful_logins", "failed_logins", "failure_rate",
        "unique_ips", "unique_countries", "unique_devices", "unique_asns",
        "avg_hour_diff", "max_hour_diff", "device_change_count",
        "account_span_days", "logins_per_day"
    ]

    df = pd.DataFrame([u.dict() for u in users])
    X = df[feature_cols]
    X_scaled = scaler.transform(X)

    raw_scores = iso_forest.decision_function(X_scaled)   # lower = more anomalous
    labels = iso_forest.predict(X_scaled)                  # -1 = anomaly, 1 = normal

    # IMPORTANT: normalize against a FIXED reference range, not the batch's own
    # min/max. Per-batch min-max would make a user's risk score depend on who
    # else happened to be in the same request - e.g. two genuinely risky users
    # sent together would still show one of them as "0 risk" purely because
    # they were the less-bad of the two. That's a real bug, not a style choice.
    #
    # ANOMALY_SCORE_MIN/MAX below should be set from your TRAINING data's
    # decision_function range (compute once after training, e.g.:
    #   train_scores = iso_forest.decision_function(X_train_scaled)
    #   ANOMALY_SCORE_MIN, ANOMALY_SCORE_MAX = train_scores.min(), train_scores.max()
    # and hardcode them here, or save/load them alongside the model .pkl files.
    ANOMALY_SCORE_MIN = -0.2   # placeholder - replace with your real training range
    ANOMALY_SCORE_MAX = 0.25   # placeholder - replace with your real training range

    norm = (ANOMALY_SCORE_MAX - raw_scores) / (ANOMALY_SCORE_MAX - ANOMALY_SCORE_MIN + 1e-9)
    norm = np.clip(norm, 0, 1)

    results = []
    for user, score, label in zip(users, norm, labels):
        results.append(UserRiskResult(
            user_id=user.user_id,
            anomaly_score=round(float(score), 4),
            is_anomaly=(label == -1),
            risk_score=int(round(float(score) * 100))
        ))
    return results


# ==================================================================
# Helpers
# ==================================================================

def safe_encode(encoder, series: pd.Series) -> pd.Series:
    """
    LabelEncoder throws on unseen categories. Map unseen values to -1
    instead of crashing the whole batch request.
    """
    known = set(encoder.classes_)
    mapped = series.astype(str).apply(lambda x: x if x in known else None)
    result = pd.Series(-1, index=series.index)
    mask = mapped.notna()
    if mask.any():
        result.loc[mask] = encoder.transform(mapped.loc[mask])
    return result


def risk_bucket(proba: float) -> str:
    if proba >= 0.7:
        return "high"
    elif proba >= 0.4:
        return "medium"
    return "low"


# NOTE on ip_total_logins / ip_unique_users / ip_failure_rate:
# These are the per-IP behavioral aggregates we engineered in the notebook
# (Cell 8-9 of feature engineering). In production, your backend/DB layer
# (Person 4) needs to compute these from a rolling window of recent logs
# (e.g., last 24-72h) before calling this API - this service does NOT
# compute them itself, it only scores pre-aggregated features.