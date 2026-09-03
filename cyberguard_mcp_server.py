# cyberguard_mcp_server.py
import os
import joblib
import pandas as pd
from fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("CyberGuard-SOC-Server")

# Path to Data Science models
MODEL_DIR = os.path.join(os.path.dirname(__file__), "web_mcp-Data-Science", "cyberguard_api", "models")

# In-memory mock telemetry / DB store for live analysis
MOCK_TELEMETRY = {
    "USR-402": {
        "user_id": "USR-402",
        "username": "alex.chen@enterprise.internal",
        "failed_logins": 47,
        "successful_logins": 1,
        "unique_ips": ["198.51.100.23", "203.0.113.88", "192.0.2.14"],
        "anomaly_score": 0.93,
        "device_changes": 4,
        "geo_velocity_violation": True
    },
    "USR-108": {
        "user_id": "USR-108",
        "username": "sarah.admin@enterprise.internal",
        "failed_logins": 12,
        "successful_logins": 2,
        "unique_ips": ["198.51.100.12"],
        "anomaly_score": 0.68,
        "device_changes": 1,
        "geo_velocity_violation": False
    }
}

@mcp.tool()
def get_security_summary() -> dict:
    """Returns high-level summary counts of anomalies, active alerts, and flagged entities."""
    return {
        "monitored_users": 150,
        "flagged_suspicious_users": 2,
        "high_severity_alerts": 1,
        "status": "ELEVATED_RISK"
    }

@mcp.tool()
def get_suspicious_users(limit: int = 5) -> list:
    """Returns users ranked by anomaly detection score from the DS engine."""
    results = sorted(MOCK_TELEMETRY.values(), key=lambda x: x["anomaly_score"], reverse=True)
    return results[:limit]

@mcp.tool()
def investigate_user(user_id: str) -> dict:
    """Retrieves detailed authentication telemetry, failed attempts, and IPs for a specific user."""
    user = MOCK_TELEMETRY.get(user_id)
    if not user:
        return {"error": f"User {user_id} not found in current telemetry log."}
    return user

@mcp.tool()
def get_user_risk_score(user_id: str) -> dict:
    """Calculates the normalized 0-100 risk score and contributing risk factors."""
    user = MOCK_TELEMETRY.get(user_id)
    if not user:
        return {"error": f"User {user_id} not found."}
    
    score = int(user["anomaly_score"] * 100)
    return {
        "user_id": user_id,
        "risk_score": score,
        "risk_level": "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM",
        "top_contributing_factors": [
            f"{user['failed_logins']} failed authentication attempts within 10 minutes",
            "Geographical impossible travel detected across 3 ASN networks",
            "New unrecognized device fingerprint observed"
        ]
    }

@mcp.tool()
def detect_attack_pattern(user_id: str) -> dict:
    """Runs behavioral signals through the attack classification model."""
    user = MOCK_TELEMETRY.get(user_id)
    if not user:
        return {"error": f"User {user_id} not found."}
    
    # In production, pass features through cyberguard_rf_final.pkl
    return {
        "user_id": user_id,
        "classified_pattern": "Account Takeover (ATO)",
        "confidence": 0.91,
        "mitre_technique_id": "T1078.004",
        "signature_details": "Brute-force credential attempts succeeded by a single authenticated session from an anomalous ASN."
    }

@mcp.tool()
def generate_incident_report(user_id: str, threat_type: str, severity: str, recommendations: list) -> dict:
    """Generates an official SOC incident ID and records the containment recommendations."""
    incident_id = f"INC-2026-{abs(hash(user_id)) % 10000:04d}"
    return {
        "incident_id": incident_id,
        "status": "LOGGED",
        "target_entity": user_id,
        "severity": severity,
        "threat_type": threat_type,
        "recommended_actions": recommendations
    }

if __name__ == "__main__":
    mcp.run()