# cyberguard_mcp_server.py
# ============================================================================
# CyberGuard SOC — MCP stdio server.
#
# Thin @mcp.tool() wrappers over cyberguard_api.services.telemetry — the SAME
# shared module the REST surface (routes_webmcp.py) and the autonomous agent
# (agent_controller.py) use (L-7). So a user record is masked identically on
# every transport (M-6) and the classification / risk scoring is one
# deterministic function of the telemetry (H-1 / L-3).
#
# Tool contracts (PP-M2 / PP-L6):
#   * `severity` is a Literal enum — identical to the REST IncidentRequest.
#   * `recommendations` is bounded: 1-25 items, <= 500 chars each.
#   * A missing entity raises a FastMCP ToolError (falls back to
#     `{"ok": false, "error": ...}`) so a consumer LLM can tell "not found"
#     apart from a successful telemetry payload.
#
# SAFETY: analytical only. `generate_incident_report` records recommendations;
# it never executes remediation.
# ============================================================================
import os
from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import Field, StringConstraints

try:  # FastMCP >= 2 exposes a first-class tool error
    from fastmcp.exceptions import ToolError as _ToolError
except Exception:  # pragma: no cover - older/newer layout
    class _ToolError(Exception):
        pass

from cyberguard_api.services.telemetry import (
    classify_pattern as _classify_pattern,
    generate_incident_report as _generate_incident_report,
    get_user as _get_user,
    project_user as _project_user,
    risk_score as _risk_score,
    security_summary as _security_summary,
    suspicious_users as _suspicious_users,
)

try:
    from cyberguard_api.services.model_loader import MODEL_DIR
except Exception:  # pragma: no cover - import-environment fallback
    MODEL_DIR = os.path.join(os.path.dirname(__file__), "cyberguard_api", "models")

_GROUNDED_CLASSIFIER = "cyberguard_api.services.telemetry.classify_pattern"

# Shared with routes_webmcp.IncidentRequest.
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Recommendation = Annotated[str, StringConstraints(min_length=3, max_length=500)]

mcp = FastMCP("CyberGuard-SOC-Server")


def _not_found(user_id: str, what: str = "user"):
    """Protocol-compliant 'missing entity' signal (PP-L6)."""
    msg = f"{what} {user_id} not found in current telemetry log"
    try:
        raise _ToolError(msg)
    except TypeError:  # pragma: no cover - stub signature mismatch
        return {"ok": False, "error": msg}


@mcp.tool()
def get_security_summary() -> dict:
    """Returns high-level summary counts of anomalies, active alerts, and flagged entities."""
    return _security_summary()


@mcp.tool()
def get_suspicious_users(
    limit: Annotated[int, Field(ge=1, le=100)] = 5,
) -> list:
    """Users ranked by anomaly detection score. Usernames and source IPs are masked (M-6)."""
    return [_project_user(u) for u in _suspicious_users(limit)]


@mcp.tool()
def investigate_user(user_id: str) -> dict:
    """Authentication telemetry for a user. Usernames and IPs are masked (M-6).

    Raises a ToolError when the user is absent (PP-L6) — a masked record and a
    missing record are never both plain dicts.
    """
    user = _get_user(user_id)
    if user is None:
        return _not_found(user_id)
    return _project_user(user)


@mcp.tool()
def get_user_risk_score(user_id: str) -> dict:
    """
    Normalized 0-100 risk score plus contributing factors.

    Every factor is derived from an observed telemetry field — an impossible-travel
    line appears only when `geo_velocity_violation` is set on the record (H-1).
    Raises a ToolError for an unknown user (PP-L6).
    """
    user = _get_user(user_id)
    if user is None:
        return _not_found(user_id)
    return _risk_score(user_id)


@mcp.tool()
def detect_attack_pattern(user_id: str) -> dict:
    """
    Classify the user's authentication activity from real telemetry counters.

    The verdict is derived from this user's failed/successful login counts,
    distinct source IPs, device changes and anomaly score — every value is echoed
    back under `evidence`. No 32-feature login vector is available at this call
    site, so the login Random Forest is not run; `inference_mode` reports which
    path produced the result ("heuristic").
    """
    user = _get_user(user_id)
    if user is None:
        return _not_found(user_id)

    result = dict(_classify_pattern(user))
    result["user_id"] = user_id
    result.setdefault("inference_mode", "heuristic")
    result["classifier"] = _GROUNDED_CLASSIFIER
    return result


@mcp.tool()
def generate_incident_report(
    user_id: str,
    threat_type: Annotated[str, StringConstraints(min_length=2, max_length=120)],
    severity: Severity,
    recommendations: Annotated[list[Recommendation], Field(min_length=1, max_length=25)],
) -> dict:
    """Generate an official SOC incident ID and record the containment recommendations.

    `severity` is a fixed enum and `recommendations` is bounded (1-25 items,
    <= 500 chars each) — identical to the REST /api/v1/reports/incident contract.
    """
    return _generate_incident_report(user_id, threat_type, severity, list(recommendations))


if __name__ == "__main__":
    mcp.run()
