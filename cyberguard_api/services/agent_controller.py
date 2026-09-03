"""
agent_controller.py
================================================================================
Phase 3 — Autonomous Agent Investigation Loop.

`run_autonomous_investigation()` drives the full CyberGuard SOC lifecycle with no
human in the loop:

    a. TRIAGE        get_security_summary() + get_suspicious_users(limit=3)
                     -> pick the highest anomaly_score  (skipped if a target is given)
    b. DEEP-DIVE     investigate_user(user_id) -> get_user_risk_score(user_id)
    c. ATTRIBUTION   detect_attack_pattern(user_id)
                     -> classified pattern, confidence, MITRE ATT&CK technique
    d. REGISTRATION  generate_incident_report(user_id, threat_type, severity, recs)
                     -> consolidated JSON + Markdown report + full audit trace

The six "tools" are the pure helper functions in cyberguard_api.routes_webmcp
(same logic the REST surface and the MCP server expose). Every call is appended
to `audit_trace` so the run is fully replayable.

SAFETY: analytical only. Recommendations are non-destructive and flagged for
human authorisation; nothing here mutates accounts, sessions, or infrastructure.
================================================================================
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cyberguard_api import routes_webmcp as rw

__all__ = ["run_autonomous_investigation"]


# ============================================================================
# Orchestrator
# ============================================================================

async def run_autonomous_investigation(target_user_id: str | None = None) -> dict:
    """
    Run the end-to-end investigation pipeline.

    Args:
        target_user_id: investigate this user directly. If None, auto-select the
            worst offender via triage.

    Returns:
        Consolidated assessment dict: status, target, triage, telemetry,
        risk_score, attack_attribution, incident, recommended_actions,
        markdown_report, and the step-by-step audit_trace.
    """
    trace: list[dict[str, Any]] = []

    def record(step: int, tool: str, tool_input: dict[str, Any], output: Any) -> None:
        trace.append(
            {
                "step": step,
                "tool": tool,
                "input": tool_input,
                "output": output,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        )

    # ---- a. TRIAGE ---------------------------------------------------------
    security_summary: dict[str, Any] | None = None
    candidates: list[dict[str, Any]] | None = None

    if target_user_id:
        user_id = target_user_id
        selection_reason = "explicit target supplied by caller"
    else:
        security_summary = rw._security_summary()
        record(1, "get_security_summary", {}, security_summary)

        candidates = rw._suspicious_users(limit=3)
        record(2, "get_suspicious_users", {"limit": 3}, candidates)

        if not candidates:
            return {
                "status": "NO_TARGETS",
                "message": "Triage returned no suspicious users.",
                "triage": {"security_summary": security_summary, "candidates": []},
                "audit_trace": trace,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

        top = max(candidates, key=lambda u: u.get("anomaly_score", 0))
        user_id = top["user_id"]
        selection_reason = (
            f"highest anomaly_score among {len(candidates)} triaged users "
            f"({top.get('anomaly_score')})"
        )

    # ---- guard: target must exist in telemetry ---------------------------
    if user_id not in rw.MOCK_TELEMETRY:
        return {
            "status": "TARGET_NOT_FOUND",
            "target_user_id": user_id,
            "message": f"User {user_id} not present in telemetry store.",
            "triage": {"security_summary": security_summary, "candidates": candidates},
            "audit_trace": trace,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ---- b. DEEP-DIVE TELEMETRY -----------------------------------------
    telemetry = rw._get_user_or_404(user_id)
    record(3, "investigate_user", {"user_id": user_id}, telemetry)

    risk = rw._risk_score(user_id)
    record(4, "get_user_risk_score", {"user_id": user_id}, risk)

    # ---- c. ML ATTRIBUTION --------------------------------------------
    attack = rw._heuristic_pattern(user_id)
    record(5, "detect_attack_pattern", {"user_id": user_id}, attack)

    # ---- d. REPORT REGISTRATION -------------------------------------
    threat_type = attack["classified_pattern"]
    severity = _severity_from(risk, attack)
    recommendations = _recommendations(attack, risk, telemetry)

    incident = rw._generate_incident_report(
        user_id, threat_type, severity, recommendations
    )
    record(
        6,
        "generate_incident_report",
        {
            "user_id": user_id,
            "threat_type": threat_type,
            "severity": severity,
            "recommendations": recommendations,
        },
        incident,
    )

    markdown_report = _render_markdown(
        user_id, telemetry, risk, attack, incident
    )

    return {
        "status": "COMPLETE",
        "target_user_id": user_id,
        "auto_selected": target_user_id is None,
        "selection_reason": selection_reason,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assessment": {
            "threat_classification": threat_type,
            "severity": severity,
            "confidence": attack.get("confidence"),
            "confidence_pct": round(float(attack.get("confidence", 0)) * 100),
            "mitre_technique_id": attack.get("mitre_technique_id"),
            "attack_detected": attack.get("attack_detected"),
            "risk_score": risk.get("risk_score"),
        },
        "triage": {"security_summary": security_summary, "candidates": candidates},
        "telemetry": telemetry,
        "risk_score": risk,
        "attack_attribution": attack,
        "incident": incident,
        "recommended_actions": recommendations,
        "markdown_report": markdown_report,
        "audit_trace": trace,
    }


# ============================================================================
# Helpers
# ============================================================================

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _severity_from(risk: dict[str, Any], attack: dict[str, Any]) -> str:
    """Take the risk model's level, but never downgrade a detected attack below HIGH."""
    level = str(risk.get("risk_level", "MEDIUM")).upper()
    if level not in _SEVERITY_ORDER:
        level = "MEDIUM"
    if attack.get("attack_detected") and _SEVERITY_ORDER.index(level) < _SEVERITY_ORDER.index("HIGH"):
        level = "HIGH"
    return level


def _recommendations(
    attack: dict[str, Any], risk: dict[str, Any], telemetry: dict[str, Any]
) -> list[str]:
    """Non-destructive, human-authorised next steps keyed to the attack pattern."""
    pattern = str(attack.get("classified_pattern", ""))
    recs: list[str] = []

    if "Account Takeover" in pattern:
        recs += [
            "Recommend SOC Admin invalidate all active sessions for the account and force step-up re-authentication",
            "Recommend SOC Admin trigger MFA / 2FA credential reset",
            "Quarantine and forensically image the new device fingerprints before trust is re-granted",
            "Hunt the successful session for mailbox rules, OAuth/app-consent grants, and lateral movement",
        ]
    elif "Brute Force" in pattern:
        recs += [
            "Apply source-IP rate limiting / temporary block on the authentication endpoint",
            "Recommend SOC Admin review account lockout thresholds for the targeted account",
        ]
    elif "Credential Stuffing" in pattern:
        recs += [
            "Enable breached-password / credential-stuffing detection on the login flow",
            "Rate-limit authentication per source IP CIDR and require CAPTCHA on anomaly",
        ]
    else:
        recs += [
            "Maintain enhanced monitoring; escalate if the anomaly score rises or a successful login follows",
        ]

    if telemetry.get("geo_velocity_violation"):
        recs.append("Enforce conditional access blocking unapproved ASNs and impossible-travel geo pairs")
    if risk.get("risk_score", 0) >= 80:
        recs.insert(0, "Page the on-call SOC lead — risk score is CRITICAL")

    return recs


def _narrative(telemetry: dict[str, Any], attack: dict[str, Any]) -> str:
    failed = telemetry.get("failed_logins", 0)
    success = telemetry.get("successful_logins", 0)
    ips = telemetry.get("unique_ips", []) or []
    steps = [
        f"1. {failed} failed authentication attempts recorded against the account in a short window "
        f"— consistent with automated credential guessing.",
        f"2. Attempts originate from {len(ips)} distinct source IP(s): {', '.join(ips) or 'n/a'}"
        + ("; geo-velocity violation flagged (impossible travel)." if telemetry.get("geo_velocity_violation") else "."),
    ]
    if success:
        steps.append(
            f"3. {success} authentication(s) SUCCEEDED during the burst — credentials are compromised; "
            f"the resulting session is treated as attacker-controlled."
        )
    if telemetry.get("device_changes"):
        steps.append(
            f"4. {telemetry['device_changes']} device change(s) / a new unrecognised fingerprint observed "
            f"— access is from hardware not previously associated with the user."
        )
    steps.append(
        f"5. Classifier attribution: {attack.get('classified_pattern')} "
        f"(MITRE {attack.get('mitre_technique_id') or 'n/a'}, "
        f"{round(float(attack.get('confidence', 0)) * 100)}% confidence). "
        f"{attack.get('signature_details', '')}"
    )
    return "\n".join(steps)


def _render_markdown(
    user_id: str,
    telemetry: dict[str, Any],
    risk: dict[str, Any],
    attack: dict[str, Any],
    incident: dict[str, Any],
) -> str:
    anomaly = telemetry.get("anomaly_score", 0)
    ips = telemetry.get("unique_ips", []) or []
    factors = risk.get("top_contributing_factors", []) or []
    lines = [
        f"# INCIDENT REPORT: {incident['incident_id']} / {user_id}",
        "",
        "## 1. Executive Summary",
        f"- Threat Classification: {attack.get('classified_pattern')}",
        f"- Severity Level: {incident.get('severity')}",
        f"- Confidence Score: {round(float(attack.get('confidence', 0)) * 100)}%",
        f"- MITRE ATT&CK: {attack.get('mitre_technique_id') or 'n/a'}",
        f"- Investigation Verdict: {attack.get('signature_details', '')}",
        "",
        "## 2. Telemetry & Machine Learning Evidence",
        "| Indicator | Observed Value | Risk Assessment |",
        "| :--- | :--- | :--- |",
        f"| Anomaly Score | {anomaly} | {'High' if anomaly >= 0.8 else 'Elevated' if anomaly >= 0.5 else 'Low'} deviation |",
        f"| Risk Score (0-100) | {risk.get('risk_score')} ({risk.get('risk_level')}) | {factors[0] if factors else 'n/a'} |",
        f"| Failed vs Successful Logins | {telemetry.get('failed_logins')} / {telemetry.get('successful_logins')} | "
        f"{'Compromise confirmed' if telemetry.get('successful_logins', 0) >= 1 and telemetry.get('failed_logins', 0) >= 10 else 'Attack in progress'} |",
        f"| Unique Source IPs | {len(ips)} — {', '.join(ips) or 'n/a'} | "
        f"{'Impossible travel / multi-ASN' if telemetry.get('geo_velocity_violation') else 'Single origin'} |",
        f"| Device Changes | {telemetry.get('device_changes')} | "
        f"{'New unrecognised fingerprint' if telemetry.get('device_changes', 0) > 0 else 'Stable'} |",
        "",
        "## 3. Threat Narrative & Attack Vector",
        _narrative(telemetry, attack),
        "",
        "## 4. Recommended Mitigations (Non-Destructive)",
    ]
    for i, rec in enumerate(incident.get("recommended_actions", []), start=1):
        lines.append(f"{i}. {rec}")
    lines += [
        "",
        f"_Incident {incident['incident_id']} status: {incident.get('status')}. "
        f"Generated autonomously by CyberGuard agent_controller — analytical only, "
        f"no remediation executed._",
    ]
    return "\n".join(lines)
