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

The six "tools" are the pure helper functions in
cyberguard_api.services.telemetry (the same functions the REST surface and the
MCP server expose). Every call is appended to `audit_trace` so the run is fully
replayable, and every user record is masked via `project_user()` before it is
recorded or returned (C-5 / M-6).

SAFETY: analytical only. Recommendations are non-destructive and flagged for
human authorisation; nothing here mutates accounts, sessions, or infrastructure.
================================================================================
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

# Shared telemetry store + pure helpers (L-7). Same functions the REST surface
# and the MCP server use, so PII masking + scoring are identical everywhere.
from cyberguard_api.services import telemetry as tele
from cyberguard_api.observability import current_request_id, new_correlation_id

__all__ = ["run_autonomous_investigation"]

_LOG = logging.getLogger("cyberguard.agent")


# ============================================================================
# Orchestrator
# ============================================================================

async def run_autonomous_investigation(target_user_id: str | None = None) -> dict:
    """
    Top-level error boundary around the investigation pipeline (PP-M8).

    On any failure this returns a structured ``{"status": "ERROR", ...}`` payload
    with a ``correlation_id`` (matching the request's ``X-Request-ID``) and the
    partial ``audit_trace`` — never an unhandled 500.
    """
    trace: list[dict[str, Any]] = []
    try:
        return await _run_investigation(target_user_id, trace)
    except Exception as exc:
        cid = current_request_id()
        if cid in ("", "-", None):
            cid = new_correlation_id()
        _LOG.error(
            "autonomous investigation failed",
            exc_info=exc,
            extra={"request_id": cid, "target_user_id": target_user_id, "steps_done": len(trace)},
        )
        return {
            "status": "ERROR",
            "message": "Investigation failed before completion.",
            "correlation_id": cid,
            "target_user_id": target_user_id,
            "audit_trace": trace,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


async def _run_investigation(target_user_id: str | None, trace: list[dict[str, Any]]) -> dict:
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
        # A-M4: async store access so a slow external backend never blocks the loop.
        security_summary = await tele.asecurity_summary()
        record(1, "get_security_summary", {}, security_summary)

        # Project every triage candidate before it is recorded or returned —
        # the audit_trace and `triage` block are part of the API response (C-5).
        candidates = [tele.project_user(u) for u in await tele.asuspicious_users(limit=3)]
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
    user_raw = await tele.aget_user(user_id)
    if user_raw is None:
        return {
            "status": "TARGET_NOT_FOUND",
            "target_user_id": user_id,
            "message": f"User {user_id} not present in telemetry store.",
            "triage": {"security_summary": security_summary, "candidates": candidates},
            "audit_trace": trace,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ---- b. DEEP-DIVE TELEMETRY -----------------------------------------
    # `telemetry` is the MASKED projection from here on — it is what gets recorded
    # in the trace and returned to the caller (C-5). Numeric scoring below reads
    # the projected counts, which are identical to the raw ones.
    telemetry = tele.project_user(user_raw)
    record(3, "investigate_user", {"user_id": user_id}, telemetry)

    risk = await tele.arisk_score(user_id)
    record(4, "get_user_risk_score", {"user_id": user_id}, risk)

    # ---- c. ATTACK ATTRIBUTION ---------------------------------------
    # No feature vector is available at this step (we only have a user id), so the
    # login Random Forest cannot be run here. Attribution is the shared, grounded
    # classifier over the telemetry counters. Record the exact function executed
    # and the inference mode so the trace stays auditable and reproducible (M-13).
    attack = tele.classify_pattern(user_raw)
    attack.setdefault("inference_mode", "heuristic")
    record(
        5,
        "detect_attack_pattern",
        {
            "user_id": user_id,
            "executed_function": "cyberguard_api.services.telemetry.classify_pattern",
            "inference_mode": "heuristic",
        },
        attack,
    )

    # ---- d. REPORT REGISTRATION -------------------------------------
    threat_type = attack["classified_pattern"]
    severity = _severity_from(risk, attack)
    recommendations = _recommendations(attack, risk, telemetry)

    incident = tele.generate_incident_report(
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
            "inference_mode": attack.get("inference_mode"),
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


def _origin_note(n_ips: int, geo: bool) -> str:
    """
    GR-1: origin description must agree with the IP count. Never claim "Single
    origin" when more than one distinct source IP is on the record.
    """
    if n_ips > 1:
        note = f"Multiple origins on record ({n_ips} unique IPs)"
        return f"{note}; geo_velocity_violation flag set" if geo else note
    if geo:
        return "geo_velocity_violation flag set"
    return "Single origin on record"


def _narrative(telemetry: dict[str, Any], attack: dict[str, Any]) -> str:
    """
    Factual, count-based narrative (L-4). No invented timing windows ("in a
    short window", "during the burst") and no intent claims ("consistent with
    automated credential guessing", "credentials are compromised") — only what
    the telemetry record actually carries. IPs are the masked sample (C-5).

    GR-2: steps are numbered dynamically from the ones actually emitted, so a
    skipped conditional step never leaves a gap (1, 2, 5, 6 ...).
    """
    failed = int(telemetry.get("failed_logins", 0) or 0)
    success = int(telemetry.get("successful_logins", 0) or 0)
    ips_masked = list(telemetry.get("unique_ips_masked", []) or [])
    n_ips = int(telemetry.get("unique_ip_count", len(ips_masked)))
    dev = int(telemetry.get("device_changes", 0) or 0)
    geo = bool(telemetry.get("geo_velocity_violation", False))
    anom = telemetry.get("anomaly_score")

    steps = [
        f"Telemetry records {failed} failed and {success} successful authentication "
        f"event(s) for this account. The store carries counts only — no per-event "
        f"timestamps, so no time window is asserted.",
        f"Distinct source IPs on the record: {n_ips}"
        + (f" (masked sample: {', '.join(ips_masked)})." if ips_masked else ".")
        + (" geo_velocity_violation is set on the record." if geo else ""),
    ]
    if success and failed:
        steps.append(
            f"Both failed ({failed}) and successful ({success}) events are present; "
            f"the successful session is treated as suspect pending analyst review."
        )
    if dev:
        steps.append(
            f"device_changes = {dev} on the record (a new or changed device fingerprint)."
        )
    steps.append(
        f"Classifier attribution: {attack.get('classified_pattern')} "
        f"(MITRE {attack.get('mitre_technique_id') or 'n/a'}, "
        f"{round(float(attack.get('confidence', 0)) * 100)}% confidence). "
        f"{attack.get('signature_details', '')}"
    )
    if anom is not None:
        steps.append(f"Anomaly-detector score on the record: {anom}.")
    return "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))


def _render_markdown(
    user_id: str,
    telemetry: dict[str, Any],
    risk: dict[str, Any],
    attack: dict[str, Any],
    incident: dict[str, Any],
) -> str:
    anomaly = telemetry.get("anomaly_score", 0)
    ips_masked = list(telemetry.get("unique_ips_masked", []) or [])
    n_ips = int(telemetry.get("unique_ip_count", len(ips_masked)))
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
        f"{'Failed + successful events both present' if telemetry.get('successful_logins', 0) >= 1 and telemetry.get('failed_logins', 0) >= 10 else 'Failures only'} |",
        f"| Unique Source IPs | {n_ips} — {', '.join(ips_masked) or 'n/a'} | "
        f"{_origin_note(n_ips, bool(telemetry.get('geo_velocity_violation')))} |",
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
