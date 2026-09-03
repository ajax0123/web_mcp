#!/usr/bin/env python3
"""
Smoke test — graceful error handling of the autonomous agent endpoint.

Cases:
  1. Target Not Found     POST {"user_id":"USR-999"}  -> 200 + status TARGET_NOT_FOUND (never 500)
  2. Direct Target Inject  POST {"user_id":"USR-108"} -> triage phase skipped, straight to deep-dive

Stdlib only. Usage:  python3 tests/smoke_agent.py [API_BASE]
"""

import json
import sys
import urllib.error
import urllib.request

API = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")

PASS = 0
FAIL = 0


def check(cond: bool, label: str) -> None:
    global PASS, FAIL
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"    {mark} {label}")
    if cond:
        PASS += 1
    else:
        FAIL += 1


def post(path: str, payload: dict):
    """Return (status_code, parsed_json_or_text). Does not raise on 4xx/5xx."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        API + path, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode()
            code = r.status
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        code = e.code
    try:
        return code, json.loads(body)
    except json.JSONDecodeError:
        return code, body


# --------------------------------------------------------------------------
print("\n[1] Target Not Found  —  POST /api/v1/agent/investigate {\"user_id\":\"USR-999\"}")
code, d = post("/api/v1/agent/investigate", {"user_id": "USR-999"})
check(code == 200, f"HTTP {code} == 200  (graceful, not an unhandled 500)")
check(isinstance(d, dict), "response body is JSON object")
if isinstance(d, dict):
    check(d.get("status") == "TARGET_NOT_FOUND", f"status == TARGET_NOT_FOUND  (got {d.get('status')!r})")
    check(d.get("target_user_id") == "USR-999", "echoes target_user_id USR-999")
    check(d.get("audit_trace") == [], "audit_trace is empty  (no partial side effects)")
    check("message" in d, f"carries a human-readable message  ({d.get('message')!r})")
    check("incident" not in d, "no incident registered for a non-existent user")

# --------------------------------------------------------------------------
print("\n[2] Direct Target Injection  —  POST /api/v1/agent/investigate {\"user_id\":\"USR-108\"}")
code, d = post("/api/v1/agent/investigate", {"user_id": "USR-108"})
check(code == 200, f"HTTP {code} == 200")
tools = [s["tool"] for s in d.get("audit_trace", [])] if isinstance(d, dict) else []
steps = [s["step"] for s in d.get("audit_trace", [])] if isinstance(d, dict) else []
if isinstance(d, dict):
    check(d.get("status") == "COMPLETE", f"status == COMPLETE  (got {d.get('status')!r})")
    check(d.get("target_user_id") == "USR-108", "target_user_id == USR-108")
    check(d.get("auto_selected") is False, "auto_selected == false  (explicit target)")
    check("get_security_summary" not in tools, "TRIAGE tool get_security_summary  SKIPPED")
    check("get_suspicious_users" not in tools, "TRIAGE tool get_suspicious_users  SKIPPED")
    check(steps[:1] == [3], f"first audit step == 3  (jumps straight to deep-dive; got {steps[:1]})")
    check(
        tools == ["investigate_user", "get_user_risk_score", "detect_attack_pattern", "generate_incident_report"],
        f"trace == deep-dive → correlate → attribute → report  (got {tools})",
    )
    check((d.get("triage") or {}).get("security_summary") is None, "triage.security_summary is null")
    check((d.get("triage") or {}).get("candidates") is None, "triage.candidates is null")
    a = d.get("assessment", {})
    print(f"      → {a.get('threat_classification')} / {a.get('severity')} / {a.get('confidence_pct')}% / {a.get('mitre_technique_id')}")

# --------------------------------------------------------------------------
summary = f"\n  smoke_agent: {PASS} passed, {FAIL} failed"
print("\033[32m" + summary + "\033[0m" if FAIL == 0 else "\033[31m" + summary + "\033[0m")
sys.exit(1 if FAIL else 0)
