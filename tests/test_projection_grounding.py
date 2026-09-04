"""
tests/test_projection_grounding.py
================================================================================
Coverage for the AI / tool-layer remediations:

  * C-5 / M-5 / M-6 — every telemetry record leaving the API is masked; the
    agent loop, REST helpers and MCP server share one projection; no ?scope=full.
  * H-1 / L-4 — contributing factors / narrative are derived from observed
    telemetry fields only (no "impossible travel across 3 ASN networks", no
    invented time windows).
  * L-3 / L-7 — one shared MOCK_TELEMETRY; classification + scoring are pure,
    deterministic functions of the telemetry.

Run:  .venv/bin/pytest tests/test_projection_grounding.py
================================================================================
"""

from __future__ import annotations

import asyncio
import inspect
import json

from cyberguard_api.services import telemetry as tele
from cyberguard_api.services import agent_controller as agent
from cyberguard_api import routes_webmcp as rw
import cyberguard_mcp_server as mcp

_UNGROUNDED = (
    "impossible travel across",
    "3 ASN networks",
    "within 10 minutes",
    "consistent with automated credential guessing",
    "during the burst",
    "in a short window",
    "credentials are compromised",
)
_RAW_EMAIL = "alex.chen@enterprise.internal"
_RAW_IP = "198.51.100.23"


# ---------------------------------------------------------------------------
# L-7 — single shared store
# ---------------------------------------------------------------------------

def test_one_shared_mock_telemetry():
    assert rw.MOCK_TELEMETRY is tele.MOCK_TELEMETRY
    # agent_controller + mcp server go through the same module
    assert agent.tele is tele
    assert mcp._classify_pattern is tele.classify_pattern


# ---------------------------------------------------------------------------
# C-5 / M-5 / M-6 — masking everywhere, no unmasked path
# ---------------------------------------------------------------------------

def test_project_user_masks_and_drops_raw_fields():
    p = tele.project_user(tele.MOCK_TELEMETRY["USR-402"])
    assert "username" not in p and "unique_ips" not in p
    assert p["username_masked"] == "a***n@enterprise.internal"
    assert p["unique_ip_count"] == 3
    assert all(ip.endswith(".x.x.x") for ip in p["unique_ips_masked"])
    assert _RAW_EMAIL not in json.dumps(p) and _RAW_IP not in json.dumps(p)


def test_project_user_has_no_full_parameter():
    sig = inspect.signature(tele.project_user)
    assert list(sig.parameters) == ["user"]
    # routes_webmcp alias is the 1-arg form too
    assert list(inspect.signature(rw._project_user).parameters) == ["user"]


def test_scope_full_bypass_is_decommissioned():
    assert not hasattr(rw, "_scope_is_full")
    assert not hasattr(rw, "_SCOPED_SESSION_TOKEN")
    params = inspect.signature(rw.webmcp_suspicious_users).parameters
    assert "scope" not in params and "request" not in params
    assert "scope" not in inspect.signature(rw.webmcp_investigate_user).parameters


def test_mcp_server_uses_the_shared_masked_projection():
    # Version-proof: assert the MCP tools are bound to the shared helpers rather
    # than poking fastmcp's tool wrapper.
    assert mcp._project_user is tele.project_user
    assert mcp._suspicious_users is tele.suspicious_users
    assert mcp._risk_score is tele.risk_score
    assert mcp._generate_incident_report is tele.generate_incident_report
    # and the projection those tools call really does mask
    got = mcp._project_user(tele.MOCK_TELEMETRY["USR-402"])
    assert _RAW_EMAIL not in json.dumps(got) and _RAW_IP not in json.dumps(got)


def test_agent_investigation_returns_only_masked_pii():
    out = asyncio.run(agent.run_autonomous_investigation("USR-402"))
    blob = json.dumps(out)
    assert _RAW_EMAIL not in blob, "raw email leaked in agent response"
    assert _RAW_IP not in blob, "raw source IP leaked in agent response"
    assert "username" not in out["telemetry"] and "unique_ips" not in out["telemetry"]
    assert out["telemetry"]["username_masked"]
    # audit trace embeds the same masked shape
    step3 = next(s for s in out["audit_trace"] if s["tool"] == "investigate_user")
    assert "username" not in step3["output"] and "unique_ips" not in step3["output"]
    assert out["markdown_report"].startswith("# INCIDENT REPORT")
    assert _RAW_IP not in out["markdown_report"]


# ---------------------------------------------------------------------------
# H-1 / L-4 — grounded evidence
# ---------------------------------------------------------------------------

def test_usr108_factors_have_no_unobserved_claims():
    # USR-108: geo_velocity_violation == False, 1 IP
    factors = tele.contributing_factors(tele.MOCK_TELEMETRY["USR-108"])
    joined = " ".join(factors).lower()
    for bad in _UNGROUNDED:
        assert bad not in joined, f"ungrounded phrase in USR-108 factors: {bad!r}"
    assert "impossible-travel" not in joined and "asn" not in joined
    # but it does reflect the real fields
    assert any("12 failed" in f for f in factors)
    assert any("0.68" in f for f in factors)


def test_usr402_factors_include_geo_only_because_flag_is_set():
    factors = tele.contributing_factors(tele.MOCK_TELEMETRY["USR-402"])
    assert any("geo_velocity_violation is set" in f for f in factors)
    assert any("3 distinct source IP" in f for f in factors)


def test_risk_score_factors_are_dynamic_and_pii_free():
    r108 = tele.risk_score("USR-108")
    assert r108["risk_score"] == 68 and r108["risk_level"] == "HIGH"
    assert not any("impossible travel" in f.lower() for f in r108["top_contributing_factors"])
    assert _RAW_EMAIL not in json.dumps(r108) and "198.51.100.12" not in json.dumps(r108)


def test_narrative_has_no_timing_or_intent_language():
    tel = tele.project_user(tele.MOCK_TELEMETRY["USR-402"])
    attack = tele.classify_pattern(tele.MOCK_TELEMETRY["USR-402"])
    text = agent._narrative(tel, attack).lower()
    for bad in _UNGROUNDED:
        assert bad not in text, f"ungrounded phrase in narrative: {bad!r}"
    assert "counts only" in text  # explicitly disclaims a time window


# ---------------------------------------------------------------------------
# L-3 — deterministic classification / scoring
# ---------------------------------------------------------------------------

def test_classification_and_scoring_are_pure():
    u = tele.MOCK_TELEMETRY["USR-402"]
    assert tele.classify_pattern(u) == tele.classify_pattern(dict(u))
    assert tele.risk_score("USR-402") == tele.risk_score("USR-402")
    # only the incident id varies between calls
    a = tele.generate_incident_report("USR-402", "Brute Force", "HIGH", ["x"])
    b = tele.generate_incident_report("USR-402", "Brute Force", "HIGH", ["x"])
    assert a["incident_id"] != b["incident_id"]
    assert {k: v for k, v in a.items() if k != "incident_id"} == {
        k: v for k, v in b.items() if k != "incident_id"
    }


def test_stale_model_dir_reference_is_fixed():
    assert "web_mcp-Data-Science" not in str(mcp.MODEL_DIR)
    assert str(mcp.MODEL_DIR).endswith("models")
