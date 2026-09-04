"""
tests/test_telemetry_expansion.py
================================================================================
Regression lock for the mock-telemetry expansion from 2 -> 10 seeded users
(`cyberguard_api/services/telemetry.py::_MOCK_RECORDS`).

Pins the values every downstream surface (REST facade, agent controller,
dashboard) now derives dynamically, so a future edit to the seed data — or a
re-introduction of the `__MOCK_RECORDS` name typo that made the module
un-importable — fails loudly here instead of in a demo.

Run:  .venv/bin/pytest tests/test_telemetry_expansion.py
================================================================================
"""

from __future__ import annotations

import asyncio
import importlib

import pytest
from fastapi.testclient import TestClient

from cyberguard_api.services import telemetry as tele
from cyberguard_api.services import agent_controller as agent

ALL_IDS = [
    "USR-101", "USR-108", "USR-205", "USR-319", "USR-402",
    "USR-512", "USR-620", "USR-733", "USR-814", "USR-905",
]


@pytest.fixture(scope="module")
def client():
    main = importlib.import_module("cyberguard_api.main")
    with TestClient(main.app) as c:
        yield c


# ---------------------------------------------------------------------------
# Seed data shape
# ---------------------------------------------------------------------------

def test_module_exposes_ten_records_under_the_canonical_name():
    # Guards the `__MOCK_RECORDS` vs `_MOCK_RECORDS` name mismatch that broke import.
    assert hasattr(tele, "_MOCK_RECORDS")
    assert tele.MOCK_TELEMETRY is tele._MOCK_RECORDS
    assert sorted(tele.MOCK_TELEMETRY) == ALL_IDS
    for uid in ALL_IDS:
        rec = tele.MOCK_TELEMETRY[uid]
        assert rec["user_id"] == uid
        assert 0.0 <= rec["anomaly_score"] <= 1.0


# ---------------------------------------------------------------------------
# security_summary() — dynamic over the full pool
# ---------------------------------------------------------------------------

def test_security_summary_reflects_ten_user_pool():
    s = tele.security_summary()
    assert s == {
        "monitored_users": 10,
        # anomaly_score >= 0.60: USR-205, USR-402, USR-319, USR-512, USR-108
        "flagged_suspicious_users": 5,
        # anomaly_score >= 0.85: USR-205, USR-402, USR-319
        "high_severity_alerts": 3,
        "status": "ELEVATED_RISK",
    }


def test_summary_route_matches_helper(client):
    assert client.get("/api/v1/security/summary").json() == tele.security_summary()


# ---------------------------------------------------------------------------
# suspicious_users() — ranked by anomaly_score desc
# ---------------------------------------------------------------------------

def test_suspicious_top5_order_and_rank_one():
    ranked = [u["user_id"] for u in tele.suspicious_users(5)]
    assert ranked == ["USR-205", "USR-402", "USR-319", "USR-512", "USR-108"]
    assert ranked[0] == "USR-205"


def test_suspicious_route_honours_limit(client):
    got = client.get("/api/v1/users/suspicious?limit=5").json()["result"]
    assert [u["user_id"] for u in got] == ["USR-205", "USR-402", "USR-319", "USR-512", "USR-108"]
    assert got[0]["username_masked"] == "d***s@enterprise.internal"  # david.ross


# ---------------------------------------------------------------------------
# classify_pattern() — branch coverage across the seeded profiles
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "user_id, pattern, mitre",
    [
        ("USR-402", "Account Takeover (ATO)", "T1078.004"),
        ("USR-205", "Brute Force", "T1110.001"),
        ("USR-319", "Credential Stuffing", "T1110.004"),
        ("USR-814", "Normal", None),
        ("USR-905", "Normal", None),
        ("USR-101", "Normal", None),
    ],
)
def test_classification_branches(user_id, pattern, mitre):
    c = tele.classify_pattern(tele.MOCK_TELEMETRY[user_id])
    assert c["classified_pattern"] == pattern
    assert c["mitre_technique_id"] == mitre
    assert c["attack_detected"] is (pattern != "Normal")


# ---------------------------------------------------------------------------
# Every seeded id is reachable through the deep-dive route (no 404s)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("user_id", ALL_IDS)
def test_all_seeded_ids_resolve(client, user_id):
    r = client.get(f"/api/v1/users/{user_id}/investigate")
    assert r.status_code == 200
    body = r.json()
    assert body["user_id"] == user_id
    assert "username" not in body and "unique_ips" not in body  # masked projection only


# ---------------------------------------------------------------------------
# Autonomous auto-triage now selects USR-205 (0.96), not a hardcoded USR-402
# ---------------------------------------------------------------------------

def test_auto_triage_targets_highest_anomaly_user():
    out = asyncio.run(agent.run_autonomous_investigation(None))
    assert out["status"] == "COMPLETE"
    assert out["target_user_id"] == "USR-205"
    assert out["auto_selected"] is True
    assert "0.96" in out["selection_reason"]
    a = out["assessment"]
    assert a["threat_classification"] == "Brute Force"
    assert a["mitre_technique_id"] == "T1110.001"
    assert a["severity"] == "CRITICAL"
    assert a["risk_score"] == 96
