from __future__ import annotations

from cyberguard_api.services import security_decision_engine as engine


def test_safe_login_is_allowed_without_fake_model_score():
    result = engine.assess_login({
        "user_id": "TEST-SAFE",
        "login_successful": True,
        "failed_logins": 0,
        "successful_logins": 1,
        "unique_ips": ["192.0.2.10"],
        "anomaly_score": 0.05,
    })
    assert result["status"] == "SAFE"
    assert result["access_decision"] == "ALLOWED"
    assert result["model_score"] is None
    assert result["model_source"] == "deterministic_rule_fallback"


def test_high_risk_login_creates_incident_and_demo_containment():
    result = engine.assess_login({
        "user_id": "TEST-HIGH",
        "login_successful": True,
        "failed_logins": 47,
        "successful_logins": 1,
        "unique_ips": ["198.51.100.7", "203.0.113.8"],
        "anomaly_score": 0.93,
        "device_changed": True,
        "location_changed": True,
        "login_hour": 2,
    })
    assert result["status"] == "HIGH_RISK"
    assert result["access_decision"] == "REQUIRE_ADMIN_REVIEW"
    incident = engine.get_incident(result["incident_id"])
    assert incident is not None
    containment = engine.deny_access("TEST-HIGH", "admin", "demo test")
    assert containment["status"] == "CONTAINED"
    assert engine.access_status("TEST-HIGH")["status"] == "DEMO_CONTAINED"


def test_contained_user_is_denied_on_next_login():
    result = engine.assess_login({
        "user_id": "TEST-CONTAINED",
        "login_successful": True,
        "failed_logins": 30,
        "unique_ips": ["198.51.100.9"],
        "anomaly_score": 0.9,
        "device_changed": True,
    })
    engine.deny_access("TEST-CONTAINED", "admin")
    blocked = engine.assess_login({"user_id": "TEST-CONTAINED", "login_successful": True})
    assert blocked["login_allowed"] is False
    assert blocked["access_decision"] == "DENIED_DEMO_CONTAINED"
    assert blocked["status"] == "HIGH_RISK"
