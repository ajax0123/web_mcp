"""
tests/test_gateway.py
================================================================================
Coverage for the edge gateway added for audit findings C-3, H-4, M-9, M-11, L-5.

Run:  .venv/bin/pytest tests/test_gateway.py
(The full suite needs the pinned deps + model artifacts — see scripts/bootstrap.sh.)
================================================================================
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    # Default env => APP_ENV=dev, API_KEYS unset => auth is a warn-once no-op.
    main = importlib.import_module("cyberguard_api.main")
    with TestClient(main.app) as c:
        yield c


# --- H-4: security headers on every response ---------------------------------

def test_security_headers_present(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert "content-security-policy" in r.headers


def test_hsts_absent_in_dev(client):
    # dev default HSTS_MAX_AGE=0 -> header omitted
    assert "strict-transport-security" not in client.get("/health").headers


# --- M-9: liveness vs readiness --------------------------------------------

def test_health_is_pure_liveness(client):
    body = client.get("/health").json()
    assert set(body) == {"status"}


def test_readyz_reports_model_state(client):
    r = client.get("/readyz")
    assert r.status_code in (200, 503)
    payload = r.json()
    if r.status_code == 503:
        assert payload["detail"]["status"] == "not_ready"
        assert isinstance(payload["detail"]["missing"], list)
        # A-M1: the telemetry store is part of the readiness set.
        assert "telemetry_store" in payload["detail"]["checks"]
    else:
        assert payload["status"] == "ready"
        assert all(payload["checks"].values())
        assert payload["checks"]["telemetry_store"] is True


# --- M-11: ASGI body-size cap ---------------------------------------------

def test_oversized_body_rejected_with_413(client):
    huge = {"data": {"x": "A" * 1_100_000}}  # > MAX_BODY_BYTES default (1_000_000)
    r = client.post("/detect_attack_pattern", json=huge)
    assert r.status_code == 413
    assert r.json()["detail"] == "request body too large"


def test_normal_body_not_rejected(client):
    # Small malformed payload should get past the size gate and be handled by
    # the route (422/503), never 413.
    r = client.post("/detect_attack_pattern", json={"data": {"a": 1}})
    assert r.status_code != 413


# --- C-3 / L-5: config-driven auth + CORS fail-closed --------------------

def test_dev_allows_unauthenticated_api_v1(client):
    # APP_ENV=dev + no API_KEYS => dependency is a no-op.
    r = client.get("/api/v1/security/summary")
    assert r.status_code == 200


def test_production_requires_api_keys(monkeypatch):
    from cyberguard_api import gateway

    gateway.get_settings.cache_clear()
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("API_KEYS", "")
    monkeypatch.setenv("CORS_ORIGINS", "")
    try:
        s = gateway.Settings()
        assert s.is_production and not s.api_key_set
    finally:
        gateway.get_settings.cache_clear()


def test_key_extraction_and_client_ip(monkeypatch):
    from cyberguard_api import gateway

    class _Req:
        def __init__(self, headers, peer="203.0.113.9"):
            self.headers = headers
            self.client = type("C", (), {"host": peer})()

    assert gateway._extract_key(_Req({"x-api-key": "abc"})) == "abc"
    assert gateway._extract_key(_Req({"authorization": "Bearer xyz"})) == "xyz"
    assert gateway._extract_key(_Req({})) is None

    gateway.get_settings.cache_clear()
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "")
    s = gateway.Settings()
    # No trusted proxies configured -> XFF is ignored, socket peer wins (H-6).
    req = _Req({"x-forwarded-for": "1.2.3.4"}, peer="203.0.113.9")
    assert gateway.client_ip(req, s) == "203.0.113.9"
    gateway.get_settings.cache_clear()
