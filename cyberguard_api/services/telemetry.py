"""
telemetry.py
================================================================================
Single source of truth for the CyberGuard telemetry surface and the pure,
transport-agnostic helpers that read it (audit finding L-7).

The REST surface (``routes_webmcp.py``), the autonomous agent
(``agent_controller.py``) and the MCP stdio server (``cyberguard_mcp_server.py``)
all import from here, so a user record is masked identically no matter which
transport returns it (M-6) and the classification / risk scoring is one
deterministic function of the input telemetry (L-3).

Data-source abstraction (PP-C2)
------------------------------------------------------------------------------
The concrete records now come from a :class:`TelemetryStore`. Which
implementation is bound is decided by config:

    TELEMETRY_BACKEND=mock        in-memory demo store (dev / tests only)
    TELEMETRY_BACKEND=external    HTTP adapter -> TELEMETRY_API_URL (+ token)

``verify_store_config()`` (called from ``main.lifespan``) raises immediately when
``APP_ENV=production`` and ``TELEMETRY_BACKEND=mock`` — a production process
refuses to boot on demo data.

PII policy (C-5 / M-5)
------------------------------------------------------------------------------
``project_user()`` is the ONLY shape that may appear in an API response. It
always masks the username + source IPs; there is no "full" / unmasked path.

Grounding policy (H-1 / L-4)
------------------------------------------------------------------------------
``contributing_factors()`` emits a line only when the telemetry field that backs
it is actually set — no invented timing windows or intent.
================================================================================
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "TelemetryStore",
    "MockTelemetryStore",
    "ExternalTelemetryStore",
    "build_store",
    "verify_store_config",
    "get_store",
    "set_store",
    "MOCK_TELEMETRY",
    "security_summary",
    "suspicious_users",
    "get_user",
    "mask_username",
    "mask_ip",
    "project_user",
    "project_users",
    "contributing_factors",
    "risk_score",
    "classify_pattern",
    "incident_id",
    "generate_incident_report",
]

_LOG = logging.getLogger("cyberguard.telemetry")


# ============================================================================
# Store abstraction (PP-C2)
# ============================================================================

@runtime_checkable
class TelemetryStore(Protocol):
    """
    Read model for authentication telemetry. Implementations return RAW records
    (with real username / IP strings) — callers mask via :func:`project_user`
    before anything is serialised outward.

    A record is a plain dict with at least:
        user_id, username, failed_logins, successful_logins,
        unique_ips (list[str]), anomaly_score (float 0-1),
        device_changes (int), geo_velocity_violation (bool)
    """

    def get_user(self, user_id: str) -> dict[str, Any] | None: ...

    def list_suspicious(self, limit: int = 5) -> list[dict[str, Any]]: ...

    def summary(self) -> dict[str, Any]: ...


# ---- in-memory demo store (dev / tests) ------------------------------------

_MOCK_RECORDS: dict[str, dict[str, Any]] = {
    # 1. Critical Anomaly - Account Takeover (ATO)[cite: 1]
    # Condition match: success >= 1 and geo and (failed >= 10 or dev >= 3)
    "USR-402": {
        "user_id": "USR-402",
        "username": "alex.chen@enterprise.internal",
        "failed_logins": 47,
        "successful_logins": 1,
        "unique_ips": ["198.51.100.23", "203.0.113.88", "192.0.2.14"],
        "anomaly_score": 0.93,
        "device_changes": 4,
        "geo_velocity_violation": True,
    },
    # 2. Critical Anomaly - High-Volume Brute Force[cite: 1]
    # Condition match: failed >= 20 and success == 0 and ips <= 2
    "USR-205": {
        "user_id": "USR-205",
        "username": "david.ross@enterprise.internal",
        "failed_logins": 38,
        "successful_logins": 0,
        "unique_ips": ["198.51.100.45"],
        "anomaly_score": 0.96,
        "device_changes": 0,
        "geo_velocity_violation": False,
    },
    # 3. Critical Anomaly - Distributed Credential Stuffing[cite: 1]
    # Condition match: ips >= 3 and failed >= 10
    "USR-319": {
        "user_id": "USR-319",
        "username": "elena.vargas@enterprise.internal",
        "failed_logins": 29,
        "successful_logins": 0,
        "unique_ips": ["198.51.100.77", "203.0.113.41", "192.0.2.99", "198.51.100.150"],
        "anomaly_score": 0.88,
        "device_changes": 2,
        "geo_velocity_violation": False,
    },
    # 4. High Risk - Suspicious Authentication / Elevated Failure[cite: 1]
    "USR-108": {
        "user_id": "USR-108",
        "username": "sarah.admin@enterprise.internal",
        "failed_logins": 12,
        "successful_logins": 2,
        "unique_ips": ["198.51.100.12"],
        "anomaly_score": 0.68,
        "device_changes": 1,
        "geo_velocity_violation": False,
    },
    # 5. High Risk - Device Hopping / Session Anomaly[cite: 1]
    "USR-512": {
        "user_id": "USR-512",
        "username": "marcus.brody@enterprise.internal",
        "failed_logins": 14,
        "successful_logins": 1,
        "unique_ips": ["203.0.113.19", "198.51.100.61"],
        "anomaly_score": 0.74,
        "device_changes": 3,
        "geo_velocity_violation": False,
    },
    # 6. Medium Risk - Low-Volume Distributed Probing[cite: 1]
    "USR-620": {
        "user_id": "USR-620",
        "username": "priya.nair@enterprise.internal",
        "failed_logins": 8,
        "successful_logins": 1,
        "unique_ips": ["192.0.2.55", "198.51.100.201", "203.0.113.102"],
        "anomaly_score": 0.58,
        "device_changes": 1,
        "geo_velocity_violation": False,
    },
    # 7. Low / Suspicious - Single Geo-Jump without Heavy Brute Force[cite: 1]
    "USR-733": {
        "user_id": "USR-733",
        "username": "james.wilson@enterprise.internal",
        "failed_logins": 4,
        "successful_logins": 1,
        "unique_ips": ["198.51.100.33", "203.0.113.7"],
        "anomaly_score": 0.44,
        "device_changes": 1,
        "geo_velocity_violation": True,
    },
    # 8. Nominal / Baseline - Standard User (Typo on Login)[cite: 1]
    # Condition match: failed <= 3 and anom < 0.40 -> "Normal"
    "USR-814": {
        "user_id": "USR-814",
        "username": "clara.oswald@enterprise.internal",
        "failed_logins": 1,
        "successful_logins": 1,
        "unique_ips": ["198.51.100.5"],
        "anomaly_score": 0.12,
        "device_changes": 0,
        "geo_velocity_violation": False,
    },
    # 9. Nominal / Baseline - Routine Office Worker[cite: 1]
    # Condition match: failed <= 3 and anom < 0.40 -> "Normal"
    "USR-905": {
        "user_id": "USR-905",
        "username": "kevin.hart@enterprise.internal",
        "failed_logins": 0,
        "successful_logins": 4,
        "unique_ips": ["198.51.100.18"],
        "anomaly_score": 0.08,
        "device_changes": 0,
        "geo_velocity_violation": False,
    },
    # 10. Nominal / Baseline - Normal Workstation & Mobile Sync[cite: 1]
    # Condition match: failed <= 3 and anom < 0.40 -> "Normal"
    "USR-101": {
        "user_id": "USR-101",
        "username": "rachel.green@enterprise.internal",
        "failed_logins": 2,
        "successful_logins": 3,
        "unique_ips": ["198.51.100.9", "192.0.2.81"],
        "anomaly_score": 0.19,
        "device_changes": 1,
        "geo_velocity_violation": False,
    },
}

# Back-compat: existing imports do `from ...telemetry import MOCK_TELEMETRY`.
MOCK_TELEMETRY: dict[str, dict[str, Any]] = _MOCK_RECORDS


class MockTelemetryStore:
    """The in-memory demo store (10 seeded records). Never selectable when APP_ENV=production."""

    backend_name = "mock"

    def __init__(self, records: dict[str, dict[str, Any]] | None = None) -> None:
        self._records = records if records is not None else _MOCK_RECORDS

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        return self._records.get(user_id)

    def list_suspicious(self, limit: int = 5) -> list[dict[str, Any]]:
        ranked = sorted(
            self._records.values(), key=lambda u: u.get("anomaly_score", 0.0), reverse=True
        )
        return ranked[: max(0, int(limit))]

    def summary(self) -> dict[str, Any]:
        vals = list(self._records.values())
        flagged = sum(1 for u in vals if u.get("anomaly_score", 0.0) >= 0.6)
        return {
            "monitored_users": len(vals),
            "flagged_suspicious_users": flagged,
            "high_severity_alerts": sum(1 for u in vals if u.get("anomaly_score", 0.0) >= 0.85),
            "status": "ELEVATED_RISK" if flagged else "NOMINAL",
        }


# ---- external HTTP adapter (production template) -------------------------

class ExternalTelemetryStore:
    """
    Production adapter: reads records from an upstream telemetry service over
    HTTPS. Wire it with::

        TELEMETRY_BACKEND=external
        TELEMETRY_API_URL=https://telemetry.internal/api
        TELEMETRY_API_TOKEN=<bearer>          # optional
        TELEMETRY_API_TIMEOUT=3.0             # seconds, optional

    Expected upstream contract (adjust ``_get`` to your service):
        GET  {url}/users/{user_id}        -> record | 404
        GET  {url}/users/suspicious?limit -> {"result": [record, ...]}
        GET  {url}/summary                -> summary dict
    """

    backend_name = "external"

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = 3.0,
    ) -> None:
        if not base_url:
            raise RuntimeError("TELEMETRY_BACKEND=external requires TELEMETRY_API_URL")
        import httpx  # pinned dependency

        self._httpx = httpx
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._base = base_url.rstrip("/")
        self._headers = headers
        self._timeout = timeout
        # Sync client for the sync `def` REST routes (Starlette threadpool).
        self._client = httpx.Client(base_url=self._base, headers=headers, timeout=timeout)
        # Async client for the agent loop / readiness probe — created lazily on
        # the running loop so sync I/O never blocks the event loop (A-M4).
        self._aclient = None

    # ---- sync (REST routes) --------------------------------------------
    def _get(self, path: str, **params: Any) -> Any:
        resp = self._client.get(path, params=params or None)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        return self._get(f"/users/{user_id}")

    def list_suspicious(self, limit: int = 5) -> list[dict[str, Any]]:
        data = self._get("/users/suspicious", limit=int(limit)) or {}
        rows = data.get("result", data) if isinstance(data, dict) else data
        return list(rows or [])[: max(0, int(limit))]

    def summary(self) -> dict[str, Any]:
        return self._get("/summary") or {}

    # ---- async (agent loop / readiness) -----------------------------
    def _get_aclient(self):
        if self._aclient is None:
            self._aclient = self._httpx.AsyncClient(
                base_url=self._base, headers=self._headers, timeout=self._timeout
            )
        return self._aclient

    async def _aget(self, path: str, **params: Any) -> Any:
        resp = await self._get_aclient().get(path, params=params or None)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    async def aget_user(self, user_id: str) -> dict[str, Any] | None:
        return await self._aget(f"/users/{user_id}")

    async def alist_suspicious(self, limit: int = 5) -> list[dict[str, Any]]:
        data = await self._aget("/users/suspicious", limit=int(limit)) or {}
        rows = data.get("result", data) if isinstance(data, dict) else data
        return list(rows or [])[: max(0, int(limit))]

    async def asummary(self) -> dict[str, Any]:
        return await self._aget("/summary") or {}

    async def aclose(self) -> None:
        if self._aclient is not None:
            await self._aclient.aclose()
            self._aclient = None
        try:
            self._client.close()
        except Exception:  # pragma: no cover
            pass


# ---- binding ------------------------------------------------------------

def _is_production() -> bool:
    return os.getenv("APP_ENV", "dev").strip().lower() in {"production", "prod"}


def build_store() -> TelemetryStore:
    """Construct the store named by ``TELEMETRY_BACKEND`` (default: ``mock``)."""
    backend = os.getenv("TELEMETRY_BACKEND", "mock").strip().lower()
    if backend in ("mock", "", "memory"):
        return MockTelemetryStore()
    if backend == "external":
        return ExternalTelemetryStore(
            os.getenv("TELEMETRY_API_URL", "").strip(),
            token=os.getenv("TELEMETRY_API_TOKEN") or None,
            timeout=float(os.getenv("TELEMETRY_API_TIMEOUT", "3.0")),
        )
    raise RuntimeError(f"unknown TELEMETRY_BACKEND={backend!r} (expected 'mock' or 'external')")


def verify_store_config() -> None:
    """
    Fail-closed startup gate (PP-C2). Call from ``main.lifespan`` BEFORE serving.
    A production process must not run on the demo store.
    """
    backend = os.getenv("TELEMETRY_BACKEND", "mock").strip().lower()
    if _is_production() and backend in ("mock", "", "memory"):
        raise RuntimeError(
            "APP_ENV=production but TELEMETRY_BACKEND is 'mock'. Configure a real "
            "telemetry backend (TELEMETRY_BACKEND=external + TELEMETRY_API_URL) "
            "before starting the service."
        )


_store: TelemetryStore | None = None


def get_store() -> TelemetryStore:
    global _store
    if _store is None:
        _store = build_store()
        _LOG.info("telemetry store bound", extra={"backend": getattr(_store, "backend_name", "?")})
    return _store


def set_store(store: TelemetryStore) -> None:
    """Test / bootstrap hook to inject a store explicitly."""
    global _store
    _store = store


# ============================================================================
# Public read helpers — all go through the bound store
# ============================================================================

def security_summary() -> dict[str, Any]:
    return get_store().summary()


def suspicious_users(limit: int = 5) -> list[dict[str, Any]]:
    """Raw records ranked by anomaly score — internal use; project before output."""
    return get_store().list_suspicious(limit)


def get_user(user_id: str) -> dict[str, Any] | None:
    """Raw record or None. Callers own the 404 / not-found behaviour."""
    return get_store().get_user(user_id)


# ============================================================================
# Async access (A-M4) — for the agent loop and the readiness probe, so a slow
# external backend never blocks the event loop. Falls back to a threadpool
# executor for stores that only implement the sync Protocol (e.g. Mock).
# ============================================================================

import asyncio  # noqa: E402  (kept local to this section)


async def _acall(sync_fn, async_name: str, *args):
    store = get_store()
    coro = getattr(store, async_name, None)
    if coro is not None:
        return await coro(*args)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, sync_fn, *args)


async def aget_user(user_id: str) -> dict[str, Any] | None:
    return await _acall(get_store().get_user, "aget_user", user_id)


async def asuspicious_users(limit: int = 5) -> list[dict[str, Any]]:
    return await _acall(get_store().list_suspicious, "alist_suspicious", limit)


async def asecurity_summary() -> dict[str, Any]:
    return await _acall(get_store().summary, "asummary")


async def arisk_score(user_id: str) -> dict[str, Any]:
    user = await aget_user(user_id)
    if user is None:
        raise KeyError(user_id)
    return _risk_from_record(user_id, user)


async def check_store_health(timeout: float = 2.0) -> tuple[bool, str]:
    """
    Readiness probe for the bound store (A-M1). Returns (ok, detail).
    Mock is always healthy; external does a bounded ``summary()`` round-trip.
    """
    store = get_store()
    name = getattr(store, "backend_name", "?")
    try:
        await asyncio.wait_for(asecurity_summary(), timeout=timeout)
        return True, name
    except Exception as exc:  # noqa: BLE001 - readiness must not raise
        return False, f"{name}: {type(exc).__name__}: {exc}"


async def aclose_store() -> None:
    """Best-effort shutdown of the bound store's clients."""
    store = _store
    closer = getattr(store, "aclose", None)
    if closer is not None:
        try:
            await closer()
        except Exception:  # pragma: no cover
            pass


# ============================================================================
# PII projection (C-5 / M-5 / M-6) — always masked, no unmasked path
# ============================================================================

_MASKED_IP_SAMPLE = 3


def mask_username(value: str) -> str:
    """``alex.chen@enterprise.internal`` -> ``a***n@enterprise.internal``."""
    value = str(value or "")
    local, sep, domain = value.partition("@")
    if not local:
        return "***"
    masked_local = local[0] + "*" if len(local) <= 2 else f"{local[0]}***{local[-1]}"
    return masked_local + sep + domain if sep else masked_local


def mask_ip(value: str) -> str:
    """``198.51.100.23`` -> ``198.x.x.x`` ; ``2001:db8::1`` -> ``2001:x``."""
    text = str(value or "")
    if ":" in text:  # IPv6
        head = text.split(":", 1)[0]
        return f"{head}:x" if head else "x:x"
    parts = text.split(".")
    return f"{parts[0]}.x.x.x" if len(parts) == 4 and parts[0] else "x.x.x.x"


def project_user(user: dict[str, Any]) -> dict[str, Any]:
    """
    The only telemetry shape allowed in an API response. Username and source
    IPs are always masked; raw string identifiers never leave the process.
    """
    ips = list(user.get("unique_ips", []) or [])
    return {
        "user_id": user.get("user_id"),
        "username_masked": mask_username(user.get("username", "")),
        "anomaly_score": user.get("anomaly_score"),
        "failed_logins": user.get("failed_logins"),
        "successful_logins": user.get("successful_logins"),
        "device_changes": user.get("device_changes"),
        "geo_velocity_violation": user.get("geo_velocity_violation"),
        "unique_ip_count": len(ips),
        "unique_ips_masked": [mask_ip(ip) for ip in ips[:_MASKED_IP_SAMPLE]],
    }


def project_users(users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [project_user(u) for u in users]


# ============================================================================
# Grounded evidence (H-1 / L-4)
# ============================================================================

def contributing_factors(user: dict[str, Any]) -> list[str]:
    """Evidence lines, each backed by an observed telemetry field."""
    failed = int(user.get("failed_logins", 0) or 0)
    success = int(user.get("successful_logins", 0) or 0)
    n_ips = len(list(user.get("unique_ips", []) or []))
    geo = bool(user.get("geo_velocity_violation", False))
    dev = int(user.get("device_changes", 0) or 0)
    anom = float(user.get("anomaly_score", 0.0) or 0.0)

    factors: list[str] = []
    if failed:
        tail = f" against {success} successful" if success else ", none successful"
        factors.append(f"{failed} failed authentication event(s) on record{tail}")
    if success and failed >= 10:
        factors.append(
            f"{success} successful login(s) present alongside {failed} failures "
            "— treat the successful session as suspect"
        )
    if n_ips > 1:
        factors.append(f"authentication from {n_ips} distinct source IP addresses")
    if geo:
        factors.append("geo_velocity_violation is set on the record (impossible-travel flag)")
    if dev > 0:
        factors.append(f"{dev} device-fingerprint change(s) recorded")
    if anom >= 0.5:
        factors.append(f"anomaly-detector score {anom:.2f} (elevated)")
    if not factors:
        factors.append(
            f"no elevated indicators; anomaly score {anom:.2f}, "
            f"{failed} failed / {success} successful auth"
        )
    return factors


def _risk_from_record(user_id: str, user: dict[str, Any]) -> dict[str, Any]:
    """Pure risk projection from an already-fetched record (shared sync/async)."""
    score = int(round(float(user["anomaly_score"]) * 100))
    return {
        "user_id": user_id,
        "risk_score": score,
        "risk_level": (
            "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM"
        ),
        "top_contributing_factors": contributing_factors(user),
    }


def risk_score(user_id: str) -> dict[str, Any]:
    """
    Deterministic risk projection: score from ``anomaly_score``, band from
    score, evidence from :func:`contributing_factors`. No PII, no randomness.
    """
    user = get_user(user_id)
    if user is None:
        raise KeyError(user_id)
    return _risk_from_record(user_id, user)


# ============================================================================
# Grounded classifier (deterministic — L-3)
# ============================================================================

def classify_pattern(user: dict[str, Any]) -> dict[str, Any]:
    """
    Classify authentication activity purely from this user's telemetry counters.
    Pure and deterministic; every input is echoed back under ``evidence``.
    """
    failed = user["failed_logins"]
    success = user["successful_logins"]
    ips = len(user["unique_ips"])
    geo = user["geo_velocity_violation"]
    dev = user["device_changes"]
    anom = user["anomaly_score"]

    if success >= 1 and geo and (failed >= 10 or dev >= 3):
        pattern, mitre, confidence = "Account Takeover (ATO)", "T1078.004", anom
        signature = (
            f"{failed} failed then {success} successful auth; geo_velocity_violation set; "
            f"{ips} distinct source IPs; {dev} device changes."
        )
    elif failed >= 20 and success == 0 and ips <= 2:
        pattern, mitre = "Brute Force", "T1110.001"
        confidence = min(0.97, 0.50 + failed / 100)
        signature = f"{failed} failed auth from {ips} IP(s); no successful login."
    elif ips >= 3 and failed >= 10:
        pattern, mitre = "Credential Stuffing", "T1110.004"
        confidence = min(0.95, 0.40 + ips * 0.10)
        signature = f"{failed} failed auth spread across {ips} distinct source IPs."
    elif failed <= 3 and anom < 0.40:
        pattern, mitre, confidence = "Normal", None, round(1 - anom, 4)
        signature = f"{failed} failed / {success} successful auth; anomaly score {anom}."
    else:
        pattern, mitre, confidence = "Suspicious Authentication Activity", "T1078", anom
        signature = (
            f"{failed} failed / {success} successful auth; anomaly score {anom}; "
            f"{ips} unique IPs; {dev} device changes."
        )

    return {
        "classified_pattern": pattern,
        "confidence": round(float(confidence), 4),
        "attack_detected": pattern != "Normal",
        "mitre_technique_id": mitre,
        "signature_details": signature,
        "inference_mode": "heuristic",
        "evidence": {
            "failed_logins": failed,
            "successful_logins": success,
            "unique_ip_count": ips,
            "geo_velocity_violation": geo,
            "device_changes": dev,
            "anomaly_score": anom,
        },
    }


# ============================================================================
# Incident report — deterministic body, non-deterministic id only (L-3)
# ============================================================================

def incident_id(user_id: str) -> str:
    """Collision-resistant, unpredictable id. The only non-deterministic field."""
    return f"INC-2026-{uuid.uuid4().hex[:8].upper()}"


def generate_incident_report(
    user_id: str, threat_type: str, severity: str, recommendations: list[str]
) -> dict[str, Any]:
    return {
        "incident_id": incident_id(user_id),
        "status": "LOGGED",
        "target_entity": user_id,
        "severity": severity,
        "threat_type": threat_type,
        "recommended_actions": list(recommendations),
    }
