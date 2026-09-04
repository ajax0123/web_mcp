"""
gateway.py
================================================================================
API gateway / edge hardening for the CyberGuard service.

This module is deliberately OUTSIDE ``cyberguard_api/security/`` — that tree is
owned by the security track. Everything here is request-path plumbing that
``main.py`` / ``routes_webmcp.py`` wire in:

  * ``Settings``                  env-driven config (pydantic-settings)
  * ``require_api_key``           FastAPI dependency — API key / Bearer auth        (C-3)
  * ``create_limiter``            per-client rate limiting via slowapi              (C-3)
  * ``install_middleware``        security headers + ASGI body-size cap             (H-4, M-11)
  * ``client_ip``                 trusted-reverse-proxy aware client IP             (H-6)

Audit findings addressed: C-3, H-4, H-6, M-9 (helpers), M-11, L-5.

Graceful degradation: if the optional ``slowapi`` package is missing the app
still imports and serves — rate limiting is disabled with a loud warning. Auth
and the header / body-size middleware have no optional dependencies.
================================================================================
"""

from __future__ import annotations

import ipaddress
import logging
import os
import base64
import hashlib
import hmac
import secrets
import time
from functools import lru_cache
from typing import Iterable

from fastapi import FastAPI, HTTPException, Request, status
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

try:  # pydantic-settings is a pinned dependency; fall back defensively.
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _HAVE_SETTINGS = True
except Exception:  # pragma: no cover - only if the dep is missing
    _HAVE_SETTINGS = False

    class BaseSettings:  # type: ignore
        pass

    def SettingsConfigDict(**_kw):  # type: ignore
        return None


_LOG = logging.getLogger("cyberguard.gateway")

# Docs endpoints need a looser CSP than the JSON API (Swagger UI pulls its
# bundle from jsdelivr and uses inline styles).
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")

_CSP_API = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_CSP_DOCS = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
)


# ============================================================================
# Settings
# ============================================================================

class Settings(BaseSettings):
    """Runtime configuration. Every field is overridable via environment / .env."""

    # dev | staging | production. Controls fail-closed behaviour.
    app_env: str = "dev"

    # Comma-separated list of accepted API keys. Empty in a non-dev env is a
    # startup error (see main.lifespan); empty in dev = auth bypassed + warning.
    api_keys: str = ""

    # Trusted reverse-proxy source IPs whose X-Forwarded-For we honour (H-6).
    # Prefer uvicorn --forwarded-allow-ips as the primary control; this is a
    # defence-in-depth check inside the app.
    trusted_proxy_ips: str = ""

    # ASGI request-body cap in bytes (M-11). 0 disables the check.
    max_body_bytes: int = 1_000_000

    # slowapi limit string, e.g. "60/minute", "1000/hour".
    rate_limit: str = "60/minute"
    rate_limit_enabled: bool = True
    # "memory://" (default, per-process) or e.g. "redis://localhost:6379/1".
    rate_limit_storage_uri: str = "memory://"

    # HSTS max-age in seconds. 0 (dev default) omits the header. Auto-bumped to
    # one year in production unless explicitly overridden.
    hsts_max_age: int = 0

    csp_api: str = _CSP_API
    csp_docs: str = _CSP_DOCS

    # Expose interactive docs only when true (default: off in production).
    enable_docs: bool = True

    admin_username: str = ""
    admin_password_hash: str = ""
    auth_session_ttl_seconds: int = 1800

    if _HAVE_SETTINGS:
        model_config = SettingsConfigDict(
            env_file=".env", env_file_encoding="utf-8", extra="ignore"
        )

    # --- derived helpers ---------------------------------------------------

    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() in {"production", "prod"}

    @property
    def api_key_set(self) -> frozenset[str]:
        return frozenset(_split_csv(self.api_keys))

    @property
    def trusted_proxies(self) -> tuple[ipaddress._BaseNetwork, ...]:
        nets: list[ipaddress._BaseNetwork] = []
        for token in _split_csv(self.trusted_proxy_ips):
            try:
                nets.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                _LOG.warning("ignoring invalid TRUSTED_PROXY_IPS entry: %r", token)
        return tuple(nets)

    @property
    def effective_hsts_max_age(self) -> int:
        if self.hsts_max_age > 0:
            return self.hsts_max_age
        return 31_536_000 if self.is_production else 0

    @property
    def docs_url(self) -> str | None:
        return "/docs" if (self.enable_docs and not self.is_production) else None

    @property
    def redoc_url(self) -> str | None:
        return "/redoc" if (self.enable_docs and not self.is_production) else None


def _split_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [part.strip() for part in str(raw).replace("\n", ",").split(",") if part.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# ============================================================================
# Authentication dependency (C-3)
# ============================================================================

_AUTH_BYPASS_WARNED = False
_AUTH_SESSIONS: dict[str, float] = {}


def _verify_password(password: str, encoded_hash: str) -> bool:
    """Verify PBKDF2-SHA256 hashes encoded as pbkdf2_sha256$iterations$salt$hash."""
    try:
        algorithm, iterations, salt, expected = encoded_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
        return hmac.compare_digest(base64.urlsafe_b64encode(derived).decode().rstrip("="), expected)
    except (ValueError, TypeError):
        return False


def authenticate_admin(username: str, password: str) -> str | None:
    settings = get_settings()
    if not settings.admin_username or not settings.admin_password_hash:
        return None
    if not hmac.compare_digest(username, settings.admin_username) or not _verify_password(password, settings.admin_password_hash):
        return None
    session_id = secrets.token_urlsafe(32)
    _AUTH_SESSIONS[session_id] = time.time() + max(60, settings.auth_session_ttl_seconds)
    return session_id


def valid_session(session_id: str | None) -> bool:
    if not session_id:
        return False
    expires_at = _AUTH_SESSIONS.get(session_id)
    if expires_at is None:
        return False
    if expires_at <= time.time():
        _AUTH_SESSIONS.pop(session_id, None)
        return False
    return True


def revoke_session(session_id: str | None) -> None:
    if session_id:
        _AUTH_SESSIONS.pop(session_id, None)


def _extract_key(request: Request) -> str | None:
    key = request.headers.get("x-api-key")
    if key:
        return key.strip()
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip() or None
    return None


async def require_api_key(request: Request) -> None:
    """
    Reject any request without a valid ``X-API-Key`` / ``Authorization: Bearer``.

    * keys configured  -> constant-time match, else 401
    * no keys + prod   -> 503 (fail closed; startup also refuses, see lifespan)
    * no keys + dev    -> allowed once with a one-time warning
    """
    global _AUTH_BYPASS_WARNED
    settings = get_settings()
    keys = settings.api_key_set

    if not keys:
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="authentication is not configured",
            )
        if not _AUTH_BYPASS_WARNED:
            _LOG.warning(
                "API_KEYS is empty and APP_ENV=%s — /api/v1 and ML routes are "
                "UNAUTHENTICATED. Set API_KEYS before any non-dev deploy.",
                settings.app_env,
            )
            _AUTH_BYPASS_WARNED = True
        return

    import secrets

    if valid_session(request.cookies.get("cyberguard_session")):
        return
    provided = _extract_key(request)
    if not provided or not any(secrets.compare_digest(provided, k) for k in keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================================
# Trusted-proxy aware client IP (H-6)
# ============================================================================

_RL_KEY_WARNED = False


def _in_trusted(addr: str, proxies) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in proxies)


def client_ip(request: Request, settings: Settings | None = None) -> str:
    """
    Best-effort real client IP for the rate-limit key (H-6 / A-M8).

    uvicorn's ``--proxy-headers --forwarded-allow-ips`` already rewrites
    ``request.client`` when the immediate peer is a trusted proxy. In addition,
    when the direct peer is in ``TRUSTED_PROXY_IPS`` we walk ``X-Forwarded-For``
    RIGHT-TO-LEFT, skipping trusted-proxy hops, and take the first NON-trusted
    address — a client cannot forge that by prepending fake entries.

    When no trusted proxy is configured we fall back to the raw socket peer (the
    correct behaviour for a direct-connection deployment). If that happens in
    production it is logged once, loudly: it usually means the ingress IP was
    left out of ``FORWARDED_ALLOW_IPS`` / ``TRUSTED_PROXY_IPS`` and every client
    would otherwise share one bucket.
    """
    global _RL_KEY_WARNED
    settings = settings or get_settings()
    peer = request.client.host if request.client else "unknown"
    proxies = settings.trusted_proxies

    if proxies and peer != "unknown" and _in_trusted(peer, proxies):
        chain = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        for hop in reversed(chain):
            if not _in_trusted(hop, proxies):
                return hop
        # every hop was a trusted proxy -> leftmost is the closest we have
        if chain:
            return chain[0]

    if settings.is_production and not proxies and not _RL_KEY_WARNED:
        _LOG.warning(
            "rate-limit key falls back to the socket peer and no TRUSTED_PROXY_IPS "
            "is configured. If this service sits behind a load balancer, set "
            "--forwarded-allow-ips / TRUSTED_PROXY_IPS to the ingress IP(s) or "
            "every client will share a single rate-limit bucket (A-M8)."
        )
        _RL_KEY_WARNED = True
    return peer


# ============================================================================
# Rate limiting (C-3) — slowapi is optional
# ============================================================================

def _web_concurrency() -> int:
    try:
        return max(1, int(os.getenv("WEB_CONCURRENCY", "1")))
    except ValueError:
        return 1


def create_limiter(app: FastAPI, settings: Settings) -> None:
    """Attach ``app.state.limiter`` (or ``None``) + the 429 exception handler."""
    if not settings.rate_limit_enabled:
        if settings.is_production:
            raise RuntimeError(
                "RATE_LIMIT_ENABLED=false is not permitted when APP_ENV=production (PP-H1)."
            )
        app.state.limiter = None
        _LOG.info("rate limiting disabled by config (RATE_LIMIT_ENABLED=false)")
        return
    try:
        from slowapi import Limiter, _rate_limit_exceeded_handler
        from slowapi.errors import RateLimitExceeded
    except Exception as exc:
        # PP-H1: fail closed in production — a missing dependency must not silently
        # remove a security control.
        if settings.is_production:
            raise RuntimeError(
                f"slowapi is required when APP_ENV=production but failed to import: {exc}"
            ) from exc
        app.state.limiter = None
        _LOG.warning("slowapi unavailable — rate limiting DISABLED (%s)", exc)
        return

    # PP-M4: a per-process 'memory://' counter drifts across workers/replicas.
    multiworker = settings.is_production or _web_concurrency() > 1
    if multiworker and not settings.rate_limit_storage_uri.startswith("redis"):
        raise RuntimeError(
            "RATE_LIMIT_STORAGE_URI must be a redis:// URI when APP_ENV=production "
            f"or WEB_CONCURRENCY>1 (got {settings.rate_limit_storage_uri!r}) — a "
            "per-process memory store under-counts across workers (PP-M4)."
        )

    limiter = Limiter(
        key_func=lambda request: client_ip(request, settings),
        default_limits=[settings.rate_limit],
        storage_uri=settings.rate_limit_storage_uri,
        headers_enabled=True,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    _LOG.info(
        "rate limiting enabled: %s (store=%s)",
        settings.rate_limit,
        settings.rate_limit_storage_uri,
    )


def rate_limit_exempt(app: FastAPI):
    """Decorator factory: mark a route exempt from the global default limit.

    Usage::

        @app.get("/health")
        @rate_limit_exempt(app)
        def health(): ...
    """
    limiter = getattr(app.state, "limiter", None)

    def _wrap(fn):
        return limiter.exempt(fn) if limiter is not None else fn

    return _wrap


# ============================================================================
# ASGI middleware: security headers (H-4) + body-size cap (M-11)
# ============================================================================

class SecurityHeadersMiddleware:
    """Add HSTS / nosniff / DENY / CSP / COOP to every response (pure ASGI)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        hsts_max_age: int,
        csp_api: str,
        csp_docs: str,
        docs_paths: Iterable[str] = DOCS_PATHS,
    ) -> None:
        self.app = app
        self.hsts_max_age = hsts_max_age
        self.csp_api = csp_api
        self.csp_docs = csp_docs
        self.docs_paths = tuple(docs_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        csp = self.csp_docs if path.startswith(self.docs_paths) else self.csp_api
        hsts = self.hsts_max_age

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message.setdefault("headers", []))
                headers.setdefault("x-content-type-options", "nosniff")
                headers.setdefault("x-frame-options", "DENY")
                headers.setdefault("referrer-policy", "no-referrer")
                headers.setdefault("cross-origin-opener-policy", "same-origin")
                headers.setdefault("content-security-policy", csp)
                if hsts > 0:
                    headers.setdefault(
                        "strict-transport-security",
                        f"max-age={hsts}; includeSubDomains",
                    )
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """
    Reject over-large request bodies at the ASGI edge (M-11).

    * ``Content-Length`` over the cap  -> immediate 413, body never read
    * missing / chunked / lying length -> counted while streaming; on overflow a
      413 is sent (if the response has not started) and the downstream app is
      fed ``http.disconnect`` so it unwinds; anything it then emits is dropped.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.max_bytes <= 0:
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value.decode() or "0") > self.max_bytes:
                        await self._reject(send)
                        return
                except ValueError:
                    pass
                break

        state = {"seen": 0, "started": False, "tripped": False}

        async def recv_wrapper() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                state["seen"] += len(message.get("body", b"") or b"")
                if state["seen"] > self.max_bytes and not state["tripped"]:
                    state["tripped"] = True
                    if not state["started"]:
                        await self._reject(send)
                        state["started"] = True
                    return {"type": "http.disconnect"}
            return message

        async def send_wrapper(message: Message) -> None:
            if state["tripped"]:
                return  # 413 already sent; swallow the app's unwind output
            if message["type"] == "http.response.start":
                state["started"] = True
            await send(message)

        await self.app(scope, recv_wrapper, send_wrapper)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def install_middleware(app: FastAPI, settings: Settings) -> None:
    """
    Wrap the app with the edge middleware. Call this LAST so these end up
    outermost (outer -> inner: body-size, security-headers, rate-limit, CORS,
    auth-defense, router).
    """
    if getattr(app.state, "limiter", None) is not None:
        try:
            from slowapi.middleware import SlowAPIMiddleware

            app.add_middleware(SlowAPIMiddleware)
        except Exception as exc:  # pragma: no cover
            _LOG.warning("SlowAPIMiddleware unavailable (%s)", exc)

    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts_max_age=settings.effective_hsts_max_age,
        csp_api=settings.csp_api,
        csp_docs=settings.csp_docs,
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    _LOG.info(
        "edge middleware installed (body<=%dB, hsts=%ds, env=%s)",
        settings.max_body_bytes,
        settings.effective_hsts_max_age,
        settings.app_env,
    )
