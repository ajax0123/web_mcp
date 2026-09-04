"""
Authentication Defense Integration Middleware
==============================================
FastAPI middleware that integrates all five layers of authentication defense
into the existing CyberGuard API without modifying business logic.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_429_TOO_MANY_REQUESTS, HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED

from cyberguard_api.security.auth_defense import (
    # Layer 1
    multi_tier_limiter,
    AuthRoute,
    # Layer 2
    bot_detector,
    FingerprintComponents,
    ChallengeType,
    # Layer 3
    credential_intel,
    # Layer 4
    mfa_manager,
    lockout_manager,
    step_up_engine,
    StepUpTrigger,
    MFAMethod,
    # Layer 5
    telemetry_manager,
    TelemetryEventType,
    AlertSeverity,
    PlaybookAction,
)
from cyberguard_api.security.core.registry import registry, SecurityConfig
from cyberguard_api.security.core.interfaces import (
    SecurityContext,
    SecurityEvent,
    ThreatLevel,
    AuditAction,
    PolicyDecision,
)


@dataclass
class AuthDefenseConfig:
    """Configuration for authentication defense middleware."""
    enabled: bool = True
    protected_routes: list[str] = None
    excluded_paths: list[str] = None
    enable_rate_limiting: bool = True
    enable_bot_detection: bool = True
    enable_credential_intel: bool = True
    enable_step_up: bool = True
    enable_telemetry: bool = True
    hibp_api_key: Optional[str] = None
    stream_endpoints: list[dict] = None
    action_handlers: dict[PlaybookAction, Callable] = None


class AuthDefenseMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive authentication defense middleware.
    Integrates all five defensive layers around auth endpoints.
    """

    def __init__(
        self,
        app: FastAPI,
        config: Optional[AuthDefenseConfig] = None,
    ) -> None:
        super().__init__(app)
        self.config = config or AuthDefenseConfig()
        self._initialized = False

        # Default protected routes
        if self.config.protected_routes is None:
            self.config.protected_routes = [
                "/login", "/signup", "/password-reset", "/api/token",
                "/mfa/challenge", "/mfa/verify", "/password-change",
                "/account-recovery",
            ]

        # Default excluded paths
        if self.config.excluded_paths is None:
            self.config.excluded_paths = [
                "/health", "/", "/docs", "/openapi.json", "/redoc",
            ]

    async def _initialize(self) -> None:
        """Initialize all defense components."""
        if self._initialized:
            return

        # Initialize credential intelligence
        if self.config.enable_credential_intel:
            await credential_intel.ip_reputation.initialize()

        # Initialize telemetry
        if self.config.enable_telemetry:
            await telemetry_manager.initialize(
                stream_endpoints=self.config.stream_endpoints,
                action_handlers=self.config.action_handlers,
            )

        # Register default SOAR action handlers
        self._register_default_actions()

        self._initialized = True

    def _register_default_actions(self) -> None:
        """Register default SOAR action handlers."""
        # These would integrate with actual firewall/WAF in production
        async def block_ip(ip: str, params: dict, events: list) -> dict:
            # In production: call firewall API
            return {"action": "block_ip", "ip": ip, "simulated": True}

        async def rate_limit_ip(ip: str, params: dict, events: list) -> dict:
            return {"action": "rate_limit_ip", "ip": ip, "simulated": True}

        async def require_mfa(user_id: str, params: dict, events: list) -> dict:
            return {"action": "require_mfa", "user_id": user_id, "simulated": True}

        async def notify_soc(params: dict, events: list) -> dict:
            return {"action": "notify_soc", "simulated": True}

        async def revoke_sessions(user_id: str, params: dict, events: list) -> dict:
            return {"action": "revoke_sessions", "user_id": user_id, "simulated": True}

        handlers = {
            PlaybookAction.BLOCK_IP: block_ip,
            PlaybookAction.RATE_LIMIT_IP: rate_limit_ip,
            PlaybookAction.REQUIRE_MFA: require_mfa,
            PlaybookAction.NOTIFY_SOC: notify_soc,
            PlaybookAction.REVOKE_SESSIONS: revoke_sessions,
            PlaybookAction.BLOCK_ASN: lambda asn, p, e: {"action": "block_asn", "asn": asn, "simulated": True},
            PlaybookAction.RATE_LIMIT_CIDR: lambda cidr, p, e: {"action": "rate_limit_cidr", "cidr": cidr, "simulated": True},
            PlaybookAction.QUARANTINE_ACCOUNT: lambda uid, p, e: {"action": "quarantine_account", "user_id": uid, "simulated": True},
            PlaybookAction.NOTIFY_USER: lambda uid, p, e: {"action": "notify_user", "user_id": uid, "simulated": True},
            PlaybookAction.CREATE_TICKET: lambda p, e: {"action": "create_ticket", "simulated": True},
        }

        for action, handler in handlers.items():
            telemetry_manager.soar.register_action_handler(action, handler)

    def _is_protected_route(self, path: str) -> bool:
        """Check if path is protected by auth defense."""
        if any(path.startswith(excluded) for excluded in self.config.excluded_paths):
            return False
        return any(path.startswith(protected) for protected in self.config.protected_routes)

    def _extract_client_info(self, request: Request) -> dict[str, Any]:
        """Extract client information from request."""
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

        # Get user agent
        user_agent = request.headers.get("user-agent", "")

        # Get device ID from header or cookie
        device_id = request.headers.get("x-device-id") or request.cookies.get("device_id")

        # Get fingerprint ID
        fingerprint_id = request.headers.get("x-fingerprint-id")

        # Get session ID
        session_id = request.headers.get("x-session-id") or request.cookies.get("session_id")

        return {
            "ip": client_ip,
            "user_agent": user_agent,
            "device_id": device_id,
            "fingerprint_id": fingerprint_id,
            "session_id": session_id,
        }

    def _extract_fingerprint(self, request: Request) -> FingerprintComponents:
        """Extract fingerprint components from request."""
        # Passive headers
        fp = FingerprintComponents(
            user_agent=request.headers.get("user-agent", ""),
            accept=request.headers.get("accept", ""),
            accept_language=request.headers.get("accept-language", ""),
            accept_encoding=request.headers.get("accept-encoding", ""),
            connection=request.headers.get("connection", ""),
            upgrade_insecure_requests=request.headers.get("upgrade-insecure-requests", ""),
            sec_fetch_site=request.headers.get("sec-fetch-site", ""),
            sec_fetch_mode=request.headers.get("sec-fetch-mode", ""),
            sec_fetch_dest=request.headers.get("sec-fetch-dest", ""),
            sec_fetch_user=request.headers.get("sec-fetch-user", ""),
            sec_ch_ua=request.headers.get("sec-ch-ua", ""),
            sec_ch_ua_mobile=request.headers.get("sec-ch-ua-mobile", ""),
            sec_ch_ua_platform=request.headers.get("sec-ch-ua-platform", ""),
            sec_ch_ua_full_version_list=request.headers.get("sec-ch-ua-full-version-list", ""),
            cookie=request.headers.get("cookie", ""),
            referer=request.headers.get("referer", ""),
            origin=request.headers.get("origin", ""),
            x_forwarded_for=request.headers.get("x-forwarded-for", ""),
            x_real_ip=request.headers.get("x-real-ip", ""),
            cf_connecting_ip=request.headers.get("cf-connecting-ip", ""),
            true_client_ip=request.headers.get("true-client-ip", ""),
        )

        # Active components would come from JavaScript - check request body for fingerprint
        return fp

    async def _process_auth_request(
        self,
        request: Request,
        client_info: dict[str, Any],
        fingerprint: FingerprintComponents,
    ) -> tuple[bool, Optional[Response], dict[str, Any]]:
        """
        Process authentication request through all defense layers.
        Returns (allowed, response_if_blocked, context).
        """
        context = {
            "request_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "route": request.url.path,
            "method": request.method,
            "client_info": client_info,
            "fingerprint": fingerprint,
        }

        ip = client_info["ip"]
        device_id = client_info["device_id"]
        fingerprint_id = client_info["fingerprint_id"]
        user_id = None  # Will be extracted from request body

        # Try to extract username from request body
        if request.method == "POST":
            try:
                body = await request.body()
                if body:
                    import json
                    data = json.loads(body)
                    user_id = data.get("username") or data.get("email") or data.get("user_id")
                    context["username"] = user_id
                    context["password"] = data.get("password")  # For breach check (never logged)
            except Exception:
                pass

        # ============================================================
        # LAYER 1: Rate Limiting
        # ============================================================
        if self.config.enable_rate_limiting:
            route = AuthRoute(request.url.path)
            allowed, tier_states, mitigations = await multi_tier_limiter.check_all_tiers(
                ip=ip,
                user_id=user_id,
                device_id=device_id,
                fingerprint_id=fingerprint_id,
                route=route,
            )

            context["rate_limit"] = {
                "allowed": allowed,
                "tier_states": {k: v.__dict__ for k, v in tier_states.items()},
                "mitigations": [m.value for m in mitigations],
            }

            # Apply tarpit delay
            if MitigationAction.TARPIT in mitigations:
                ip_state = tier_states.get("ip")
                if ip_state:
                    await multi_tier_limiter.ip_limiter.apply_tarpit(ip_state)

            if not allowed:
                # Record telemetry
                if self.config.enable_telemetry:
                    await telemetry_manager.create_telemetry_event(
                        event_type=TelemetryEventType.RATE_LIMIT_EXCEEDED,
                        user_id=user_id or "",
                        ip_address=ip,
                        risk_score=0.9,
                        threat_categories=["rate_limit"],
                        mitigation_actions=[m.value for m in mitigations],
                        route=request.url.path,
                        method=request.method,
                        request_id=context["request_id"],
                        session_id=client_info["session_id"],
                        details={"tier_states": {k: v.__dict__ for k, v in tier_states.items()}},
                    )

                return False, JSONResponse(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "rate_limit_exceeded",
                        "message": "Too many requests. Please try again later.",
                        "retry_after": 60,
                    },
                    headers={"Retry-After": "60"},
                ), context

        # ============================================================
        # LAYER 2: Bot Detection
        # ============================================================
        bot_challenge = None
        if self.config.enable_bot_detection:
            # Prepare request data for bot detection
            request_data = {
                "username": context.get("username", ""),
                "password": context.get("password", ""),
                "headers": dict(request.headers),
            }

            # Behavioral data from client (would be sent by frontend)
            behavior_data = {
                "keystrokes": request.headers.get("x-keystroke-timings", "").split(",") if request.headers.get("x-keystroke-timings") else [],
                "mouse_movements": [],  # Would be parsed from client
                "timing_events": [],
                "paste_events": int(request.headers.get("x-paste-events", "0")),
            }

            # Convert keystroke timings to integers
            try:
                behavior_data["keystrokes"] = [int(t) for t in behavior_data["keystrokes"] if t]
            except Exception:
                behavior_data["keystrokes"] = []

            bot_result = await bot_detector.analyze(fingerprint, request_data, behavior_data)

            context["bot_detection"] = {
                "is_bot": bot_result.is_bot,
                "confidence": bot_result.confidence,
                "signals": [s.value for s in bot_result.signals],
                "risk_score": bot_result.risk_score,
                "challenge_recommended": bot_result.challenge_recommended.value,
            }

            if bot_result.is_bot:
                # Generate challenge
                bot_challenge = await bot_detector.generate_challenge(fingerprint)
                context["bot_challenge"] = {
                    "challenge_id": bot_challenge.challenge_id,
                    "type": bot_challenge.challenge_type.value,
                    "difficulty": bot_challenge.difficulty,
                    "data": bot_challenge.data,
                }

                # Record telemetry
                if self.config.enable_telemetry:
                    await telemetry_manager.create_telemetry_event(
                        event_type=TelemetryEventType.BOT_DETECTED,
                        user_id=user_id or "",
                        ip_address=ip,
                        risk_score=bot_result.risk_score,
                        threat_categories=[s.value for s in bot_result.signals],
                        mitigation_actions=["challenge"],
                        route=request.url.path,
                        method=request.method,
                        request_id=context["request_id"],
                        session_id=client_info["session_id"],
                        details={"bot_result": context["bot_detection"]},
                    )

        # ============================================================
        # LAYER 3: Credential Intelligence
        # ============================================================
        cred_assessment = None
        if self.config.enable_credential_intel and user_id and context.get("password"):
            # Get geo info (would come from GeoIP in production)
            lat = None
            lon = None

            cred_assessment = await credential_intel.assess_credential_stuffing(
                ip=ip,
                username=user_id,
                password=context["password"],
                user_id=user_id,
                device_id=device_id,
                fingerprint={
                    "user_agent": fingerprint.user_agent,
                    "platform": fingerprint.platform,
                },
                lat=lat,
                lon=lon,
            )

            context["credential_intel"] = {
                "patterns": [p.value for p in cred_assessment.patterns_detected],
                "ip_reputation": cred_assessment.ip_reputation.__dict__ if cred_assessment.ip_reputation else None,
                "geo_velocity": cred_assessment.geo_velocity.__dict__ if cred_assessment.geo_velocity else None,
                "device_anomaly": cred_assessment.device_anomaly.__dict__ if cred_assessment.device_anomaly else None,
                "breached_credential": cred_assessment.breached_credential.__dict__ if cred_assessment.breached_credential else None,
                "overall_risk": cred_assessment.overall_risk,
                "confidence": cred_assessment.confidence,
                "recommended_actions": cred_assessment.recommended_actions,
            }

            # Record telemetry for high-risk findings
            if self.config.enable_telemetry and cred_assessment.overall_risk > 0.7:
                await telemetry_manager.create_telemetry_event(
                    event_type=TelemetryEventType.CREDENTIAL_STUFFING,
                    user_id=user_id,
                    ip_address=ip,
                    risk_score=cred_assessment.overall_risk,
                    threat_categories=[p.value for p in cred_assessment.patterns_detected],
                    mitigation_actions=cred_assessment.recommended_actions,
                    route=request.url.path,
                    method=request.method,
                    request_id=context["request_id"],
                    session_id=client_info["session_id"],
                    details=context["credential_intel"],
                )

        # ============================================================
        # LAYER 4: Step-Up Authentication
        # ============================================================
        step_up_required = False
        step_up_challenges = []

        if self.config.enable_step_up and user_id:
            # Check lockout
            is_locked, lockout = await lockout_manager.check_lockout(user_id)
            if is_locked:
                context["lockout"] = {
                    "locked": True,
                    "state": lockout.state.value,
                    "unlock_at": lockout.unlock_at.isoformat() if lockout.unlock_at else None,
                }

                if self.config.enable_telemetry:
                    await telemetry_manager.create_telemetry_event(
                        event_type=TelemetryEventType.ACCOUNT_LOCKED,
                        user_id=user_id,
                        ip_address=ip,
                        risk_score=1.0,
                        threat_categories=["account_lockout"],
                        mitigation_actions=["block_user"],
                        route=request.url.path,
                        method=request.method,
                        request_id=context["request_id"],
                        session_id=client_info["session_id"],
                    )

                return False, JSONResponse(
                    status_code=HTTP_403_FORBIDDEN,
                    content={
                        "error": "account_locked",
                        "message": "Account temporarily locked due to suspicious activity.",
                        "unlock_at": lockout.unlock_at.isoformat() if lockout.unlock_at else None,
                    },
                ), context

            # Determine step-up triggers
            triggers = []
            risk_score = 0.0

            if cred_assessment:
                risk_score = max(risk_score, cred_assessment.overall_risk)
                if cred_assessment.geo_velocity and cred_assessment.geo_velocity.impossible_travel:
                    triggers.append(StepUpTrigger.IMPOSSIBLE_TRAVEL)
                if cred_assessment.ip_reputation and cred_assessment.ip_reputation.is_tor:
                    triggers.append(StepUpTrigger.HIGH_RISK_IP)
                if cred_assessment.device_anomaly and cred_assessment.device_anomaly.new_device:
                    triggers.append(StepUpTrigger.NEW_DEVICE)
                if cred_assessment.breached_credential and cred_assessment.breached_credential.breached:
                    triggers.append(StepUpTrigger.BREACHED_CREDENTIAL)

            if context.get("bot_detection", {}).get("is_bot"):
                triggers.append(StepUpTrigger.BOT_DETECTED)
                risk_score = max(risk_score, context["bot_detection"]["risk_score"])

            if context.get("rate_limit", {}).get("mitigations"):
                if "challenge" in context["rate_limit"]["mitigations"]:
                    triggers.append(StepUpTrigger.BRUTE_FORCE_DETECTED)

            if triggers:
                step_up = await step_up_engine.evaluate_step_up(
                    user_id=user_id,
                    risk_score=risk_score,
                    triggers=triggers,
                    context=context,
                )

                if step_up.required_methods:
                    step_up_required = True
                    step_up_challenges = await step_up_engine.initiate_step_up(step_up)
                    context["step_up"] = {
                        "required": True,
                        "trigger": step_up.trigger.value,
                        "risk_score": step_up.risk_score,
                        "methods": [m.value for m in step_up.required_methods],
                        "challenges": [
                            {
                                "challenge_id": c.challenge_id,
                                "method": c.method.value,
                                "data": c.challenge_data,
                            }
                            for c in step_up_challenges
                        ],
                    }

                    if self.config.enable_telemetry:
                        await telemetry_manager.create_telemetry_event(
                            event_type=TelemetryEventType.STEP_UP_REQUIRED,
                            user_id=user_id,
                            ip_address=ip,
                            risk_score=risk_score,
                            threat_categories=[t.value for t in triggers],
                            mitigation_actions=["require_mfa"],
                            route=request.url.path,
                            method=request.method,
                            request_id=context["request_id"],
                            session_id=client_info["session_id"],
                        )

        # Return context for downstream processing
        context["bot_challenge_required"] = bot_challenge is not None
        context["step_up_required"] = step_up_required
        context["step_up_challenges"] = step_up_challenges

        return True, None, context

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch."""
        # Initialize on first request
        if not self._initialized:
            await self._initialize()

        # Skip if not protected route
        if not self._is_protected_route(request.url.path):
            return await call_next(request)

        # Skip if auth defense disabled
        if not self.config.enabled:
            return await call_next(request)

        start_time = time.time()

        # Extract client info
        client_info = self._extract_client_info(request)
        fingerprint = self._extract_fingerprint(request)

        # Process through defense layers
        allowed, blocked_response, context = await self._process_auth_request(
            request, client_info, fingerprint
        )

        if not allowed:
            return blocked_response

        # Add defense context to request state for downstream use
        request.state.auth_defense = context

        # Process request
        response = await call_next(request)

        # Record success/failure telemetry
        if self.config.enable_telemetry:
            # Determine if auth succeeded based on response
            is_success = response.status_code < 400
            user_id = context.get("username", "")

            if request.url.path in ["/login", "/api/token"]:
                if is_success:
                    event_type = TelemetryEventType.LOGIN_SUCCESS
                    # Record successful attempt in rate limiter
                    route = AuthRoute(request.url.path)
                    await multi_tier_limiter.record_attempt_all_tiers(
                        ip=client_info["ip"],
                        user_id=user_id,
                        device_id=client_info["device_id"],
                        fingerprint_id=client_info["fingerprint_id"],
                        route=route,
                        success=True,
                    )
                    # Record success in lockout manager
                    if user_id:
                        await lockout_manager.record_success(user_id)
                else:
                    event_type = TelemetryEventType.LOGIN_FAILURE
                    # Record failed attempt in rate limiter
                    route = AuthRoute(request.url.path)
                    await multi_tier_limiter.record_attempt_all_tiers(
                        ip=client_info["ip"],
                        user_id=user_id,
                        device_id=client_info["device_id"],
                        fingerprint_id=client_info["fingerprint_id"],
                        route=route,
                        success=False,
                    )
                    # Record failure in lockout manager
                    if user_id:
                        triggers = context.get("step_up", {}).get("trigger", StepUpTrigger.BRUTE_FORCE_DETECTED)
                        await lockout_manager.record_failed_attempt(user_id, triggers)

                await telemetry_manager.create_telemetry_event(
                    event_type=event_type,
                    user_id=user_id,
                    ip_address=client_info["ip"],
                    risk_score=context.get("credential_intel", {}).get("overall_risk", 0.0),
                    threat_categories=context.get("credential_intel", {}).get("patterns", []),
                    mitigation_actions=context.get("rate_limit", {}).get("mitigations", []),
                    route=request.url.path,
                    method=request.method,
                    request_id=context["request_id"],
                    session_id=client_info["session_id"],
                    details={"duration_ms": (time.time() - start_time) * 1000},
                )

        # Add defense headers
        response.headers["X-Auth-Defense"] = "enabled"
        response.headers["X-Request-ID"] = context.get("request_id", "")

        return response


def create_auth_defense_middleware(
    app: FastAPI,
    config: Optional[AuthDefenseConfig] = None,
) -> AuthDefenseMiddleware:
    """Factory function to create and register auth defense middleware."""
    middleware = AuthDefenseMiddleware(app, config)
    app.add_middleware(AuthDefenseMiddleware, config=config)
    return middleware


@asynccontextmanager
async def auth_defense_lifespan(app: FastAPI):
    """Lifespan context manager for auth defense initialization."""
    # Initialize telemetry
    await telemetry_manager.initialize()
    # Initialize credential intel
    await credential_intel.ip_reputation.initialize()

    yield

    # Shutdown
    await telemetry_manager.shutdown()
    await credential_intel.close()


def get_auth_defense_context(request: Request) -> dict[str, Any]:
    """Dependency to get auth defense context from request state."""
    return getattr(request.state, "auth_defense", {})


def require_bot_challenge_verification(request: Request) -> dict[str, Any]:
    """Dependency to verify bot challenge if required."""
    context = get_auth_defense_context(request)

    if context.get("bot_challenge_required"):
        challenge_id = context.get("bot_challenge", {}).get("challenge_id")
        # In real implementation, verify challenge from request body/header
        # For now, return context with challenge info
        return {"challenge_required": True, "challenge_id": challenge_id}

    return {"challenge_required": False}


def require_step_up_verification(request: Request) -> dict[str, Any]:
    """Dependency to verify step-up authentication if required."""
    context = get_auth_defense_context(request)

    if context.get("step_up_required"):
        return {
            "step_up_required": True,
            "methods": context.get("step_up", {}).get("methods", []),
            "challenges": context.get("step_up_challenges", []),
        }

    return {"step_up_required": False}