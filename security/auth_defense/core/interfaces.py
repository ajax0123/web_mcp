"""
Authentication Defense Core Interfaces
======================================
Foundational types for the anti-brute-force, anti-credential-stuffing,
and bot mitigation defense architecture.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class AuthRoute(str, Enum):
    """High-risk authentication routes requiring protection."""
    LOGIN = "/login"
    SIGNUP = "/signup"
    PASSWORD_RESET = "/password-reset"
    TOKEN_REFRESH = "/api/token"
    MFA_CHALLENGE = "/mfa/challenge"
    MFA_VERIFY = "/mfa/verify"
    PASSWORD_CHANGE = "/password-change"
    ACCOUNT_RECOVERY = "/account-recovery"


class ThreatCategory(str, Enum):
    """Authentication threat categories."""
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    BOT_AUTOMATION = "bot_automation"
    PASSWORD_SPRAY = "password_spray"
    ACCOUNT_TAKEOVER = "account_takeover"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    DEVICE_ANOMALY = "device_anomaly"
    BREACHED_CREDENTIAL = "breached_credential"
    PROXY_TOR = "proxy_tor"
    DISTRIBUTED_ATTACK = "distributed_attack"


class MitigationAction(str, Enum):
    """Mitigation actions for detected threats."""
    ALLOW = "allow"
    TARPIT = "tarpit"  # Artificial delay
    CHALLENGE = "challenge"  # CAPTCHA, proof-of-work
    RATE_LIMIT = "rate_limit"
    BLOCK_IP = "block_ip"
    BLOCK_USER = "block_user"
    REQUIRE_MFA = "require_mfa"
    REQUIRE_EMAIL_VERIFY = "require_email_verify"
    LOCK_ACCOUNT = "lock_account"
    REVOKE_SESSIONS = "revoke_sessions"
    QUARANTINE = "quarantine"


class RiskLevel(str, Enum):
    """Risk assessment levels."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ClientFingerprint:
    """Client device/browser fingerprint."""
    fingerprint_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_agent: str = ""
    accept_language: str = ""
    accept_encoding: str = ""
    screen_resolution: str = ""
    timezone: str = ""
    platform: str = ""
    canvas_hash: str = ""
    webgl_hash: str = ""
    audio_hash: str = ""
    fonts_hash: str = ""
    plugins_hash: str = ""
    hardware_concurrency: int = 0
    device_memory: int = 0
    touch_support: bool = False
    cookie_enabled: bool = True
    js_enabled: bool = True
    headers_hash: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuthAttempt:
    """Authentication attempt record."""
    attempt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    route: AuthRoute = AuthRoute.LOGIN
    identifier: str = ""  # username, email, or IP
    ip_address: str = ""
    client_fingerprint: Optional[ClientFingerprint] = None
    success: bool = False
    failure_reason: str = ""
    risk_score: float = 0.0
    threat_categories: list[ThreatCategory] = field(default_factory=list)
    mitigation_applied: list[MitigationAction] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitState:
    """Rate limit state for an identifier."""
    identifier: str
    identifier_type: str  # ip, user, device, fingerprint
    window_start: datetime
    request_count: int = 0
    failed_count: int = 0
    success_count: int = 0
    penalty_until: Optional[datetime] = None
    penalty_level: int = 0  # 0 = no penalty, 1 = tarpit, 2 = challenge, 3 = block
    last_request: Optional[datetime] = None


@dataclass
class RiskAssessment:
    """Authentication risk assessment result."""
    request_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    overall_risk: RiskLevel = RiskLevel.NONE
    risk_score: float = 0.0  # 0.0 - 1.0
    threat_categories: list[ThreatCategory] = field(default_factory=list)
    factors: dict[str, float] = field(default_factory=dict)  # factor -> score
    recommended_actions: list[MitigationAction] = field(default_factory=list)
    requires_step_up: bool = False
    step_up_reasons: list[str] = field(default_factory=list)


@dataclass
class BreachedCredentialCheck:
    """Result of breached credential check."""
    checked: bool = False
    breached: bool = False
    breach_count: int = 0
    breach_sources: list[str] = field(default_factory=list)
    last_breach_date: Optional[datetime] = None
    recommendation: str = ""


class RateLimiter(ABC):
    """Abstract rate limiter interface."""

    @abstractmethod
    async def check_limit(
        self,
        identifier: str,
        identifier_type: str,
        route: AuthRoute,
        cost: int = 1,
    ) -> tuple[bool, RateLimitState]:
        """Check rate limit. Returns (allowed, state)."""
        pass

    @abstractmethod
    async def record_attempt(
        self,
        identifier: str,
        identifier_type: str,
        route: AuthRoute,
        success: bool,
    ) -> RateLimitState:
        """Record authentication attempt."""
        pass

    @abstractmethod
    async def get_state(
        self,
        identifier: str,
        identifier_type: str,
        route: AuthRoute,
    ) -> Optional[RateLimitState]:
        """Get current rate limit state."""
        pass

    @abstractmethod
    async def reset(self, identifier: str, identifier_type: str, route: AuthRoute) -> None:
        """Reset rate limit state."""
        pass


class BotDetector(ABC):
    """Abstract bot detection interface."""

    @abstractmethod
    async def analyze(
        self,
        fingerprint: ClientFingerprint,
        request_data: dict[str, Any],
        behavior_data: dict[str, Any],
    ) -> tuple[bool, float, list[str]]:
        """
        Analyze for bot behavior.
        Returns (is_bot, confidence, indicators).
        """
        pass

    @abstractmethod
    async def generate_challenge(self, fingerprint: ClientFingerprint) -> dict[str, Any]:
        """Generate bot challenge (CAPTCHA, proof-of-work, etc.)."""
        pass

    @abstractmethod
    async def verify_challenge(self, challenge_id: str, response: Any) -> bool:
        """Verify challenge response."""
        pass


class CredentialIntelligence(ABC):
    """Abstract credential intelligence interface."""

    @abstractmethod
    async def check_password_breach(self, password: str) -> BreachedCredentialCheck:
        """Check if password appears in breach databases."""
        pass

    @abstractmethod
    async def check_ip_reputation(self, ip: str) -> dict[str, Any]:
        """Check IP reputation (Tor, proxy, hosting, malicious)."""
        pass

    @abstractmethod
    async def check_credential_stuffing_pattern(
        self,
        ip: str,
        username: str,
        fingerprint: ClientFingerprint,
    ) -> dict[str, Any]:
        """Check for credential stuffing patterns."""
        pass


class MFAProvider(ABC):
    """Abstract MFA provider interface."""

    @abstractmethod
    async def enroll(self, user_id: str, method: str) -> dict[str, Any]:
        """Enroll user in MFA."""
        pass

    @abstractmethod
    async def challenge(self, user_id: str, method: str) -> dict[str, Any]:
        """Generate MFA challenge."""
        pass

    @abstractmethod
    async def verify(self, user_id: str, method: str, response: str) -> bool:
        """Verify MFA response."""
        pass

    @abstractmethod
    async def revoke_all(self, user_id: str) -> bool:
        """Revoke all MFA methods for user."""
        pass


class SessionManager(ABC):
    """Abstract session management interface."""

    @abstractmethod
    async def create_session(
        self,
        user_id: str,
        device_info: dict[str, Any],
        risk_level: RiskLevel,
    ) -> str:
        """Create new session. Returns session_id."""
        pass

    @abstractmethod
    async def validate_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """Validate session. Returns session data or None."""
        pass

    @abstractmethod
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke specific session."""
        pass

    @abstractmethod
    async def revoke_all_sessions(self, user_id: str, reason: str) -> int:
        """Revoke all sessions for user. Returns count."""
        pass

    @abstractmethod
    async def get_user_sessions(self, user_id: str) -> list[dict[str, Any]]:
        """Get all active sessions for user."""
        pass


class AuthTelemetry(ABC):
    """Abstract authentication telemetry interface."""

    @abstractmethod
    async def record_attempt(self, attempt: AuthAttempt) -> None:
        """Record authentication attempt."""
        pass

    @abstractmethod
    async def record_risk_assessment(self, assessment: RiskAssessment) -> None:
        """Record risk assessment."""
        pass

    @abstractmethod
    async def record_mitigation(
        self,
        identifier: str,
        action: MitigationAction,
        reason: str,
        metadata: dict[str, Any],
    ) -> None:
        """Record mitigation action."""
        pass

    @abstractmethod
    async def get_attack_summary(
        self,
        since: datetime,
        group_by: str = "ip",
    ) -> dict[str, Any]:
        """Get attack summary for time window."""
        pass