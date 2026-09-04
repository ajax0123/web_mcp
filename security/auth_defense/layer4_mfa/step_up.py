"""
Layer 4: Adaptive Multi-Factor & Step-Up Authorization
========================================================
Risk-based step-up triggers, progressive account lockout,
silent session revocation hooks.
"""

from __future__ import annotations

import secrets
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Optional
import httpx


class MFAMethod(str, Enum):
    """Multi-factor authentication methods."""
    TOTP = "totp"  # Time-based One-Time Password (Google Authenticator, Authy)
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"  # Push notification (Duo, Auth0 Guardian)
    WEBAUTHN = "webauthn"  # FIDO2/WebAuthn (YubiKey, TouchID, Windows Hello)
    BACKUP_CODES = "backup_codes"
    RECOVERY_EMAIL = "recovery_email"


class StepUpTrigger(str, Enum):
    """Triggers for step-up authentication."""
    NEW_DEVICE = "new_device"
    HIGH_RISK_IP = "high_risk_ip"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    CREDENTIAL_STUFFING = "credential_stuffing"
    BOT_DETECTED = "bot_detected"
    BREACHED_CREDENTIAL = "breached_credential"
    SENSITIVE_ACTION = "sensitive_action"
    ADMIN_ACTION = "admin_action"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    POLICY_REQUIRED = "policy_required"


class LockoutState(str, Enum):
    """Account lockout states."""
    ACTIVE = "active"
    SOFT_LOCKED = "soft_locked"  # Temporary, auto-unlock
    HARD_LOCKED = "hard_locked"  # Requires admin/unlock flow
    QUARANTINED = "quarantined"  # Under active attack


@dataclass
class MFAEnrollment:
    """MFA method enrollment record."""
    enrollment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    method: MFAMethod = MFAMethod.TOTP
    config: dict[str, Any] = field(default_factory=dict)  # secret, phone, email, credential_id
    verified: bool = False
    enrolled_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: Optional[datetime] = None
    backup_codes: list[str] = field(default_factory=list)


@dataclass
class MFAChallenge:
    """MFA challenge for verification."""
    challenge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    method: MFAMethod = MFAMethod.TOTP
    challenge_data: dict[str, Any] = field(default_factory=dict)  # e.g., {"code": "123456"} for TOTP
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=5))
    verified: bool = False
    verified_at: Optional[datetime] = None
    attempts: int = 0
    max_attempts: int = 3


@dataclass
class AccountLockout:
    """Account lockout record."""
    user_id: str
    state: LockoutState = LockoutState.ACTIVE
    trigger: StepUpTrigger = StepUpTrigger.BRUTE_FORCE_DETECTED
    failed_attempts: int = 0
    locked_at: Optional[datetime] = None
    unlock_at: Optional[datetime] = None
    unlock_method: str = ""  # auto, admin, user_action, mfa
    lockout_count: int = 0  # Progressive lockout counter
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StepUpRequest:
    """Step-up authentication request."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    trigger: StepUpTrigger = StepUpTrigger.NEW_DEVICE
    risk_score: float = 0.0
    context: dict[str, Any] = field(default_factory=dict)
    required_methods: list[MFAMethod] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    success: bool = False


@dataclass
class SessionRevocationEvent:
    """Session revocation event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    reason: str = ""
    revoked_session_ids: list[str] = field(default_factory=list)
    revoked_count: int = 0
    triggered_by: str = "system"  # system, admin, user, security_event
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


class TOTPManager:
    """TOTP (RFC 6238) management for authenticator apps."""

    def __init__(self, issuer: str = "CyberGuard", digits: int = 6, period: int = 30) -> None:
        self.issuer = issuer
        self.digits = digits
        self.period = period

    def generate_secret(self, length: int = 20) -> str:
        """Generate base32 secret for TOTP."""
        import base64
        return base64.b32encode(secrets.token_bytes(length)).decode().rstrip("=")

    def get_provisioning_uri(self, secret: str, account_name: str) -> str:
        """Get otpauth:// URI for QR code."""
        import urllib.parse
        params = {
            "secret": secret,
            "issuer": self.issuer,
            "algorithm": "SHA1",
            "digits": str(self.digits),
            "period": str(self.period),
        }
        query = urllib.parse.urlencode(params)
        label = urllib.parse.quote(f"{self.issuer}:{account_name}")
        return f"otpauth://totp/{label}?{query}"

    def verify_totp(self, secret: str, code: str, window: int = 1) -> bool:
        """Verify TOTP code with time window."""
        import hmac
        import base64
        import time

        try:
            key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret)) % 8))
        except Exception:
            return False

        current_counter = int(time.time()) // self.period

        for i in range(-window, window + 1):
            counter = current_counter + i
            counter_bytes = counter.to_bytes(8, "big")
            hmac_hash = hmac.new(key, counter_bytes, "sha1").digest()

            offset = hmac_hash[-1] & 0x0F
            code_int = (
                ((hmac_hash[offset] & 0x7F) << 24) |
                ((hmac_hash[offset + 1] & 0xFF) << 16) |
                ((hmac_hash[offset + 2] & 0xFF) << 8) |
                (hmac_hash[offset + 3] & 0xFF)
            ) % (10 ** self.digits)

            expected_code = str(code_int).zfill(self.digits)
            if secrets.compare_digest(expected_code, code):
                return True

        return False


class SMSProvider(ABC):
    """Abstract SMS provider for MFA."""

    @abstractmethod
    async def send_sms(self, phone: str, code: str) -> bool:
        pass


class EmailProvider(ABC):
    """Abstract email provider for MFA."""

    @abstractmethod
    async def send_email(self, email: str, subject: str, body: str, code: str) -> bool:
        pass


class PushProvider(ABC):
    """Abstract push notification provider."""

    @abstractmethod
    async def send_push(self, user_id: str, title: str, body: str, data: dict) -> str:
        """Send push, return push_id."""
        pass

    @abstractmethod
    async def check_push_status(self, push_id: str) -> dict:
        """Check push verification status."""
        pass


class WebAuthnManager:
    """WebAuthn/FIDO2 credential management."""

    def __init__(self, rp_id: str, rp_name: str, origin: str) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin

    def generate_registration_options(
        self,
        user_id: str,
        username: str,
        display_name: str,
        exclude_credentials: list[dict] = None,
    ) -> dict:
        """Generate WebAuthn registration options."""
        import base64
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")

        return {
            "publicKey": {
                "rp": {"id": self.rp_id, "name": self.rp_name},
                "user": {
                    "id": base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("="),
                    "name": username,
                    "displayName": display_name,
                },
                "challenge": challenge,
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},  # ES256
                    {"type": "public-key", "alg": -257},  # RS256
                ],
                "timeout": 60000,
                "excludeCredentials": exclude_credentials or [],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "requireResidentKey": False,
                    "userVerification": "preferred",
                },
                "attestation": "direct",
            }
        }

    def generate_authentication_options(
        self,
        allow_credentials: list[dict] = None,
    ) -> dict:
        """Generate WebAuthn authentication options."""
        import base64
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")

        return {
            "publicKey": {
                "challenge": challenge,
                "timeout": 60000,
                "rpId": self.rp_id,
                "allowCredentials": allow_credentials or [],
                "userVerification": "preferred",
            }
        }

    def verify_registration(self, response: dict, expected_challenge: str) -> tuple[bool, dict]:
        """Verify WebAuthn registration response."""
        # In production, use proper WebAuthn library (webauthn, py_webauthn)
        # This is a simplified placeholder
        return True, {"credential_id": "placeholder", "public_key": "placeholder"}

    def verify_authentication(self, response: dict, expected_challenge: str, credential: dict) -> bool:
        """Verify WebAuthn authentication response."""
        # In production, use proper WebAuthn library
        return True


class MFAManager:
    """
    Central MFA management with support for multiple methods.
    """

    def __init__(
        self,
        totp_issuer: str = "CyberGuard",
        sms_provider: Optional[SMSProvider] = None,
        email_provider: Optional[EmailProvider] = None,
        push_provider: Optional[PushProvider] = None,
        webauthn_manager: Optional[WebAuthnManager] = None,
    ) -> None:
        self.totp = TOTPManager(issuer=totp_issuer)
        self.sms_provider = sms_provider
        self.email_provider = email_provider
        self.push_provider = push_provider
        self.webauthn = webauthn_manager

        self._enrollments: dict[str, list[MFAEnrollment]] = defaultdict(list)
        self._challenges: dict[str, MFAChallenge] = {}
        self._lock = asyncio.Lock()

    async def enroll_totp(self, user_id: str) -> tuple[str, str]:
        """Enroll user in TOTP. Returns (secret, provisioning_uri)."""
        secret = self.totp.generate_secret()
        uri = self.totp.get_provisioning_uri(secret, user_id)

        enrollment = MFAEnrollment(
            user_id=user_id,
            method=MFAMethod.TOTP,
            config={"secret": secret},
            verified=False,
        )

        async with self._lock:
            self._enrollments[user_id].append(enrollment)

        return secret, uri

    async def verify_totp_enrollment(self, user_id: str, code: str) -> bool:
        """Verify TOTP enrollment code."""
        async with self._lock:
            enrollments = self._enrollments.get(user_id, [])
            for e in enrollments:
                if e.method == MFAMethod.TOTP and not e.verified:
                    if self.totp.verify_totp(e.config["secret"], code):
                        e.verified = True
                        return True
        return False

    async def enroll_sms(self, user_id: str, phone: str) -> bool:
        """Enroll user in SMS MFA."""
        if not self.sms_provider:
            return False

        code = str(secrets.randbelow(1000000)).zfill(6)
        sent = await self.sms_provider.send_sms(phone, code)

        if sent:
            enrollment = MFAEnrollment(
                user_id=user_id,
                method=MFAMethod.SMS,
                config={"phone": phone, "pending_code": code},
                verified=False,
            )
            async with self._lock:
                self._enrollments[user_id].append(enrollment)
            return True
        return False

    async def verify_sms_enrollment(self, user_id: str, code: str) -> bool:
        """Verify SMS enrollment code."""
        async with self._lock:
            enrollments = self._enrollments.get(user_id, [])
            for e in enrollments:
                if e.method == MFAMethod.SMS and not e.verified:
                    if secrets.compare_digest(e.config.get("pending_code", ""), code):
                        e.verified = True
                        e.config.pop("pending_code", None)
                        return True
        return False

    async def enroll_email(self, user_id: str, email: str) -> bool:
        """Enroll user in email MFA."""
        if not self.email_provider:
            return False

        code = str(secrets.randbelow(1000000)).zfill(6)
        sent = await self.email_provider.send_email(
            email, "Your CyberGuard Verification Code", f"Your code is: {code}", code
        )

        if sent:
            enrollment = MFAEnrollment(
                user_id=user_id,
                method=MFAMethod.EMAIL,
                config={"email": email, "pending_code": code},
                verified=False,
            )
            async with self._lock:
                self._enrollments[user_id].append(enrollment)
            return True
        return False

    async def verify_email_enrollment(self, user_id: str, code: str) -> bool:
        """Verify email enrollment code."""
        async with self._lock:
            enrollments = self._enrollments.get(user_id, [])
            for e in enrollments:
                if e.method == MFAMethod.EMAIL and not e.verified:
                    if secrets.compare_digest(e.config.get("pending_code", ""), code):
                        e.verified = True
                        e.config.pop("pending_code", None)
                        return True
        return False

    async def create_challenge(
        self,
        user_id: str,
        method: MFAMethod,
        context: dict[str, Any] = None,
    ) -> MFAChallenge:
        """Create MFA challenge."""
        challenge = MFAChallenge(
            user_id=user_id,
            method=method,
            challenge_data=context or {},
        )

        # Generate challenge based on method
        if method == MFAMethod.TOTP:
            # TOTP - no server-side challenge needed, just verify code
            pass
        elif method == MFAMethod.SMS:
            enrollments = self.get_enrollments(user_id, MFAMethod.SMS)
            if enrollments:
                code = str(secrets.randbelow(1000000)).zfill(6)
                await self.sms_provider.send_sms(enrollments[0].config["phone"], code)
                challenge.challenge_data["expected_code"] = code
        elif method == MFAMethod.EMAIL:
            enrollments = self.get_enrollments(user_id, MFAMethod.EMAIL)
            if enrollments:
                code = str(secrets.randbelow(1000000)).zfill(6)
                await self.email_provider.send_email(
                    enrollments[0].config["email"],
                    "CyberGuard Verification Code",
                    f"Your code is: {code}",
                    code
                )
                challenge.challenge_data["expected_code"] = code
        elif method == MFAMethod.PUSH:
            if self.push_provider:
                push_id = await self.push_provider.send_push(
                    user_id,
                    "Sign-in Request",
                    "Someone is trying to sign in to your account.",
                    {"action": "verify_signin", "challenge_id": challenge.challenge_id}
                )
                challenge.challenge_data["push_id"] = push_id
        elif method == MFAMethod.WEBAUTHN:
            if self.webauthn:
                enrollments = self.get_enrollments(user_id, MFAMethod.WEBAUTHN)
                if enrollments:
                    options = self.webauthn.generate_authentication_options(
                        allow_credentials=[{"id": e.config.get("credential_id", ""), "type": "public-key"} for e in enrollments]
                    )
                    challenge.challenge_data["webauthn_options"] = options

        async with self._lock:
            self._challenges[challenge.challenge_id] = challenge

        return challenge

    async def verify_challenge(self, challenge_id: str, response: dict) -> bool:
        """Verify MFA challenge response."""
        async with self._lock:
            challenge = self._challenges.get(challenge_id)

        if not challenge:
            return False

        if datetime.now(timezone.utc) > challenge.expires_at:
            return False

        if challenge.attempts >= challenge.max_attempts:
            return False

        challenge.attempts += 1

        verified = False

        if challenge.method == MFAMethod.TOTP:
            enrollments = self.get_enrollments(challenge.user_id, MFAMethod.TOTP)
            for e in enrollments:
                if e.verified and self.totp.verify_totp(e.config["secret"], response.get("code", "")):
                    verified = True
                    break

        elif challenge.method in [MFAMethod.SMS, MFAMethod.EMAIL]:
            expected = challenge.challenge_data.get("expected_code", "")
            provided = response.get("code", "")
            verified = secrets.compare_digest(expected, provided)

        elif challenge.method == MFAMethod.PUSH:
            if self.push_provider:
                push_id = challenge.challenge_data.get("push_id")
                status = await self.push_provider.check_push_status(push_id)
                verified = status.get("verified", False)

        elif challenge.method == MFAMethod.WEBAUTHN:
            if self.webauthn:
                expected_challenge = challenge.challenge_data.get("webauthn_options", {}).get("publicKey", {}).get("challenge")
                verified = self.webauthn.verify_authentication(response, expected_challenge, {})

        elif challenge.method == MFAMethod.BACKUP_CODES:
            code = response.get("code", "")
            enrollments = self.get_enrollments(challenge.user_id, MFAMethod.BACKUP_CODES)
            for e in enrollments:
                if code in e.backup_codes:
                    e.backup_codes.remove(code)  # Single use
                    verified = True
                    break

        if verified:
            challenge.verified = True
            challenge.verified_at = datetime.now(timezone.utc)

            # Update enrollment last_used
            async with self._lock:
                enrollments = self._enrollments.get(challenge.user_id, [])
                for e in enrollments:
                    if e.method == challenge.method:
                        e.last_used = datetime.now(timezone.utc)

        return verified

    def get_enrollments(self, user_id: str, method: Optional[MFAMethod] = None) -> list[MFAEnrollment]:
        """Get user's MFA enrollments."""
        enrollments = self._enrollments.get(user_id, [])
        if method:
            return [e for e in enrollments if e.method == method]
        return enrollments

    def has_verified_method(self, user_id: str, method: MFAMethod) -> bool:
        """Check if user has verified MFA method."""
        return any(e.verified for e in self.get_enrollments(user_id, method))

    def get_verified_methods(self, user_id: str) -> list[MFAMethod]:
        """Get list of verified MFA methods for user."""
        return [
            e.method for e in self._enrollments.get(user_id, [])
            if e.verified
        ]

    async def revoke_all(self, user_id: str) -> int:
        """Revoke all MFA enrollments for user."""
        async with self._lock:
            count = len(self._enrollments.get(user_id, []))
            self._enrollments[user_id] = []
            return count


class LockoutManager:
    """
    Progressive account lockout with DoS protection.
    """

    # Progressive lockout durations (minutes)
    LOCKOUT_DURATIONS = [5, 15, 60, 240, 1440]  # 5m, 15m, 1h, 4h, 24h

    def __init__(self) -> None:
        self._lockouts: dict[str, AccountLockout] = {}
        self._lock = asyncio.Lock()

    def _get_lockout_duration(self, lockout_count: int) -> int:
        """Get lockout duration for progressive lockout count."""
        index = min(lockout_count, len(self.LOCKOUT_DURATIONS) - 1)
        return self.LOCKOUT_DURATIONS[index]

    async def record_failed_attempt(
        self,
        user_id: str,
        trigger: StepUpTrigger,
        metadata: dict[str, Any] = None,
    ) -> AccountLockout:
        """Record failed attempt and potentially lock account."""
        async with self._lock:
            lockout = self._lockouts.get(user_id)

            if not lockout:
                lockout = AccountLockout(user_id=user_id)
                self._lockouts[user_id] = lockout

            lockout.failed_attempts += 1
            lockout.trigger = trigger
            if metadata:
                lockout.metadata.update(metadata)

            # Check if should lock
            if lockout.failed_attempts >= 5:  # Threshold
                if lockout.state == LockoutState.ACTIVE:
                    lockout.state = LockoutState.SOFT_LOCKED
                    lockout.lockout_count += 1
                    duration = self._get_lockout_duration(lockout.lockout_count)
                    lockout.locked_at = datetime.now(timezone.utc)
                    lockout.unlock_at = lockout.locked_at + timedelta(minutes=duration)
                    lockout.unlock_method = "auto"

            return lockout

    async def record_success(self, user_id: str) -> None:
        """Record successful authentication - reset failed attempts."""
        async with self._lock:
            if user_id in self._lockouts:
                lockout = self._lockouts[user_id]
                lockout.failed_attempts = 0
                if lockout.state == LockoutState.SOFT_LOCKED:
                    lockout.state = LockoutState.ACTIVE
                    lockout.locked_at = None
                    lockout.unlock_at = None

    async def check_lockout(self, user_id: str) -> tuple[bool, Optional[AccountLockout]]:
        """Check if account is locked. Returns (is_locked, lockout)."""
        async with self._lock:
            lockout = self._lockouts.get(user_id)

            if not lockout or lockout.state == LockoutState.ACTIVE:
                return False, None

            if lockout.state == LockoutState.SOFT_LOCKED:
                if lockout.unlock_at and datetime.now(timezone.utc) >= lockout.unlock_at:
                    # Auto-unlock
                    lockout.state = LockoutState.ACTIVE
                    lockout.failed_attempts = 0
                    lockout.locked_at = None
                    lockout.unlock_at = None
                    lockout.unlock_method = "auto"
                    return False, None
                return True, lockout

            # Hard locked or quarantined
            return True, lockout

    async def unlock_account(self, user_id: str, method: str = "admin") -> bool:
        """Unlock account manually."""
        async with self._lock:
            if user_id in self._lockouts:
                lockout = self._lockouts[user_id]
                lockout.state = LockoutState.ACTIVE
                lockout.failed_attempts = 0
                lockout.locked_at = None
                lockout.unlock_at = None
                lockout.unlock_method = method
                return True
        return False

    async def quarantine_account(self, user_id: str, reason: str) -> AccountLockout:
        """Quarantine account under active attack."""
        async with self._lock:
            lockout = self._lockouts.get(user_id)
            if not lockout:
                lockout = AccountLockout(user_id=user_id)
                self._lockouts[user_id] = lockout

            lockout.state = LockoutState.QUARANTINED
            lockout.trigger = StepUpTrigger.CREDENTIAL_STUFFING
            lockout.locked_at = datetime.now(timezone.utc)
            lockout.metadata["quarantine_reason"] = reason
            return lockout


class StepUpEngine:
    """
    Risk-based step-up authentication engine.
    Determines when to require additional authentication factors.
    """

    def __init__(
        self,
        mfa_manager: MFAManager,
        lockout_manager: LockoutManager,
    ) -> None:
        self.mfa = mfa_manager
        self.lockout = lockout_manager

        # Risk thresholds for step-up
        self.step_up_threshold = 0.5
        self.mfa_required_threshold = 0.7

        # Trigger configurations
        self.trigger_config = {
            StepUpTrigger.NEW_DEVICE: {"risk": 0.4, "methods": [MFAMethod.EMAIL, MFAMethod.TOTP]},
            StepUpTrigger.HIGH_RISK_IP: {"risk": 0.6, "methods": [MFAMethod.TOTP, MFAMethod.PUSH]},
            StepUpTrigger.IMPOSSIBLE_TRAVEL: {"risk": 0.8, "methods": [MFAMethod.TOTP, MFAMethod.WEBAUTHN, MFAMethod.PUSH]},
            StepUpTrigger.BRUTE_FORCE_DETECTED: {"risk": 0.7, "methods": [MFAMethod.TOTP, MFAMethod.EMAIL]},
            StepUpTrigger.CREDENTIAL_STUFFING: {"risk": 0.8, "methods": [MFAMethod.TOTP, MFAMethod.WEBAUTHN, MFAMethod.PUSH]},
            StepUpTrigger.BOT_DETECTED: {"risk": 0.6, "methods": [MFAMethod.TOTP, MFAMethod.PUSH]},
            StepUpTrigger.BREACHED_CREDENTIAL: {"risk": 0.9, "methods": [MFAMethod.TOTP, MFAMethod.WEBAUTHN]},
            StepUpTrigger.SENSITIVE_ACTION: {"risk": 0.5, "methods": [MFAMethod.TOTP]},
            StepUpTrigger.ADMIN_ACTION: {"risk": 0.7, "methods": [MFAMethod.WEBAUTHN, MFAMethod.TOTP]},
        }

    async def evaluate_step_up(
        self,
        user_id: str,
        risk_score: float,
        triggers: list[StepUpTrigger],
        context: dict[str, Any],
    ) -> StepUpRequest:
        """Evaluate if step-up authentication is required."""
        # Check lockout first
        is_locked, lockout = await self.lockout.check_lockout(user_id)
        if is_locked:
            return StepUpRequest(
                user_id=user_id,
                trigger=lockout.trigger,
                risk_score=1.0,
                context={"lockout": True, "lockout_state": lockout.state.value},
                required_methods=[],
            )

        # Determine required step-up based on triggers and risk
        max_risk = risk_score
        required_methods = []
        primary_trigger = triggers[0] if triggers else StepUpTrigger.ANOMALOUS_BEHAVIOR

        for trigger in triggers:
            config = self.trigger_config.get(trigger, {})
            trigger_risk = config.get("risk", 0.5)
            if trigger_risk > max_risk:
                max_risk = trigger_risk
                primary_trigger = trigger
            required_methods.extend(config.get("methods", []))

        # Deduplicate methods
        required_methods = list(dict.fromkeys(required_methods))

        # Filter to only methods user has enrolled
        verified_methods = self.mfa.get_verified_methods(user_id)
        required_methods = [m for m in required_methods if m in verified_methods]

        # If no verified methods match, fall back to available methods
        if not required_methods and verified_methods:
            required_methods = verified_methods[:2]  # Use first 2 available

        step_up = StepUpRequest(
            user_id=user_id,
            trigger=primary_trigger,
            risk_score=max_risk,
            context=context,
            required_methods=required_methods,
        )

        return step_up

    async def initiate_step_up(self, step_up: StepUpRequest) -> list[MFAChallenge]:
        """Initiate step-up challenges for required methods."""
        challenges = []

        for method in step_up.required_methods:
            challenge = await self.mfa.create_challenge(step_up.user_id, method, step_up.context)
            challenges.append(challenge)

        return challenges

    async def verify_step_up(self, step_up: StepUpRequest, responses: dict[str, Any]) -> bool:
        """Verify all step-up challenges."""
        for method in step_up.required_methods:
            challenge_id = responses.get(f"{method.value}_challenge_id")
            if not challenge_id:
                return False

            response_data = responses.get(method.value, {})
            verified = await self.mfa.verify_challenge(challenge_id, response_data)

            if not verified:
                return False

        step_up.success = True
        step_up.completed_at = datetime.now(timezone.utc)
        return True


class SessionRevocationManager:
    """
    Silent session revocation for ATO response.
    """

    def __init__(self, session_manager) -> None:
        self.session_manager = session_manager
        self._revocation_events: list[SessionRevocationEvent] = []
        self._revocation_hooks: list[Callable] = []

    def register_revocation_hook(self, hook: Callable) -> None:
        """Register hook to be called on session revocation."""
        self._revocation_hooks.append(hook)

    async def revoke_all_sessions(
        self,
        user_id: str,
        reason: str,
        triggered_by: str = "system",
        exclude_session: Optional[str] = None,
    ) -> SessionRevocationEvent:
        """Revoke all sessions for user (ATO response)."""
        # Get all sessions
        sessions = await self.session_manager.get_user_sessions(user_id)
        session_ids = [s["session_id"] for s in sessions if s["session_id"] != exclude_session]

        # Revoke each session
        revoked = 0
        for sid in session_ids:
            if await self.session_manager.revoke_session(sid):
                revoked += 1

        # Create revocation event
        event = SessionRevocationEvent(
            user_id=user_id,
            reason=reason,
            revoked_session_ids=session_ids,
            revoked_count=revoked,
            triggered_by=triggered_by,
            metadata={"excluded_session": exclude_session},
        )

        self._revocation_events.append(event)

        # Call hooks
        for hook in self._revocation_hooks:
            try:
                await hook(event)
            except Exception:
                pass

        return event

    async def revoke_sessions_by_criteria(
        self,
        user_id: str,
        criteria: dict[str, Any],
        reason: str,
    ) -> SessionRevocationEvent:
        """Revoke sessions matching criteria (e.g., specific device, IP, location)."""
        sessions = await self.session_manager.get_user_sessions(user_id)

        to_revoke = []
        for session in sessions:
            match = True
            for key, value in criteria.items():
                if session.get(key) != value:
                    match = False
                    break
            if match:
                to_revoke.append(session["session_id"])

        revoked = 0
        for sid in to_revoke:
            if await self.session_manager.revoke_session(sid):
                revoked += 1

        event = SessionRevocationEvent(
            user_id=user_id,
            reason=reason,
            revoked_session_ids=to_revoke,
            revoked_count=revoked,
            triggered_by="system",
            metadata={"criteria": criteria},
        )

        self._revocation_events.append(event)
        return event

    def get_revocation_history(self, user_id: str, limit: int = 50) -> list[SessionRevocationEvent]:
        """Get session revocation history for user."""
        return [
            e for e in self._revocation_events
            if e.user_id == user_id
        ][-limit:]


import asyncio


# Global instances
mfa_manager = MFAManager()
lockout_manager = LockoutManager()
step_up_engine = StepUpEngine(mfa_manager, lockout_manager)