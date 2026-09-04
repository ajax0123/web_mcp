"""
Security Registry
=================
Central coordination point for all five security layers.
Manages initialization, configuration, and cross-layer communication.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Optional

from cyberguard_api.security.core.interfaces import (
    AuditLog,
    ContainmentController,
    IdentityProvider,
    PolicyEngine,
    SecretManager,
    SecurityContext,
    SecurityEvent,
    TelemetryCollector,
    ThreatLevel,
    AuditAction,
    PolicyDecision,
)


@dataclass
class SecurityConfig:
    """Global security configuration."""
    # Layer 1: Identity
    token_ttl_seconds: int = 300  # 5 min short-lived tokens
    max_token_refresh: int = 3    # Max refreshes before re-auth
    mfa_required: bool = True
    odac_enabled: bool = True

    # Layer 2: Runtime
    telemetry_sample_rate: float = 1.0
    rasp_enabled: bool = True
    containment_auto_trigger: bool = True
    anomaly_threshold: float = 0.85

    # Layer 3: Perimeter
    waf_enabled: bool = True
    api_schema_validation: bool = True
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    egress_whitelist: list[str] = field(default_factory=list)

    # Layer 4: Infrastructure
    sbom_enforcement: bool = True
    secret_rotation_days: int = 30
    policy_as_code_enabled: bool = True

    # Layer 5: SIEM/SOAR
    audit_encryption_enabled: bool = True
    soar_auto_response: bool = True
    alert_webhook_url: Optional[str] = None


class SecurityRegistry:
    """
    Singleton registry coordinating all security layers.
    Provides dependency injection and cross-layer event bus.
    """

    _instance: Optional[SecurityRegistry] = None
    _initialized: bool = False

    def __new__(cls) -> SecurityRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self.config = SecurityConfig()
        self._identity_provider: Optional[IdentityProvider] = None
        self._policy_engine: Optional[PolicyEngine] = None
        self._telemetry: Optional[TelemetryCollector] = None
        self._audit_log: Optional[AuditLog] = None
        self._containment: Optional[ContainmentController] = None
        self._secret_manager: Optional[SecretManager] = None

        # Cross-layer event bus
        self._event_subscribers: dict[str, list[callable]] = {}
        self._lock = asyncio.Lock()

        self._initialized = True

    # --- Provider Registration ---

    def register_identity_provider(self, provider: IdentityProvider) -> None:
        self._identity_provider = provider

    def register_policy_engine(self, engine: PolicyEngine) -> None:
        self._policy_engine = engine

    def register_telemetry(self, collector: TelemetryCollector) -> None:
        self._telemetry = collector

    def register_audit_log(self, log: AuditLog) -> None:
        self._audit_log = log

    def register_containment(self, controller: ContainmentController) -> None:
        self._containment = controller

    def register_secret_manager(self, manager: SecretManager) -> None:
        self._secret_manager = manager

    # --- Accessors ---

    @property
    def identity(self) -> IdentityProvider:
        if not self._identity_provider:
            raise RuntimeError("IdentityProvider not registered")
        return self._identity_provider

    @property
    def policy(self) -> PolicyEngine:
        if not self._policy_engine:
            raise RuntimeError("PolicyEngine not registered")
        return self._policy_engine

    @property
    def telemetry(self) -> TelemetryCollector:
        if not self._telemetry:
            raise RuntimeError("TelemetryCollector not registered")
        return self._telemetry

    @property
    def audit(self) -> AuditLog:
        if not self._audit_log:
            raise RuntimeError("AuditLog not registered")
        return self._audit_log

    @property
    def containment(self) -> ContainmentController:
        if not self._containment:
            raise RuntimeError("ContainmentController not registered")
        return self._containment

    @property
    def secrets(self) -> SecretManager:
        if not self._secret_manager:
            raise RuntimeError("SecretManager not registered")
        return self._secret_manager

    # --- Event Bus ---

    async def emit(self, event: SecurityEvent) -> None:
        """Emit event to all layers and audit log."""
        # Append to immutable audit log
        if self._audit_log:
            await self._audit_log.append(event)

        # Collect telemetry
        if self._telemetry:
            await self._telemetry.collect(event)

        # Notify subscribers
        subscribers = self._event_subscribers.get(event.action.value, [])
        for callback in subscribers:
            try:
                await callback(event)
            except Exception:
                pass  # Never let subscribers break security flow

    def subscribe(self, action: AuditAction, callback: callable) -> None:
        """Subscribe to security events."""
        key = action.value
        if key not in self._event_subscribers:
            self._event_subscribers[key] = []
        self._event_subscribers[key].append(callback)

    # --- High-Level Operations ---

    async def authenticate_and_authorize(
        self,
        token: str,
        resource: str,
        action: str,
        resource_attributes: dict[str, Any],
    ) -> tuple[SecurityContext, PolicyDecision]:
        """
        Complete zero-trust auth flow: validate token -> evaluate policy.
        Returns (context, decision).
        """
        context = await self.identity.validate_token(token)
        if not context:
            await self.emit(SecurityEvent(
                action=AuditAction.AUTHENTICATE,
                threat_level=ThreatLevel.HIGH,
                outcome=PolicyDecision.DENY,
                details={"reason": "invalid_token"},
            ))
            return SecurityContext(subject_id="anonymous", tenant_id="unknown", clearance_level="none"), PolicyDecision.DENY

        decision = await self.policy.evaluate(context, resource, action, resource_attributes)

        await self.emit(SecurityEvent(
            action=AuditAction.AUTHORIZE,
            threat_level=ThreatLevel.NONE if decision == PolicyDecision.ALLOW else ThreatLevel.MEDIUM,
            subject_id=context.subject_id,
            tenant_id=context.tenant_id,
            resource=resource,
            outcome=decision,
            context=context,
            details={"action": action, "resource_attributes": resource_attributes},
        ))

        return context, decision

    async def trigger_containment(
        self,
        context: SecurityContext,
        reason: str,
        threat_level: ThreatLevel = ThreatLevel.CRITICAL,
    ) -> bool:
        """Trigger automated containment based on threat level."""
        if not self.config.containment_auto_trigger:
            return False

        contained = False
        if context.attributes.get("session_id"):
            contained = await self.containment.isolate_session(
                context.attributes["session_id"], reason
            )

        await self.emit(SecurityEvent(
            action=AuditAction.CONTAINMENT,
            threat_level=threat_level,
            subject_id=context.subject_id,
            tenant_id=context.tenant_id,
            outcome=PolicyDecision.QUARANTINE if contained else PolicyDecision.DENY,
            context=context,
            details={"reason": reason, "contained": contained},
        ))

        return contained

    @asynccontextmanager
    async def secured_operation(
        self,
        token: str,
        resource: str,
        action: str,
        resource_attributes: dict[str, Any],
    ):
        """Context manager for secured operations with automatic audit."""
        context, decision = await self.authenticate_and_authorize(
            token, resource, action, resource_attributes
        )

        if decision != PolicyDecision.ALLOW:
            raise PermissionError(f"Access denied: {decision.value}")

        try:
            yield context
        except Exception as e:
            await self.emit(SecurityEvent(
                action=AuditAction.SECURITY_VIOLATION,
                threat_level=ThreatLevel.HIGH,
                subject_id=context.subject_id,
                tenant_id=context.tenant_id,
                resource=resource,
                outcome=PolicyDecision.DENY,
                context=context,
                details={"error": str(e), "action": action},
            ))
            raise
        finally:
            await self.emit(SecurityEvent(
                action=AuditAction.DATA_READ if "read" in action.lower() else AuditAction.DATA_WRITE,
                threat_level=ThreatLevel.NONE,
                subject_id=context.subject_id,
                tenant_id=context.tenant_id,
                resource=resource,
                outcome=PolicyDecision.ALLOW,
                context=context,
                details={"action": action},
            ))


# Global registry instance
registry = SecurityRegistry()