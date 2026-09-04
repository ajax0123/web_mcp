"""
Core Security Interfaces
========================
Foundational types and contracts for the enterprise security architecture.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    """Standardized threat severity levels."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditAction(str, Enum):
    """Audit event action types."""
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    MODEL_INFERENCE = "model_inference"
    ADMIN_ACTION = "admin_action"
    SECURITY_VIOLATION = "security_violation"
    ANOMALY_DETECTED = "anomaly_detected"
    CONTAINMENT = "containment"
    POLICY_EVALUATION = "policy_evaluation"


class PolicyDecision(str, Enum):
    """Policy evaluation outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"
    QUARANTINE = "quarantine"
    LOG_ONLY = "log_only"


@dataclass
class SecurityContext:
    """
    Immutable security context propagated through all layers.
    Carries identity, clearance, and runtime attestation data.
    """
    subject_id: str
    tenant_id: str
    clearance_level: str
    dynamic_markings: frozenset[str] = field(default_factory=frozenset)
    attributes: dict[str, Any] = field(default_factory=dict)
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    mfa_verified: bool = False
    device_attestation: Optional[dict[str, Any]] = None
    session_risk_score: float = 0.0

    def with_updated_risk(self, delta: float) -> SecurityContext:
        """Return new context with updated risk score."""
        return SecurityContext(
            subject_id=self.subject_id,
            tenant_id=self.tenant_id,
            clearance_level=self.clearance_level,
            dynamic_markings=self.dynamic_markings,
            attributes=self.attributes,
            token_id=self.token_id,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            mfa_verified=self.mfa_verified,
            device_attestation=self.device_attestation,
            session_risk_score=min(1.0, max(0.0, self.session_risk_score + delta)),
        )


@dataclass
class SecurityEvent:
    """
    Immutable security event for audit pipeline.
    Tamper-evident through cryptographic chaining.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: AuditAction = AuditAction.AUTHENTICATE
    threat_level: ThreatLevel = ThreatLevel.NONE
    subject_id: str = ""
    tenant_id: str = ""
    resource: str = ""
    outcome: PolicyDecision = PolicyDecision.ALLOW
    details: dict[str, Any] = field(default_factory=dict)
    context: Optional[SecurityContext] = None
    previous_hash: str = ""
    event_hash: str = ""

    def compute_hash(self) -> str:
        """Compute cryptographic hash for tamper evidence."""
        import hashlib
        content = f"{self.event_id}{self.timestamp.isoformat()}{self.action.value}{self.threat_level.value}{self.subject_id}{self.resource}{self.outcome.value}{self.previous_hash}"
        return hashlib.sha256(content.encode()).hexdigest()


class IdentityProvider(ABC):
    """Abstract identity provider for zero-trust token exchange."""

    @abstractmethod
    async def validate_token(self, token: str) -> Optional[SecurityContext]:
        """Validate and exchange token for security context."""
        pass

    @abstractmethod
    async def issue_token(self, context: SecurityContext) -> str:
        """Issue short-lived cryptographic token."""
        pass

    @abstractmethod
    async def revoke_token(self, token_id: str) -> bool:
        """Revoke token immediately."""
        pass


class PolicyEngine(ABC):
    """Abstract policy engine for ABAC/ODAC decisions."""

    @abstractmethod
    async def evaluate(
        self,
        context: SecurityContext,
        resource: str,
        action: str,
        resource_attributes: dict[str, Any],
    ) -> PolicyDecision:
        """Evaluate access policy."""
        pass

    @abstractmethod
    async def get_provenance(self, resource: str) -> list[dict[str, Any]]:
        """Get immutable provenance chain for resource."""
        pass


class TelemetryCollector(ABC):
    """Abstract runtime telemetry collector."""

    @abstractmethod
    async def collect(self, event: SecurityEvent) -> None:
        """Collect telemetry event."""
        pass

    @abstractmethod
    async def get_baseline(self, subject_id: str) -> dict[str, Any]:
        """Get behavioral baseline for subject."""
        pass


class AuditLog(ABC):
    """Abstract immutable audit log."""

    @abstractmethod
    async def append(self, event: SecurityEvent) -> str:
        """Append event, return event hash."""
        pass

    @abstractmethod
    async def verify_chain(self, from_event: str, to_event: str) -> bool:
        """Verify hash chain integrity."""
        pass

    @abstractmethod
    async def query(
        self,
        start: datetime,
        end: datetime,
        filters: dict[str, Any],
    ) -> list[SecurityEvent]:
        """Query audit events."""
        pass


class ContainmentController(ABC):
    """Abstract containment and isolation controller."""

    @abstractmethod
    async def isolate_session(self, session_id: str, reason: str) -> bool:
        """Isolate user session."""
        pass

    @abstractmethod
    async def isolate_container(self, container_id: str, reason: str) -> bool:
        """Isolate container/workload."""
        pass

    @abstractmethod
    async def terminate_process(self, pid: int, reason: str) -> bool:
        """Terminate suspicious process."""
        pass


class SecretManager(ABC):
    """Abstract secret management interface."""

    @abstractmethod
    async def get_secret(self, path: str) -> Optional[str]:
        """Retrieve secret."""
        pass

    @abstractmethod
    async def rotate_secret(self, path: str) -> str:
        """Rotate and return new secret."""
        pass

    @abstractmethod
    async def audit_secret_access(self, path: str, context: SecurityContext) -> None:
        """Audit secret access."""
        pass