"""
Layer 1: Identity Provider Implementation
=========================================
Integrates ODAC and Zero-Trust Token Exchange with core interfaces.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from cyberguard_api.security.core.interfaces import (
    IdentityProvider,
    PolicyEngine,
    SecurityContext,
    SecurityEvent,
    PolicyDecision,
    AuditAction,
    ThreatLevel,
)
from cyberguard_api.security.layer1_identity.odac import (
    ODACEngine,
    ZeroTrustTokenExchange,
    OntologyEntity,
    ResourceType,
    ClearanceLevel,
    DataMarking,
    odac_engine,
)


class CyberGuardIdentityProvider(IdentityProvider):
    """
    CyberGuard Identity Provider.
    Integrates zero-trust token exchange with ODAC.
    """

    def __init__(
        self,
        secret_key: str,
        token_ttl_seconds: int = 300,
        max_refresh: int = 3,
    ) -> None:
        self.token_exchange = ZeroTrustTokenExchange(
            secret_key=secret_key,
            token_ttl_seconds=token_ttl_seconds,
            max_refresh=max_refresh,
        )
        self.odac = odac_engine

    async def validate_token(self, token: str) -> Optional[SecurityContext]:
        """Validate token and return security context."""
        payload = self.token_exchange.get_token_context(token)
        if not payload:
            return None

        return SecurityContext(
            subject_id=payload["subject_id"],
            tenant_id=payload["tenant_id"],
            clearance_level=payload["clearance_level"],
            dynamic_markings=frozenset(payload["dynamic_markings"]),
            attributes={
                "mfa_verified": payload["mfa_verified"],
                "device_attestation": payload["device_attestation"],
                "token_id": payload["token_id"],
                "refresh_count": payload["refresh_count"],
            },
            token_id=payload["token_id"],
            mfa_verified=payload["mfa_verified"],
            device_attestation=payload["device_attestation"],
        )

    async def issue_token(self, context: SecurityContext) -> str:
        """Issue new token from security context."""
        return self.token_exchange.issue_token({
            "subject_id": context.subject_id,
            "tenant_id": context.tenant_id,
            "clearance_level": context.clearance_level,
            "dynamic_markings": context.dynamic_markings,
            "mfa_verified": context.mfa_verified,
            "device_attestation": context.device_attestation,
        })

    async def revoke_token(self, token_id: str) -> bool:
        """Revoke token by ID."""
        # In practice, would need to lookup token by ID
        # This is a simplified implementation
        return True


class CyberGuardPolicyEngine(PolicyEngine):
    """
    CyberGuard Policy Engine.
    Implements ABAC/ODAC policy evaluation with provenance tracking.
    """

    def __init__(self) -> None:
        self.odac = odac_engine

    async def evaluate(
        self,
        context: SecurityContext,
        resource: str,
        action: str,
        resource_attributes: dict[str, Any],
    ) -> PolicyDecision:
        """Evaluate access policy using ODAC."""
        # Build subject attributes from context
        subject_attrs = {
            "role": context.attributes.get("role", "analyst"),
            "clearance": context.clearance_level,
            "consent_granted": context.attributes.get("consent_granted", False),
        }

        # Look up or create ontology entity for resource
        entity = self.odac._entities.get(resource)
        if not entity:
            # Create default entity for unknown resources
            entity = OntologyEntity(
                entity_id=resource,
                entity_type=ResourceType(resource_attributes.get("type", "user_telemetry")),
                tenant_id=context.tenant_id,
                owner_id=context.subject_id,
                clearance_required=ClearanceLevel(resource_attributes.get("clearance", "confidential")),
                markings=frozenset(
                    DataMarking(m) for m in resource_attributes.get("markings", [])
                ),
                properties=resource_attributes,
            )
            self.odac.register_entity(entity)

        # Evaluate ODAC policy
        allowed, applied_policies = self.odac.evaluate(subject_attrs, entity, action)

        # Record provenance
        self.odac.record_provenance(
            entity_id=resource,
            event_type="ACCESS_REQUEST",
            actor_id=context.subject_id,
            actor_clearance=context.clearance_level,
            metadata={
                "action": action,
                "allowed": allowed,
                "policies": applied_policies,
                "resource_attributes": resource_attributes,
            },
        )

        if not allowed:
            return PolicyDecision.DENY

        # Check if challenge required (e.g., step-up auth for sensitive data)
        if DataMarking.EXECUTIVE in entity.markings and context.clearance_level not in ["secret", "top_secret"]:
            return PolicyDecision.CHALLENGE

        if context.session_risk_score > 0.7:
            return PolicyDecision.CHALLENGE

        return PolicyDecision.ALLOW

    async def get_provenance(self, resource: str) -> list[dict[str, Any]]:
        """Get provenance chain for resource."""
        records = self.odac.get_provenance(resource)
        return [
            {
                "record_id": r.record_id,
                "event_type": r.event_type,
                "actor_id": r.actor_id,
                "actor_clearance": r.actor_clearance,
                "timestamp": r.timestamp.isoformat(),
                "record_hash": r.record_hash,
                "previous_hash": r.previous_hash,
                "metadata": r.metadata,
            }
            for r in records
        ]


class ODACMiddleware:
    """
    FastAPI Middleware for ODAC enforcement.
    Intercepts all requests and enforces semantic access control.
    """

    def __init__(self, policy_engine: CyberGuardPolicyEngine) -> None:
        self.policy_engine = policy_engine

    async def enforce(
        self,
        context: SecurityContext,
        resource: str,
        action: str,
        resource_attributes: dict[str, Any],
    ) -> tuple[PolicyDecision, Optional[dict[str, Any]]]:
        """
        Enforce ODAC policy.
        Returns (decision, filtered_properties).
        """
        decision = await self.policy_engine.evaluate(
            context, resource, action, resource_attributes
        )

        if decision == PolicyDecision.DENY:
            return decision, None

        # Get entity for property filtering
        entity = self.policy_engine.odac._entities.get(resource)
        if entity:
            filtered = self.policy_engine.odac.filter_properties(
                {
                    "role": context.attributes.get("role", "analyst"),
                    "clearance": context.clearance_level,
                    "consent_granted": context.attributes.get("consent_granted", False),
                },
                entity,
                resource_attributes,
            )
            return decision, filtered

        return decision, resource_attributes