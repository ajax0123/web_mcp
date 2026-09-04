"""
Layer 1: Ontology-Driven Access Control (ODAC)
===============================================
Implements object-, row-, and property-level security policies.
Every data read/write passes through semantic governance interceptor.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class ClearanceLevel(str, Enum):
    """Security clearance levels."""
    UNCLASSIFIED = "unclassified"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class DataMarking(str, Enum):
    """Dynamic data markings for fine-grained control."""
    PII = "pii"
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    INTEL_PROPERTY = "intel_property"
    THREAT_INTEL = "threat_intel"
    INTERNAL_ONLY = "internal_only"
    EXECUTIVE = "executive"


class ResourceType(str, Enum):
    """Protected resource types."""
    USER_TELEMETRY = "user_telemetry"
    MODEL_INFERENCE = "model_inference"
    ATTACK_ANALYSIS = "attack_analysis"
    INCIDENT_REPORT = "incident_report"
    SECURITY_SUMMARY = "security_summary"
    AUDIT_LOG = "audit_log"
    MODEL_ARTIFACT = "model_artifact"


@dataclass(frozen=True)
class OntologyEntity:
    """Semantic entity in the security ontology."""
    entity_id: str
    entity_type: ResourceType
    tenant_id: str
    owner_id: str
    clearance_required: ClearanceLevel
    markings: frozenset[DataMarking] = field(default_factory=frozenset)
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    lineage_hash: str = ""

    def compute_lineage_hash(self) -> str:
        """Compute cryptographic lineage hash."""
        content = f"{self.entity_id}{self.entity_type.value}{self.tenant_id}{self.owner_id}{self.clearance_required.value}{json.dumps(self.properties, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class AccessPolicy:
    """ABAC policy rule for ODAC."""
    policy_id: str
    name: str
    effect: str  # allow/deny
    subject_attributes: dict[str, Any]  # Required subject attributes
    resource_attributes: dict[str, Any]  # Required resource attributes
    action: str
    conditions: list[dict[str, Any]] = field(default_factory=list)
    priority: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ProvenanceRecord:
    """Immutable provenance record for data lineage."""
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    event_type: str = ""  # CREATE, READ, UPDATE, DELETE, TRANSFORM, DERIVE
    actor_id: str = ""
    actor_clearance: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    previous_hash: str = ""
    record_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def compute_hash(self) -> str:
        content = f"{self.record_id}{self.entity_id}{self.event_type}{self.actor_id}{self.timestamp.isoformat()}{self.previous_hash}{json.dumps(self.metadata, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()


class ODACEngine:
    """
    Ontology-Driven Access Control Engine.
    Enforces semantic policies at object, row, and property level.
    """

    def __init__(self) -> None:
        self._policies: list[AccessPolicy] = []
        self._entities: dict[str, OntologyEntity] = {}
        self._provenance_chain: dict[str, list[ProvenanceRecord]] = {}
        self._initialize_default_policies()

    def _initialize_default_policies(self) -> None:
        """Initialize default CyberGuard ODAC policies."""
        # Policy: Analysts can read telemetry for their tenant
        self._policies.append(AccessPolicy(
            policy_id="pol-telemetry-read",
            name="Telemetry Read Access",
            effect="allow",
            subject_attributes={"role": "analyst", "clearance": ["confidential", "secret", "top_secret"]},
            resource_attributes={"type": ResourceType.USER_TELEMETRY.value},
            action="read",
            priority=100,
        ))

        # Policy: Only senior analysts can access executive markings
        self._policies.append(AccessPolicy(
            policy_id="pol-executive-read",
            name="Executive Data Access",
            effect="allow",
            subject_attributes={"role": "senior_analyst", "clearance": ["secret", "top_secret"]},
            resource_attributes={"markings": [DataMarking.EXECUTIVE.value]},
            action="read",
            priority=200,
        ))

        # Policy: PII requires explicit consent marking
        self._policies.append(AccessPolicy(
            policy_id="pol-pii-access",
            name="PII Access Control",
            effect="deny",
            subject_attributes={},
            resource_attributes={"markings": [DataMarking.PII.value]},
            action="read",
            conditions=[{"field": "subject_attributes.consent_granted", "operator": "eq", "value": True}],
            priority=300,
        ))

        # Policy: Model inference requires valid clearance
        self._policies.append(AccessPolicy(
            policy_id="pol-model-inference",
            name="Model Inference Access",
            effect="allow",
            subject_attributes={"clearance": ["confidential", "secret", "top_secret"]},
            resource_attributes={"type": ResourceType.MODEL_INFERENCE.value},
            action="execute",
            priority=100,
        ))

        # Policy: Incident reports require analyst role
        self._policies.append(AccessPolicy(
            policy_id="pol-incident-access",
            name="Incident Report Access",
            effect="allow",
            subject_attributes={"role": ["analyst", "senior_analyst", "soc_manager"]},
            resource_attributes={"type": ResourceType.INCIDENT_REPORT.value},
            action="read",
            priority=150,
        ))

        # Policy: Audit logs are restricted
        self._policies.append(AccessPolicy(
            policy_id="pol-audit-access",
            name="Audit Log Access",
            effect="allow",
            subject_attributes={"role": ["soc_manager", "auditor", "compliance"], "clearance": ["secret", "top_secret"]},
            resource_attributes={"type": ResourceType.AUDIT_LOG.value},
            action="read",
            priority=250,
        ))

    def register_entity(self, entity: OntologyEntity) -> None:
        """Register entity in ontology."""
        entity = OntologyEntity(
            entity_id=entity.entity_id,
            entity_type=entity.entity_type,
            tenant_id=entity.tenant_id,
            owner_id=entity.owner_id,
            clearance_required=entity.clearance_required,
            markings=entity.markings,
            properties=entity.properties,
            created_at=entity.created_at,
            lineage_hash=entity.compute_lineage_hash(),
        )
        self._entities[entity.entity_id] = entity
        self._provenance_chain[entity.entity_id] = []

    def record_provenance(
        self,
        entity_id: str,
        event_type: str,
        actor_id: str,
        actor_clearance: str,
        metadata: dict[str, Any],
    ) -> ProvenanceRecord:
        """Record immutable provenance event."""
        chain = self._provenance_chain.get(entity_id, [])
        previous_hash = chain[-1].record_hash if chain else ""

        record = ProvenanceRecord(
            entity_id=entity_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_clearance=actor_clearance,
            previous_hash=previous_hash,
            metadata=metadata,
        )
        record.record_hash = record.compute_hash()
        chain.append(record)
        self._provenance_chain[entity_id] = chain
        return record

    def get_provenance(self, entity_id: str) -> list[ProvenanceRecord]:
        """Get full provenance chain for entity."""
        return self._provenance_chain.get(entity_id, [])

    def verify_provenance_chain(self, entity_id: str) -> bool:
        """Verify cryptographic integrity of provenance chain."""
        chain = self._provenance_chain.get(entity_id, [])
        if not chain:
            return True

        previous_hash = ""
        for record in chain:
            if record.previous_hash != previous_hash:
                return False
            if record.compute_hash() != record.record_hash:
                return False
            previous_hash = record.record_hash
        return True

    def evaluate(
        self,
        subject_attributes: dict[str, Any],
        resource: OntologyEntity,
        action: str,
    ) -> tuple[bool, list[str]]:
        """
        Evaluate access request against ODAC policies.
        Returns (allowed, applied_policy_ids).
        """
        applicable_policies = [
            p for p in self._policies
            if p.action == action or p.action == "*"
        ]

        # Sort by priority (highest first)
        applicable_policies.sort(key=lambda p: p.priority, reverse=True)

        applied = []
        for policy in applicable_policies:
            if self._matches_policy(policy, subject_attributes, resource):
                applied.append(policy.policy_id)
                if policy.effect == "deny":
                    return False, applied
                elif policy.effect == "allow":
                    return True, applied

        # Default deny
        return False, applied

    def _matches_policy(
        self,
        policy: AccessPolicy,
        subject_attrs: dict[str, Any],
        resource: OntologyEntity,
    ) -> bool:
        """Check if policy matches subject and resource."""
        # Check subject attributes
        for key, expected in policy.subject_attributes.items():
            actual = subject_attrs.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        # Check resource attributes
        for key, expected in policy.resource_attributes.items():
            if key == "type":
                actual = resource.entity_type.value
            elif key == "markings":
                actual = [m.value for m in resource.markings]
            elif key == "clearance":
                actual = resource.clearance_required.value
            else:
                actual = resource.properties.get(key)

            if isinstance(expected, list):
                if not any(e in actual for e in expected):
                    return False
            elif actual != expected:
                return False

        # Check conditions
        for condition in policy.conditions:
            field_path = condition["field"]
            operator = condition["operator"]
            expected = condition["value"]

            # Navigate field path (e.g., "subject_attributes.consent_granted")
            parts = field_path.split(".")
            value = subject_attrs
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break

            if not self._evaluate_condition(value, operator, expected):
                return False

        return True

    def _evaluate_condition(self, actual: Any, operator: str, expected: Any) -> bool:
        """Evaluate condition operator."""
        if operator == "eq":
            return actual == expected
        elif operator == "ne":
            return actual != expected
        elif operator == "in":
            return actual in expected if isinstance(expected, list) else False
        elif operator == "gt":
            return actual > expected
        elif operator == "gte":
            return actual >= expected
        elif operator == "lt":
            return actual < expected
        elif operator == "lte":
            return actual <= expected
        return False

    def filter_properties(
        self,
        subject_attributes: dict[str, Any],
        resource: OntologyEntity,
        properties: dict[str, Any],
    ) -> dict[str, Any]:
        """Filter properties based on subject clearance and markings."""
        filtered = {}
        subject_clearance = subject_attributes.get("clearance", ClearanceLevel.UNCLASSIFIED.value)

        for key, value in properties.items():
            # Check if property has marking restrictions
            prop_markings = resource.properties.get(f"{key}_markings", [])

            allowed = True
            for marking in prop_markings:
                if marking == DataMarking.PII.value and not subject_attrs.get("consent_granted"):
                    allowed = False
                    break
                if marking == DataMarking.EXECUTIVE.value and subject_clearance not in ["secret", "top_secret"]:
                    allowed = False
                    break
                if marking == DataMarking.FINANCIAL.value and subject_clearance not in ["confidential", "secret", "top_secret"]:
                    allowed = False
                    break

            if allowed:
                filtered[key] = value
            else:
                filtered[key] = "[REDACTED]"

        return filtered


class ZeroTrustTokenExchange:
    """
    Zero-Trust Token Exchange Service.
    Implements short-lived, cryptographically signed tokens with continuous verification.
    """

    def __init__(
        self,
        secret_key: str,
        token_ttl_seconds: int = 300,
        max_refresh: int = 3,
        issuer: str = "cyberguard",
        audience: str = "cyberguard-api",
    ) -> None:
        self.secret_key = secret_key
        self.token_ttl = token_ttl_seconds
        self.max_refresh = max_refresh
        self.issuer = issuer
        self.audience = audience
        self._revoked_tokens: set[str] = set()
        self._refresh_counts: dict[str, int] = {}

    def issue_token(self, context: dict[str, Any]) -> str:
        """Issue new short-lived JWT token."""
        import jwt
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        token_id = str(uuid.uuid4())

        payload = {
            "jti": token_id,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self.token_ttl)).timestamp()),
            "sub": context.get("subject_id"),
            "tenant": context.get("tenant_id"),
            "clearance": context.get("clearance_level", ClearanceLevel.UNCLASSIFIED.value),
            "markings": list(context.get("dynamic_markings", [])),
            "mfa": context.get("mfa_verified", False),
            "device": context.get("device_attestation"),
            "refresh_count": 0,
        }

        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        self._refresh_counts[token_id] = 0
        return token

    def validate_token(self, token: str) -> Optional[dict[str, Any]]:
        """Validate token and return claims."""
        import jwt

        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=["HS256"],
                audience=self.audience,
                issuer=self.issuer,
            )

            token_id = payload.get("jti")
            if token_id in self._revoked_tokens:
                return None

            # Check MFA requirement
            if not payload.get("mfa", False):
                return None

            return payload

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def refresh_token(self, token: str) -> Optional[str]:
        """Refresh token if within limits."""
        import jwt

        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=["HS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"verify_exp": False},  # Allow expired for refresh
            )

            token_id = payload.get("jti")
            refresh_count = self._refresh_counts.get(token_id, 0)

            if refresh_count >= self.max_refresh:
                return None

            # Issue new token with incremented refresh count
            new_payload = {**payload}
            new_payload["jti"] = str(uuid.uuid4())
            new_payload["iat"] = int(datetime.now(timezone.utc).timestamp())
            new_payload["exp"] = int((datetime.now(timezone.utc) + timedelta(seconds=self.token_ttl)).timestamp())
            new_payload["refresh_count"] = refresh_count + 1

            new_token = jwt.encode(new_payload, self.secret_key, algorithm="HS256")
            self._refresh_counts[new_payload["jti"]] = refresh_count + 1
            return new_token

        except jwt.InvalidTokenError:
            return None

    def revoke_token(self, token: str) -> bool:
        """Revoke token immediately."""
        import jwt

        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=["HS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"verify_exp": False},
            )
            token_id = payload.get("jti")
            self._revoked_tokens.add(token_id)
            return True
        except jwt.InvalidTokenError:
            return False

    def get_token_context(self, token: str) -> Optional[dict[str, Any]]:
        """Extract security context from valid token."""
        payload = self.validate_token(token)
        if not payload:
            return None

        return {
            "subject_id": payload.get("sub"),
            "tenant_id": payload.get("tenant"),
            "clearance_level": payload.get("clearance"),
            "dynamic_markings": set(payload.get("markings", [])),
            "mfa_verified": payload.get("mfa", False),
            "device_attestation": payload.get("device"),
            "token_id": payload.get("jti"),
            "refresh_count": payload.get("refresh_count", 0),
        }


# Global ODAC engine instance
odac_engine = ODACEngine()