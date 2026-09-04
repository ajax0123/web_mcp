"""
Layer 3: API Threat Prevention & Egress Microsegmentation
==========================================================
Palo Alto Paradigm: OpenAPI schema validation, token bucket rate limiting,
egress FQDN whitelisting, data exfiltration prevention.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional
from collections import defaultdict
import json


class ValidationSeverity(str, Enum):
    """Schema validation severity."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationError:
    """Schema validation error."""
    field: str
    message: str
    severity: ValidationSeverity = ValidationSeverity.ERROR
    expected: Any = None
    received: Any = None


@dataclass
class APISchema:
    """OpenAPI/Swagger schema definition."""
    schema_id: str
    version: str
    title: str
    paths: dict[str, Any]  # OpenAPI paths object
    components: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TokenBucketRateLimiter:
    """
    Token bucket rate limiter for API endpoints.
    Supports per-endpoint, per-client, and global limits.
    """

    def __init__(
        self,
        capacity: int = 100,
        refill_rate: float = 10.0,  # tokens per second
    ) -> None:
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill)

    def _refill(self, key: str) -> float:
        """Refill bucket and return current tokens."""
        now = time.time()
        if key not in self._buckets:
            self._buckets[key] = (float(self.capacity), now)
            return float(self.capacity)

        tokens, last_refill = self._buckets[key]
        elapsed = now - last_refill
        new_tokens = min(self.capacity, tokens + elapsed * self.refill_rate)
        self._buckets[key] = (new_tokens, now)
        return new_tokens

    def consume(self, key: str, tokens: int = 1) -> tuple[bool, float]:
        """
        Try to consume tokens.
        Returns (allowed, remaining_tokens).
        """
        current = self._refill(key)
        if current >= tokens:
            self._buckets[key] = (current - tokens, time.time())
            return True, current - tokens
        return False, current

    def get_remaining(self, key: str) -> float:
        """Get remaining tokens without consuming."""
        return self._refill(key)

    def reset(self, key: str) -> None:
        """Reset bucket."""
        if key in self._buckets:
            del self._buckets[key]


class MultiTierRateLimiter:
    """
    Multi-tier rate limiter with global, per-tenant, per-endpoint limits.
    """

    def __init__(self) -> None:
        self._global = TokenBucketRateLimiter(capacity=1000, refill_rate=100.0)
        self._per_tenant: dict[str, TokenBucketRateLimiter] = defaultdict(
            lambda: TokenBucketRateLimiter(capacity=100, refill_rate=10.0)
        )
        self._per_endpoint: dict[str, TokenBucketRateLimiter] = defaultdict(
            lambda: TokenBucketRateLimiter(capacity=50, refill_rate=5.0)
        )
        self._per_client: dict[str, TokenBucketRateLimiter] = defaultdict(
            lambda: TokenBucketRateLimiter(capacity=20, refill_rate=2.0)
        )

    def check_limit(
        self,
        tenant_id: str,
        endpoint: str,
        client_ip: str,
        cost: int = 1,
    ) -> tuple[bool, dict[str, float]]:
        """
        Check all rate limit tiers.
        Returns (allowed, remaining_tokens_per_tier).
        """
        # Global
        global_allowed, global_remaining = self._global.consume("global", cost)
        if not global_allowed:
            return False, {"global": global_remaining}

        # Per tenant
        tenant_allowed, tenant_remaining = self._per_tenant[tenant_id].consume(tenant_id, cost)
        if not tenant_allowed:
            return False, {"global": global_remaining, "tenant": tenant_remaining}

        # Per endpoint
        endpoint_allowed, endpoint_remaining = self._per_endpoint[endpoint].consume(endpoint, cost)
        if not endpoint_allowed:
            return False, {
                "global": global_remaining,
                "tenant": tenant_remaining,
                "endpoint": endpoint_remaining,
            }

        # Per client
        client_allowed, client_remaining = self._per_client[client_ip].consume(client_ip, cost)
        if not client_allowed:
            return False, {
                "global": global_remaining,
                "tenant": tenant_remaining,
                "endpoint": endpoint_remaining,
                "client": client_remaining,
            }

        return True, {
            "global": global_remaining,
            "tenant": tenant_remaining,
            "endpoint": endpoint_remaining,
            "client": client_remaining,
        }


@dataclass
class EgressRule:
    """Egress microsegmentation rule."""
    rule_id: str
    name: str
    destination_fqdn: str  # Exact FQDN or wildcard pattern
    allowed_ports: list[int] = field(default_factory=lambda: [443, 80])
    allowed_protocols: list[str] = field(default_factory=lambda: ["HTTPS", "HTTP"])
    source_services: list[str] = field(default_factory=list)  # Empty = all
    enabled: bool = True
    description: str = ""


@dataclass
class EgressRequest:
    """Outbound request for egress inspection."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_service: str = ""
    destination_fqdn: str = ""
    destination_ip: str = ""
    destination_port: int = 443
    protocol: str = "HTTPS"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EgressResult:
    """Egress inspection result."""
    request_id: str
    allowed: bool
    matched_rule: Optional[EgressRule] = None
    reason: str = ""


class EgressController:
    """
    Egress microsegmentation controller.
    Enforces explicit FQDN whitelist for all outbound connections.
    """

    def __init__(self) -> None:
        self._rules: list[EgressRule] = []
        self._blocked_destinations: set[str] = set()
        self._initialize_default_rules()

    def _initialize_default_rules(self) -> None:
        """Initialize default egress rules for CyberGuard."""
        # Allow model artifact downloads from trusted registry
        self.add_rule(EgressRule(
            rule_id="egress-model-registry",
            name="Model Registry Access",
            destination_fqdn="models.cyberguard.internal",
            allowed_ports=[443],
            allowed_protocols=["HTTPS"],
            source_services=["model-loader", "api"],
            description="Allow model artifact downloads from internal registry",
        ))

        # Allow threat intelligence feeds
        self.add_rule(EgressRule(
            rule_id="egress-threat-intel",
            name="Threat Intelligence Feeds",
            destination_fqdn="intel.cyberguard.internal",
            allowed_ports=[443],
            allowed_protocols=["HTTPS"],
            source_services=["telemetry", "analysis"],
            description="Allow threat intelligence feed updates",
        ))

        # Allow SIEM forwarding
        self.add_rule(EgressRule(
            rule_id="egress-siem",
            name="SIEM Log Forwarding",
            destination_fqdn="siem.cyberguard.internal",
            allowed_ports=[514, 443],
            allowed_protocols=["SYSLOG", "HTTPS"],
            source_services=["audit", "telemetry"],
            description="Allow audit log forwarding to SIEM",
        ))

        # Allow secret manager
        self.add_rule(EgressRule(
            rule_id="egress-vault",
            name="Secret Manager Access",
            destination_fqdn="vault.cyberguard.internal",
            allowed_ports=[8200],
            allowed_protocols=["HTTPS"],
            source_services=["*"],
            description="Allow secret retrieval from Vault",
        ))

    def add_rule(self, rule: EgressRule) -> None:
        """Add egress rule."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove egress rule."""
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return True

    def block_destination(self, fqdn: str) -> None:
        """Block destination FQDN."""
        self._blocked_destinations.add(fqdn.lower())

    def allow_destination(self, fqdn: str) -> None:
        """Allow destination FQDN (remove from blocklist)."""
        self._blocked_destinations.discard(fqdn.lower())

    def inspect(self, request: EgressRequest) -> EgressResult:
        """Inspect outbound request against egress policy."""
        # Check explicit blocklist
        if request.destination_fqdn.lower() in self._blocked_destinations:
            return EgressResult(
                request_id=request.request_id,
                allowed=False,
                reason=f"Destination {request.destination_fqdn} is explicitly blocked",
            )

        # Find matching rule
        for rule in self._rules:
            if not rule.enabled:
                continue

            # Check source service
            if rule.source_services and "*" not in rule.source_services:
                if request.source_service not in rule.source_services:
                    continue

            # Check FQDN match (support wildcards)
            if self._match_fqdn(request.destination_fqdn, rule.destination_fqdn):
                # Check port
                if request.destination_port not in rule.allowed_ports:
                    return EgressResult(
                        request_id=request.request_id,
                        allowed=False,
                        matched_rule=rule,
                        reason=f"Port {request.destination_port} not allowed for {rule.destination_fqdn}",
                    )

                # Check protocol
                if request.protocol not in rule.allowed_protocols:
                    return EgressResult(
                        request_id=request.request_id,
                        allowed=False,
                        matched_rule=rule,
                        reason=f"Protocol {request.protocol} not allowed for {rule.destination_fqdn}",
                    )

                return EgressResult(
                    request_id=request.request_id,
                    allowed=True,
                    matched_rule=rule,
                    reason=f"Allowed by rule {rule.name}",
                )

        # Default deny
        return EgressResult(
            request_id=request.request_id,
            allowed=False,
            reason=f"No egress rule allows {request.destination_fqdn}:{request.destination_port}",
        )

    def _match_fqdn(self, request_fqdn: str, rule_fqdn: str) -> bool:
        """Match FQDN with wildcard support."""
        if rule_fqdn == "*":
            return True
        if rule_fqdn.startswith("*."):
            # Wildcard subdomain
            suffix = rule_fqdn[1:]  # .example.com
            return request_fqdn.endswith(suffix) or request_fqdn == suffix[1:]
        return request_fqdn.lower() == rule_fqdn.lower()

    def get_rules(self) -> list[EgressRule]:
        """Get all egress rules."""
        return list(self._rules)


class APISchemaValidator:
    """
    OpenAPI/Swagger schema validator for API requests.
    Validates request/response against declared schemas.
    """

    def __init__(self) -> None:
        self._schemas: dict[str, APISchema] = {}

    def register_schema(self, schema: APISchema) -> None:
        """Register API schema."""
        self._schemas[schema.schema_id] = schema

    def validate_request(
        self,
        schema_id: str,
        path: str,
        method: str,
        query_params: dict[str, Any],
        headers: dict[str, str],
        body: Any,
    ) -> list[ValidationError]:
        """Validate request against schema."""
        errors = []

        schema = self._schemas.get(schema_id)
        if not schema:
            return [ValidationError(
                field="schema",
                message=f"Schema {schema_id} not found",
                severity=ValidationSeverity.ERROR,
            )]

        # Find path in schema
        path_spec = schema.paths.get(path)
        if not path_spec:
            return [ValidationError(
                field="path",
                message=f"Path {path} not defined in schema",
                severity=ValidationSeverity.ERROR,
            )]

        method_spec = path_spec.get(method.lower())
        if not method_spec:
            return [ValidationError(
                field="method",
                message=f"Method {method} not allowed for path {path}",
                severity=ValidationSeverity.ERROR,
            )]

        # Validate query parameters
        query_spec = method_spec.get("parameters", [])
        for param_spec in query_spec:
            if param_spec.get("in") != "query":
                continue
            param_name = param_spec.get("name")
            if param_name and param_name not in query_params:
                if param_spec.get("required", False):
                    errors.append(ValidationError(
                        field=f"query.{param_name}",
                        message=f"Required query parameter {param_name} missing",
                        severity=ValidationSeverity.ERROR,
                    ))

        # Validate headers
        header_spec = [p for p in query_spec if p.get("in") == "header"]
        for param_spec in header_spec:
            param_name = param_spec.get("name")
            if param_name and param_name.lower() not in [h.lower() for h in headers]:
                if param_spec.get("required", False):
                    errors.append(ValidationError(
                        field=f"header.{param_name}",
                        message=f"Required header {param_name} missing",
                        severity=ValidationSeverity.ERROR,
                    ))

        # Validate body (simplified - would use jsonschema in production)
        if body and "requestBody" in method_spec:
            body_spec = method_spec["requestBody"]
            content_spec = body_spec.get("content", {})
            json_spec = content_spec.get("application/json", {})
            schema_ref = json_spec.get("schema", {})
            if schema_ref:
                body_errors = self._validate_json(body, schema_ref, schema.components)
                errors.extend(body_errors)

        return errors

    def _validate_json(
        self,
        data: Any,
        schema: dict[str, Any],
        components: dict[str, Any],
        path: str = "body",
    ) -> list[ValidationError]:
        """Validate JSON against schema (simplified)."""
        errors = []

        # Handle $ref
        if "$ref" in schema:
            ref_path = schema["$ref"]
            if ref_path.startswith("#/components/schemas/"):
                schema_name = ref_path.split("/")[-1]
                schema = components.get("schemas", {}).get(schema_name, {})
            else:
                return [ValidationError(
                    field=path,
                    message=f"Unsupported reference: {ref_path}",
                    severity=ValidationSeverity.WARNING,
                )]

        schema_type = schema.get("type")

        if schema_type == "object":
            if not isinstance(data, dict):
                errors.append(ValidationError(
                    field=path,
                    message=f"Expected object, got {type(data).__name__}",
                    severity=ValidationSeverity.ERROR,
                ))
            else:
                # Check required fields
                required = schema.get("required", [])
                for req_field in required:
                    if req_field not in data:
                        errors.append(ValidationError(
                            field=f"{path}.{req_field}",
                            message=f"Required field {req_field} missing",
                            severity=ValidationSeverity.ERROR,
                        ))

                # Check properties
                properties = schema.get("properties", {})
                for key, value in data.items():
                    if key in properties:
                        prop_errors = self._validate_json(
                            value, properties[key], components, f"{path}.{key}"
                        )
                        errors.extend(prop_errors)
                    elif not schema.get("additionalProperties", True):
                        errors.append(ValidationError(
                            field=f"{path}.{key}",
                            message=f"Additional property {key} not allowed",
                            severity=ValidationSeverity.WARNING,
                        ))

        elif schema_type == "array":
            if not isinstance(data, list):
                errors.append(ValidationError(
                    field=path,
                    message=f"Expected array, got {type(data).__name__}",
                    severity=ValidationSeverity.ERROR,
                ))
            else:
                items_schema = schema.get("items", {})
                for i, item in enumerate(data):
                    item_errors = self._validate_json(item, items_schema, components, f"{path}[{i}]")
                    errors.extend(item_errors)

        elif schema_type == "string":
            if not isinstance(data, str):
                errors.append(ValidationError(
                    field=path,
                    message=f"Expected string, got {type(data).__name__}",
                    severity=ValidationSeverity.ERROR,
                ))
            else:
                # Check format
                fmt = schema.get("format")
                if fmt == "email" and "@" not in data:
                    errors.append(ValidationError(
                        field=path,
                        message="Invalid email format",
                        severity=ValidationSeverity.ERROR,
                    ))
                # Check pattern
                pattern = schema.get("pattern")
                if pattern:
                    import re
                    if not re.match(pattern, data):
                        errors.append(ValidationError(
                            field=path,
                            message=f"String does not match pattern {pattern}",
                            severity=ValidationSeverity.ERROR,
                        ))

        elif schema_type in ["integer", "number"]:
            if not isinstance(data, (int, float)) or isinstance(data, bool):
                errors.append(ValidationError(
                    field=path,
                    message=f"Expected {schema_type}, got {type(data).__name__}",
                    severity=ValidationSeverity.ERROR,
                ))
            else:
                # Check range
                minimum = schema.get("minimum")
                maximum = schema.get("maximum")
                if minimum is not None and data < minimum:
                    errors.append(ValidationError(
                        field=path,
                        message=f"Value {data} below minimum {minimum}",
                        severity=ValidationSeverity.ERROR,
                    ))
                if maximum is not None and data > maximum:
                    errors.append(ValidationError(
                        field=path,
                        message=f"Value {data} above maximum {maximum}",
                        severity=ValidationSeverity.ERROR,
                    ))

        elif schema_type == "boolean":
            if not isinstance(data, bool):
                errors.append(ValidationError(
                    field=path,
                    message=f"Expected boolean, got {type(data).__name__}",
                    severity=ValidationSeverity.ERROR,
                ))

        return errors


# Global instances
rate_limiter = MultiTierRateLimiter()
egress_controller = EgressController()
schema_validator = APISchemaValidator()