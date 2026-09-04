"""
Core Security Exceptions
========================
Standardized exceptions for the security architecture.
"""

from __future__ import annotations

from typing import Any, Optional


class SecurityError(Exception):
    """Base security exception."""
    def __init__(self, message: str, threat_level: str = "medium", details: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.threat_level = threat_level
        self.details = details or {}


class AuthenticationError(SecurityError):
    """Authentication failure."""
    def __init__(self, message: str = "Authentication failed", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "high", details)


class AuthorizationError(SecurityError):
    """Authorization failure."""
    def __init__(self, message: str = "Access denied", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "medium", details)


class TokenError(SecurityError):
    """Token validation error."""
    def __init__(self, message: str = "Invalid token", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "high", details)


class PolicyViolationError(SecurityError):
    """Policy violation detected."""
    def __init__(self, message: str = "Policy violation", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "high", details)


class ContainmentError(SecurityError):
    """Containment operation failure."""
    def __init__(self, message: str = "Containment failed", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "critical", details)


class TelemetryError(SecurityError):
    """Telemetry collection error."""
    def __init__(self, message: str = "Telemetry error", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "low", details)


class AuditError(SecurityError):
    """Audit logging error."""
    def __init__(self, message: str = "Audit error", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "low", details)


class SecretError(SecurityError):
    """Secret management error."""
    def __init__(self, message: str = "Secret error", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "high", details)


class WAFBlockError(SecurityError):
    """Request blocked by WAF."""
    def __init__(self, message: str = "Request blocked by WAF", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "high", details)


class RateLimitError(SecurityError):
    """Rate limit exceeded."""
    def __init__(self, message: str = "Rate limit exceeded", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "medium", details)


class SchemaValidationError(SecurityError):
    """API schema validation error."""
    def __init__(self, message: str = "Schema validation failed", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "medium", details)


class RASPError(SecurityError):
    """Runtime Application Self-Protection error."""
    def __init__(self, message: str = "RASP violation", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "critical", details)


class AnomalyDetectedError(SecurityError):
    """Behavioral anomaly detected."""
    def __init__(self, message: str = "Anomaly detected", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "high", details)


class ProvenanceError(SecurityError):
    """Data provenance error."""
    def __init__(self, message: str = "Provenance verification failed", details: Optional[dict[str, Any]] = None):
        super().__init__(message, "high", details)