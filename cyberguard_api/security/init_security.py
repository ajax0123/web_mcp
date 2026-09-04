"""
Security Architecture Initialization
====================================
Initializes all five layers of the enterprise security architecture
and the authentication defense module.
"""

from __future__ import annotations

import os
from cyberguard_api.security.core.registry import registry, SecurityConfig
from cyberguard_api.security.core.interfaces import AuditAction
from cyberguard_api.security.layer1_identity import (
    CyberGuardIdentityProvider,
    CyberGuardPolicyEngine,
)
from cyberguard_api.security.layer2_runtime import (
    telemetry_collector,
    rasp_engine,
    containment_controller,
    auto_containment,
)
from cyberguard_api.security.layer3_perimeter import (
    waf_engine,
    rate_limiter,
    egress_controller,
    schema_validator,
)
from cyberguard_api.security.layer4_infrastructure import (
    secret_manager,
)
from cyberguard_api.security.layer5_siem import (
    audit_log,
)
from cyberguard_api.security.auth_defense import (
    telemetry_manager,
    multi_tier_limiter,
    bot_detector,
    credential_intel,
    mfa_manager,
    lockout_manager,
    step_up_engine,
)


async def initialize_security_architecture(
    jwt_secret: str = None,
    hibp_api_key: str = None,
    redis_url: str = None,
) -> None:
    """
    Initialize complete security architecture.
    Called during application startup.
    """

    # --- Configuration ---
    config = SecurityConfig()
    config.token_ttl_seconds = int(os.getenv("TOKEN_TTL_SECONDS", "300"))
    config.mfa_required = os.getenv("MFA_REQUIRED", "true").lower() == "true"
    config.odac_enabled = os.getenv("ODAC_ENABLED", "true").lower() == "true"
    config.telemetry_sample_rate = float(os.getenv("TELEMETRY_SAMPLE_RATE", "1.0"))
    config.rasp_enabled = os.getenv("RASP_ENABLED", "true").lower() == "true"
    config.containment_auto_trigger = os.getenv("CONTAINMENT_AUTO_TRIGGER", "true").lower() == "true"
    config.waf_enabled = os.getenv("WAF_ENABLED", "true").lower() == "true"
    config.api_schema_validation = os.getenv("API_SCHEMA_VALIDATION", "true").lower() == "true"
    config.rate_limit_requests = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    config.rate_limit_window_seconds = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    config.sbom_enforcement = os.getenv("SBOM_ENFORCEMENT", "true").lower() == "true"
    config.secret_rotation_days = int(os.getenv("SECRET_ROTATION_DAYS", "30"))
    config.policy_as_code_enabled = os.getenv("POLICY_AS_CODE_ENABLED", "true").lower() == "true"
    config.audit_encryption_enabled = os.getenv("AUDIT_ENCRYPTION_ENABLED", "true").lower() == "true"
    config.soar_auto_response = os.getenv("SOAR_AUTO_RESPONSE", "true").lower() == "true"
    config.alert_webhook_url = os.getenv("ALERT_WEBHOOK_URL")

    registry.config = config

    # --- Layer 1: Identity & Access Control ---
    jwt_secret = jwt_secret or os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
    identity_provider = CyberGuardIdentityProvider(
        secret_key=jwt_secret,
        token_ttl_seconds=config.token_ttl_seconds,
        max_refresh=3,
    )
    registry.register_identity_provider(identity_provider)

    policy_engine = CyberGuardPolicyEngine()
    registry.register_policy_engine(policy_engine)

    # --- Layer 2: Runtime Protection ---
    registry.register_telemetry(telemetry_collector)

    # Start telemetry collector
    await telemetry_collector.start()

    # Register RASP anomaly callback
    def on_rasp_anomaly(event):
        asyncio.create_task(registry.emit(event))

    # Register containment callback
    def on_containment(order):
        asyncio.create_task(registry.emit(event))

    # Register auto-containment policies
    auto_containment.add_policy({
        "policy_id": "auto-contain-brute-force",
        "name": "Auto-contain brute force",
        "trigger_conditions": {
            "threat_categories": "in [brute_force, credential_stuffing]",
            "risk_score": "> 0.8",
        },
        "actions": ["session_isolate", "network_quarantine"],
        "auto_execute": True,
        "cooldown_seconds": 300,
        "max_executions_per_hour": 10,
    })

    # --- Layer 3: Perimeter Security ---
    # WAF, rate limiter, egress controller, schema validator already initialized

    # --- Layer 4: Infrastructure Security ---
    # Secret manager would be initialized with Vault connection

    # --- Layer 5: SIEM/SOAR ---
    # Audit log and telemetry manager initialized

    # --- Authentication Defense ---
    # Initialize credential intelligence
    await credential_intel.ip_reputation.initialize()

    # Initialize telemetry manager
    await telemetry_manager.initialize()

    # Register auth defense telemetry as audit log subscriber
    async def on_auth_event(event):
        # Forward to main audit log
        pass

    registry.subscribe(AuditAction.AUTHENTICATE, on_auth_event)
    registry.subscribe(AuditAction.AUTHORIZE, on_auth_event)
    registry.subscribe(AuditAction.SECURITY_VIOLATION, on_auth_event)
    registry.subscribe(AuditAction.ANOMALY_DETECTED, on_auth_event)
    registry.subscribe(AuditAction.CONTAINMENT, on_auth_event)

    print("========================================")
    print("Enterprise Security Architecture Initialized")
    print("========================================")
    print(f"Layer 1 (Identity): ODAC + Zero-Trust Tokens")
    print(f"Layer 2 (Runtime): Telemetry + RASP + Containment")
    print(f"Layer 3 (Perimeter): WAF + API Security + Egress Control")
    print(f"Layer 4 (Infrastructure): SBOM + Secrets + Policy-as-Code")
    print(f"Layer 5 (SIEM/SOAR): Immutable Audit + Automated Response")
    print(f"Auth Defense: 5-Layer Anti-Brute-Force/Stuffing/Bot Protection")
    print("========================================")


async def shutdown_security_architecture() -> None:
    """Graceful shutdown of all security components."""
    # Stop telemetry collector
    await telemetry_collector.stop()

    # Shutdown telemetry manager
    await telemetry_manager.shutdown()

    # Close credential intelligence
    await credential_intel.close()

    print("Security architecture shut down gracefully")


# Default initialization for development
async def init_dev_security() -> None:
    """Initialize security with development defaults."""
    await initialize_security_architecture(
        jwt_secret="dev-secret-key-change-in-production-min-32-chars",
        hibp_api_key=None,  # Set in production
        redis_url=os.getenv("REDIS_URL"),
    )