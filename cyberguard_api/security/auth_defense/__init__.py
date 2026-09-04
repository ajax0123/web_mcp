"""
Authentication Defense Module
=============================
Multi-layered defense against brute-force, credential stuffing, and bot attacks.
Five targeted defensive layers:
- Layer 1: Intelligent Rate Limiting & Sliding-Window Throttling
- Layer 2: Behavioral Bot Detection & Fingerprinting
- Layer 3: Credential Intelligence & Breach Database Correlation
- Layer 4: Adaptive Multi-Factor & Step-Up Authorization
- Layer 5: Automated Telemetry, SIEM Alerting & IP Quarantine Playbooks
"""

from cyberguard_api.security.auth_defense.layer1_ratelimit import (
    RateLimitConfig,
    SlidingWindowRateLimiter,
    DistributedTokenBucket,
    MultiTierRateLimiter,
    multi_tier_limiter,
    AuthRoute,
)

from cyberguard_api.security.auth_defense.layer2_botdetection import (
    BotSignal,
    ChallengeType,
    FingerprintComponents,
    BotAnalysisResult,
    Challenge,
    Fingerprinter,
    BehavioralAnalyzer,
    EntropyAnalyzer,
    ProofOfWorkChallenge,
    BotDetector,
    bot_detector,
)

from cyberguard_api.security.auth_defense.layer3_credintel import (
    IPReputationCategory,
    CredentialStuffingPattern,
    BreachedCredentialCheck,
    IPReputation,
    GeoVelocityCheck,
    DeviceAnomalyCheck,
    CredentialStuffingAssessment,
    HaveIBeenPwnedClient,
    IPReputationService,
    GeoVelocityTracker,
    DeviceTracker,
    CredentialIntelligenceEngine,
    credential_intel,
)

from cyberguard_api.security.auth_defense.layer4_mfa import (
    MFAMethod,
    StepUpTrigger,
    LockoutState,
    MFAEnrollment,
    MFAChallenge,
    AccountLockout,
    StepUpRequest,
    SessionRevocationEvent,
    TOTPManager,
    SMSProvider,
    EmailProvider,
    PushProvider,
    WebAuthnManager,
    MFAManager,
    LockoutManager,
    StepUpEngine,
    SessionRevocationManager,
    mfa_manager,
    lockout_manager,
    step_up_engine,
)

from cyberguard_api.security.auth_defense.layer5_telemetry import (
    TelemetryEventType,
    AlertSeverity,
    PlaybookAction,
    AuthTelemetryEvent,
    SecurityAlert,
    PlaybookRule,
    PlaybookExecution,
    ImmutableAuditLog,
    TelemetryStreamer,
    SOAREngine,
    TelemetryManager,
    telemetry_manager,
)

__all__ = [
    # Layer 1
    "RateLimitConfig",
    "SlidingWindowRateLimiter",
    "DistributedTokenBucket",
    "MultiTierRateLimiter",
    "multi_tier_limiter",
    "AuthRoute",
    # Layer 2
    "BotSignal",
    "ChallengeType",
    "FingerprintComponents",
    "BotAnalysisResult",
    "Challenge",
    "Fingerprinter",
    "BehavioralAnalyzer",
    "EntropyAnalyzer",
    "ProofOfWorkChallenge",
    "BotDetector",
    "bot_detector",
    # Layer 3
    "IPReputationCategory",
    "CredentialStuffingPattern",
    "BreachedCredentialCheck",
    "IPReputation",
    "GeoVelocityCheck",
    "DeviceAnomalyCheck",
    "CredentialStuffingAssessment",
    "HaveIBeenPwnedClient",
    "IPReputationService",
    "GeoVelocityTracker",
    "DeviceTracker",
    "CredentialIntelligenceEngine",
    "credential_intel",
    # Layer 4
    "MFAMethod",
    "StepUpTrigger",
    "LockoutState",
    "MFAEnrollment",
    "MFAChallenge",
    "AccountLockout",
    "StepUpRequest",
    "SessionRevocationEvent",
    "TOTPManager",
    "SMSProvider",
    "EmailProvider",
    "PushProvider",
    "WebAuthnManager",
    "MFAManager",
    "LockoutManager",
    "StepUpEngine",
    "SessionRevocationManager",
    "mfa_manager",
    "lockout_manager",
    "step_up_engine",
    # Layer 5
    "TelemetryEventType",
    "AlertSeverity",
    "PlaybookAction",
    "AuthTelemetryEvent",
    "SecurityAlert",
    "PlaybookRule",
    "PlaybookExecution",
    "ImmutableAuditLog",
    "TelemetryStreamer",
    "SOAREngine",
    "TelemetryManager",
    "telemetry_manager",
]

__version__ = "1.0.0"