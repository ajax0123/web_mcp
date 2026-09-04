"""
Layer 2: Runtime Application Self-Protection & Endpoint Telemetry
==================================================================
CrowdStrike Paradigm: Behavioral EDR/XDR, RASP, Automated Containment.
"""

from cyberguard_api.security.layer2_runtime.telemetry import (
    TelemetryCollector,
    TelemetryEvent,
    TelemetryEventType,
    BehavioralBaseline,
    AnomalyDetection,
    AnomalyType,
    telemetry_collector,
)
from cyberguard_api.security.layer2_runtime.rasp import (
    RASPEngine,
    RASPInterceptor,
    RASPEvent,
    RASPThreatType,
    RASPAction,
    SQLInjectionInterceptor,
    CommandInjectionInterceptor,
    DeserializationInterceptor,
    SSRFInterceptor,
    PathTraversalInterceptor,
    CodeInjectionInterceptor,
    rasp_engine,
)
from cyberguard_api.security.layer2_runtime.containment import (
    ContainmentController,
    LocalContainmentController,
    AutoContainmentEngine,
    ContainmentOrder,
    ContainmentAction,
    ContainmentStatus,
    IsolationPolicy,
    containment_controller,
    auto_containment,
)

__all__ = [
    "TelemetryCollector",
    "TelemetryEvent",
    "TelemetryEventType",
    "BehavioralBaseline",
    "AnomalyDetection",
    "AnomalyType",
    "telemetry_collector",
    "RASPEngine",
    "RASPInterceptor",
    "RASPEvent",
    "RASPThreatType",
    "RASPAction",
    "SQLInjectionInterceptor",
    "CommandInjectionInterceptor",
    "DeserializationInterceptor",
    "SSRFInterceptor",
    "PathTraversalInterceptor",
    "CodeInjectionInterceptor",
    "rasp_engine",
    "ContainmentController",
    "LocalContainmentController",
    "AutoContainmentEngine",
    "ContainmentOrder",
    "ContainmentAction",
    "ContainmentStatus",
    "IsolationPolicy",
    "containment_controller",
    "auto_containment",
]