"""
Layer 5: Automated Telemetry, SIEM Alerting & IP Quarantine Playbooks
======================================================================
Real-time threat telemetry streaming, automated SOAR playbooks,
forensic audit trails with tamper-evident logging.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Optional
import httpx


class TelemetryEventType(str, Enum):
    """Authentication telemetry event types."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    SIGNUP_SUCCESS = "signup_success"
    SIGNUP_FAILURE = "signup_failure"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_SUCCESS = "password_reset_success"
    PASSWORD_RESET_FAILURE = "password_reset_failure"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ACCOUNT_QUARANTINED = "account_quarantined"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    SESSION_REVOKED_ALL = "session_revoked_all"
    STEP_UP_REQUIRED = "step_up_required"
    STEP_UP_SUCCESS = "step_up_success"
    STEP_UP_FAILURE = "step_up_failure"
    BOT_DETECTED = "bot_detected"
    CREDENTIAL_STUFFING = "credential_stuffing"
    BRUTE_FORCE = "brute_force"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_DEVICE = "new_device"
    BREACHED_CREDENTIAL = "breached_credential"
    IP_BLOCKED = "ip_blocked"
    IP_UNBLOCKED = "ip_unblocked"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    TARPIT_APPLIED = "tarpit_applied"
    CHALLENGE_ISSUED = "challenge_issued"
    CHALLENGE_PASSED = "challenge_passed"
    CHALLENGE_FAILED = "challenge_failed"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlaybookAction(str, Enum):
    """SOAR playbook actions."""
    BLOCK_IP = "block_ip"
    BLOCK_IP_CIDR = "block_ip_cidr"
    BLOCK_ASN = "block_asn"
    BLOCK_COUNTRY = "block_country"
    RATE_LIMIT_IP = "rate_limit_ip"
    RATE_LIMIT_CIDR = "rate_limit_cidr"
    REQUIRE_MFA = "require_mfa"
    QUARANTINE_ACCOUNT = "quarantine_account"
    REVOKE_SESSIONS = "revoke_sessions"
    NOTIFY_SOC = "notify_soc"
    NOTIFY_USER = "notify_user"
    CREATE_TICKET = "create_ticket"
    ENRICH_THREAT_INTEL = "enrich_threat_intel"
    LOG_ONLY = "log_only"


@dataclass
class AuthTelemetryEvent:
    """Structured authentication telemetry event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: TelemetryEventType = TelemetryEventType.LOGIN_SUCCESS
    severity: AlertSeverity = AlertSeverity.INFO

    # Identity
    user_id: str = ""
    username: str = ""
    email: str = ""

    # Network
    ip_address: str = ""
    asn: str = ""
    asn_name: str = ""
    country: str = ""
    city: str = ""
    is_tor: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_hosting: bool = False

    # Device/Fingerprint
    device_id: str = ""
    fingerprint_id: str = ""
    user_agent: str = ""
    browser: str = ""
    os: str = ""
    is_mobile: bool = False

    # Risk
    risk_score: float = 0.0
    threat_categories: list[str] = field(default_factory=list)
    mitigation_actions: list[str] = field(default_factory=list)

    # Context
    route: str = ""
    method: str = ""
    request_id: str = ""
    session_id: str = ""
    correlation_id: str = ""

    # Details
    details: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Tamper evidence
    previous_hash: str = ""
    event_hash: str = ""

    def compute_hash(self) -> str:
        """Compute cryptographic hash for tamper evidence."""
        content = json.dumps({
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "event_hash": self.previous_hash,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class SecurityAlert:
    """Security alert for SIEM/SOC."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AlertSeverity = AlertSeverity.MEDIUM
    title: str = ""
    description: str = ""
    source: str = "auth_defense"
    category: str = ""
    tags: list[str] = field(default_factory=list)

    # Entities
    user_id: str = ""
    ip_address: str = ""
    device_id: str = ""

    # Risk
    risk_score: float = 0.0
    confidence: float = 0.0

    # Evidence
    events: list[str] = field(default_factory=list)  # event_ids
    indicators: dict[str, Any] = field(default_factory=dict)

    # Response
    recommended_actions: list[PlaybookAction] = field(default_factory=list)
    auto_executed: list[PlaybookAction] = field(default_factory=list)
    status: str = "open"  # open, investigating, resolved, false_positive

    # MITRE ATT&CK
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class PlaybookRule:
    """SOAR playbook rule."""
    rule_id: str
    name: str
    description: str
    enabled: bool = True
    priority: int = 100

    # Trigger conditions
    event_types: list[TelemetryEventType] = field(default_factory=list)
    min_severity: AlertSeverity = AlertSeverity.MEDIUM
    min_risk_score: float = 0.0
    threat_categories: list[str] = field(default_factory=list)
    min_event_count: int = 1
    time_window_seconds: int = 300  # 5 minutes

    # Aggregation
    group_by: str = "ip_address"  # ip_address, user_id, asn, country

    # Actions
    actions: list[PlaybookAction] = field(default_factory=list)
    action_params: dict[str, Any] = field(default_factory=dict)

    # Cooldown
    cooldown_seconds: int = 3600  # 1 hour
    max_executions_per_hour: int = 10


@dataclass
class PlaybookExecution:
    """Playbook execution record."""
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trigger_events: list[str] = field(default_factory=list)
    group_key: str = ""
    actions_executed: list[PlaybookAction] = field(default_factory=list)
    action_results: dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: str = ""


class ImmutableAuditLog:
    """
    Tamper-evident append-only audit log with cryptographic chaining.
    """

    def __init__(self, max_memory_events: int = 10000) -> None:
        self._events: deque[AuthTelemetryEvent] = deque(maxlen=max_memory_events)
        self._lock = asyncio.Lock()
        self._last_hash = ""

    async def append(self, event: AuthTelemetryEvent) -> str:
        """Append event to audit log, return event hash."""
        async with self._lock:
            # Chain with previous event
            event.previous_hash = self._last_hash
            event.event_hash = event.compute_hash()
            self._last_hash = event.event_hash
            self._events.append(event)
            return event.event_hash

    async def verify_chain(self, start_idx: int = 0, end_idx: int = None) -> bool:
        """Verify cryptographic chain integrity."""
        async with self._lock:
            events = list(self._events)
            if end_idx is None:
                end_idx = len(events)

            prev_hash = ""
            for i in range(start_idx, min(end_idx, len(events))):
                event = events[i]
                if event.previous_hash != prev_hash:
                    return False
                if event.compute_hash() != event.event_hash:
                    return False
                prev_hash = event.event_hash
            return True

    async def query(
        self,
        start: datetime = None,
        end: datetime = None,
        event_types: list[TelemetryEventType] = None,
        user_id: str = None,
        ip_address: str = None,
        min_severity: AlertSeverity = None,
        limit: int = 1000,
    ) -> list[AuthTelemetryEvent]:
        """Query audit log with filters."""
        async with self._lock:
            events = list(self._events)

        if start:
            events = [e for e in events if e.timestamp >= start]
        if end:
            events = [e for e in events if e.timestamp <= end]
        if event_types:
            events = [e for e in events if e.event_type in event_types]
        if user_id:
            events = [e for e in events if e.user_id == user_id]
        if ip_address:
            events = [e for e in events if e.ip_address == ip_address]
        if min_severity:
            severity_order = [AlertSeverity.INFO, AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
            min_idx = severity_order.index(min_severity)
            events = [e for e in events if severity_order.index(e.severity) >= min_idx]

        return events[-limit:]

    async def get_stats(self) -> dict[str, Any]:
        """Get audit log statistics."""
        async with self._lock:
            events = list(self._events)

        if not events:
            return {"total_events": 0}

        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        by_user = defaultdict(int)
        by_ip = defaultdict(int)

        for e in events:
            by_type[e.event_type.value] += 1
            by_severity[e.severity.value] += 1
            if e.user_id:
                by_user[e.user_id] += 1
            if e.ip_address:
                by_ip[e.ip_address] += 1

        return {
            "total_events": len(events),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "unique_users": len(by_user),
            "unique_ips": len(by_ip),
            "top_users": dict(sorted(by_user.items(), key=lambda x: -x[1])[:10]),
            "top_ips": dict(sorted(by_ip.items(), key=lambda x: -x[1])[:10]),
            "chain_verified": await self.verify_chain(),
            "oldest_event": events[0].timestamp.isoformat() if events else None,
            "newest_event": events[-1].timestamp.isoformat() if events else None,
        }


class TelemetryStreamer:
    """
    Real-time telemetry streaming to external systems (SIEM, Splunk, Elastic, etc.).
    """

    def __init__(self) -> None:
        self._endpoints: list[dict[str, Any]] = []
        self._batch_size = 100
        self._batch_timeout = 5.0  # seconds
        self._buffer: list[AuthTelemetryEvent] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._running = False

    def add_endpoint(
        self,
        url: str,
        auth_token: str = None,
        headers: dict[str, str] = None,
        format: str = "json",
    ) -> None:
        """Add streaming endpoint."""
        self._endpoints.append({
            "url": url,
            "auth_token": auth_token,
            "headers": headers or {},
            "format": format,
        })

    async def start(self) -> None:
        """Start streaming."""
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Stop streaming."""
        self._running = False
        if self._flush_task:
            await self._flush_task

    async def stream(self, event: AuthTelemetryEvent) -> None:
        """Add event to streaming buffer."""
        async with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._batch_size:
                await self._flush_buffer()

    async def _flush_loop(self) -> None:
        """Periodic flush loop."""
        while self._running:
            await asyncio.sleep(self._batch_timeout)
            async with self._lock:
                if self._buffer:
                    await self._flush_buffer()

    async def _flush_buffer(self) -> None:
        """Flush buffer to endpoints."""
        if not self._buffer:
            return

        events = self._buffer[:]
        self._buffer.clear()

        for endpoint in self._endpoints:
            try:
                await self._send_to_endpoint(endpoint, events)
            except Exception as e:
                # Log error, don't crash
                print(f"[Telemetry] Failed to send to {endpoint['url']}: {e}")

    async def _send_to_endpoint(self, endpoint: dict, events: list[AuthTelemetryEvent]) -> None:
        """Send events to single endpoint."""
        url = endpoint["url"]
        headers = endpoint["headers"].copy()

        if endpoint["auth_token"]:
            headers["Authorization"] = f"Bearer {endpoint['auth_token']}"

        headers["Content-Type"] = "application/json"

        if endpoint["format"] == "json":
            payload = [self._event_to_dict(e) for e in events]
        else:
            # CEF, LEEF, etc.
            payload = "\n".join(self._event_to_cef(e) for e in events)
            headers["Content-Type"] = "text/plain"

        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json=payload if endpoint["format"] == "json" else None, data=payload if endpoint["format"] != "json" else None, headers=headers)

    def _event_to_dict(self, event: AuthTelemetryEvent) -> dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "user_id": event.user_id,
            "username": event.username,
            "email": event.email,
            "ip_address": event.ip_address,
            "asn": event.asn,
            "asn_name": event.asn_name,
            "country": event.country,
            "city": event.city,
            "is_tor": event.is_tor,
            "is_proxy": event.is_proxy,
            "is_vpn": event.is_vpn,
            "is_hosting": event.is_hosting,
            "device_id": event.device_id,
            "fingerprint_id": event.fingerprint_id,
            "user_agent": event.user_agent,
            "browser": event.browser,
            "os": event.os,
            "is_mobile": event.is_mobile,
            "risk_score": event.risk_score,
            "threat_categories": event.threat_categories,
            "mitigation_actions": event.mitigation_actions,
            "route": event.route,
            "method": event.method,
            "request_id": event.request_id,
            "session_id": event.session_id,
            "correlation_id": event.correlation_id,
            "details": event.details,
            "metadata": event.metadata,
            "event_hash": event.event_hash,
            "previous_hash": event.previous_hash,
        }

    def _event_to_cef(self, event: AuthTelemetryEvent) -> str:
        """Convert event to CEF format."""
        # CEF: Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        return (
            f"CEF:0|CyberGuard|AuthDefense|1.0|{event.event_type.value}|"
            f"{event.event_type.value}|{self._severity_to_cef(event.severity)}|"
            f"eventId={event.event_id} userId={event.user_id} src={event.ip_address} "
            f"riskScore={event.risk_score} threatCategories={','.join(event.threat_categories)}"
        )

    def _severity_to_cef(self, severity: AlertSeverity) -> int:
        """Map severity to CEF severity (0-10)."""
        mapping = {
            AlertSeverity.INFO: 1,
            AlertSeverity.LOW: 3,
            AlertSeverity.MEDIUM: 5,
            AlertSeverity.HIGH: 8,
            AlertSeverity.CRITICAL: 10,
        }
        return mapping.get(severity, 5)


class SOAREngine:
    """
    Security Orchestration, Automation and Response engine.
    Executes playbooks based on telemetry events.
    """

    def __init__(self) -> None:
        self._rules: list[PlaybookRule] = []
        self._executions: list[PlaybookExecution] = []
        self._event_buffer: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._execution_history: dict[str, list[datetime]] = defaultdict(list)
        self._lock = asyncio.Lock()

        # Action handlers
        self._action_handlers: dict[PlaybookAction, Callable] = {}

        # Initialize default rules
        self._init_default_rules()

    def _init_default_rules(self) -> None:
        """Initialize default SOAR playbook rules."""
        self._rules = [
            # Brute force from single IP
            PlaybookRule(
                rule_id="playbook-brute-force-ip",
                name="Brute Force - Single IP",
                description="Block IP showing brute force patterns",
                event_types=[
                    TelemetryEventType.LOGIN_FAILURE,
                    TelemetryEventType.RATE_LIMIT_EXCEEDED,
                ],
                min_severity=AlertSeverity.MEDIUM,
                min_risk_score=0.6,
                min_event_count=5,
                time_window_seconds=300,
                group_by="ip_address",
                actions=[PlaybookAction.BLOCK_IP, PlaybookAction.NOTIFY_SOC],
                cooldown_seconds=3600,
            ),

            # Distributed credential stuffing
            PlaybookRule(
                rule_id="playbook-cred-stuffing-distributed",
                name="Credential Stuffing - Distributed",
                description="Detect and mitigate distributed credential stuffing",
                event_types=[TelemetryEventType.CREDENTIAL_STUFFING],
                min_severity=AlertSeverity.HIGH,
                min_risk_score=0.7,
                min_event_count=10,
                time_window_seconds=600,
                group_by="asn",
                actions=[PlaybookAction.BLOCK_ASN, PlaybookAction.RATE_LIMIT_CIDR, PlaybookAction.NOTIFY_SOC],
                cooldown_seconds=7200,
            ),

            # Bot detection
            PlaybookRule(
                rule_id="playbook-bot-detected",
                name="Bot Automation Detected",
                description="Challenge or block detected bot traffic",
                event_types=[TelemetryEventType.BOT_DETECTED],
                min_severity=AlertSeverity.MEDIUM,
                min_risk_score=0.6,
                min_event_count=3,
                time_window_seconds=300,
                group_by="ip_address",
                actions=[PlaybookAction.RATE_LIMIT_IP, PlaybookAction.REQUIRE_MFA],
                cooldown_seconds=1800,
            ),

            # Impossible travel
            PlaybookRule(
                rule_id="playbook-impossible-travel",
                name="Impossible Travel Detected",
                description="Require MFA for impossible travel",
                event_types=[TelemetryEventType.IMPOSSIBLE_TRAVEL],
                min_severity=AlertSeverity.HIGH,
                min_risk_score=0.8,
                min_event_count=1,
                time_window_seconds=3600,
                group_by="user_id",
                actions=[PlaybookAction.REQUIRE_MFA, PlaybookAction.REVOKE_SESSIONS, PlaybookAction.NOTIFY_USER],
                cooldown_seconds=3600,
            ),

            # Account takeover indicators
            PlaybookRule(
                rule_id="playbook-ato-indicators",
                name="Account Takeover Indicators",
                description="Quarantine account on confirmed ATO",
                event_types=[
                    TelemetryEventType.ACCOUNT_QUARANTINED,
                    TelemetryEventType.SESSION_REVOKED_ALL,
                ],
                min_severity=AlertSeverity.CRITICAL,
                min_risk_score=0.9,
                min_event_count=1,
                time_window_seconds=3600,
                group_by="user_id",
                actions=[PlaybookAction.QUARANTINE_ACCOUNT, PlaybookAction.REVOKE_SESSIONS, PlaybookAction.NOTIFY_SOC, PlaybookAction.CREATE_TICKET],
                cooldown_seconds=86400,
            ),

            # Breached credential usage
            PlaybookRule(
                rule_id="playbook-breached-credential",
                name="Breached Credential Used",
                description="Force password reset on breached credential",
                event_types=[TelemetryEventType.BREACHED_CREDENTIAL],
                min_severity=AlertSeverity.HIGH,
                min_risk_score=0.7,
                min_event_count=1,
                time_window_seconds=86400,
                group_by="user_id",
                actions=[PlaybookAction.REQUIRE_MFA, PlaybookAction.NOTIFY_USER],
                cooldown_seconds=86400,
            ),
        ]

    def register_action_handler(self, action: PlaybookAction, handler: Callable) -> None:
        """Register handler for playbook action."""
        self._action_handlers[action] = handler

    def add_rule(self, rule: PlaybookRule) -> None:
        """Add playbook rule."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove playbook rule."""
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return True

    async def process_event(self, event: AuthTelemetryEvent) -> list[PlaybookExecution]:
        """Process event through playbook rules."""
        executions = []

        # Add to event buffer for grouping
        group_key = event.ip_address  # Default grouping
        for rule in self._rules:
            if rule.group_by == "user_id":
                group_key = event.user_id
            elif rule.group_by == "asn":
                group_key = event.asn
            elif rule.group_by == "country":
                group_key = event.country

            buffer_key = f"{rule.rule_id}:{group_key}"
            self._event_buffer[buffer_key].append(event)

        # Check each rule
        for rule in self._rules:
            if not rule.enabled:
                continue

            # Check if event matches rule
            if not self._event_matches_rule(event, rule):
                continue

            # Check cooldown
            if not await self._check_cooldown(rule):
                continue

            # Check event count in window
            buffer_key = f"{rule.rule_id}:{group_key}"
            recent_events = self._get_recent_events(buffer_key, rule.time_window_seconds)

            if len(recent_events) < rule.min_event_count:
                continue

            # Execute playbook
            execution = await self._execute_playbook(rule, group_key, recent_events)
            executions.append(execution)

        return executions

    def _event_matches_rule(self, event: AuthTelemetryEvent, rule: PlaybookRule) -> bool:
        """Check if event matches rule conditions."""
        # Check event type
        if rule.event_types and event.event_type not in rule.event_types:
            return False

        # Check severity
        severity_order = [AlertSeverity.INFO, AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        if severity_order.index(event.severity) < severity_order.index(rule.min_severity):
            return False

        # Check risk score
        if event.risk_score < rule.min_risk_score:
            return False

        # Check threat categories
        if rule.threat_categories:
            if not any(tc in event.threat_categories for tc in rule.threat_categories):
                return False

        return True

    def _get_recent_events(self, buffer_key: str, window_seconds: int) -> list[AuthTelemetryEvent]:
        """Get events within time window."""
        buffer = self._event_buffer.get(buffer_key, deque())
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        return [e for e in buffer if e.timestamp >= cutoff]

    async def _check_cooldown(self, rule: PlaybookRule) -> bool:
        """Check if rule is in cooldown."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=rule.cooldown_seconds)

        recent = [
            ts for ts in self._execution_history.get(rule.rule_id, [])
            if ts > cutoff
        ]

        if len(recent) >= rule.max_executions_per_hour:
            return False

        return True

    async def _execute_playbook(
        self,
        rule: PlaybookRule,
        group_key: str,
        trigger_events: list[AuthTelemetryEvent],
    ) -> PlaybookExecution:
        """Execute playbook actions."""
        execution = PlaybookExecution(
            rule_id=rule.rule_id,
            trigger_events=[e.event_id for e in trigger_events],
            group_key=group_key,
        )

        action_results = {}

        for action in rule.actions:
            handler = self._action_handlers.get(action)
            if handler:
                try:
                    result = await handler(group_key, rule.action_params, trigger_events)
                    action_results[action.value] = result
                    execution.actions_executed.append(action)
                except Exception as e:
                    action_results[action.value] = {"error": str(e)}
                    execution.success = False
                    execution.error = str(e)
            else:
                action_results[action.value] = {"error": "no_handler"}
                execution.success = False

        execution.action_results = action_results
        self._executions.append(execution)
        self._execution_history[rule.rule_id].append(datetime.now(timezone.utc))

        return execution

    def get_executions(self, limit: int = 100) -> list[PlaybookExecution]:
        """Get recent playbook executions."""
        return self._executions[-limit:]

    def get_active_alerts(self) -> list[SecurityAlert]:
        """Generate alerts from recent executions."""
        alerts = []
        for execution in self._executions[-50:]:
            if execution.success and execution.actions_executed:
                rule = next((r for r in self._rules if r.rule_id == execution.rule_id), None)
                if rule:
                    alert = SecurityAlert(
                        title=rule.name,
                        description=rule.description,
                        category=rule.rule_id,
                        severity=AlertSeverity.HIGH,
                        recommended_actions=rule.actions,
                        auto_executed=execution.actions_executed,
                        indicators={"group_key": execution.group_key, "trigger_count": len(execution.trigger_events)},
                    )
                    alerts.append(alert)
        return alerts


class TelemetryManager:
    """
    Central telemetry manager coordinating audit log, streaming, and SOAR.
    """

    def __init__(self) -> None:
        self.audit_log = ImmutableAuditLog()
        self.streamer = TelemetryStreamer()
        self.soar = SOAREngine()
        self._alert_handlers: list[Callable] = []

    async def initialize(
        self,
        stream_endpoints: list[dict[str, Any]] = None,
        action_handlers: dict[PlaybookAction, Callable] = None,
    ) -> None:
        """Initialize telemetry system."""
        if stream_endpoints:
            for ep in stream_endpoints:
                self.streamer.add_endpoint(**ep)
        await self.streamer.start()

        if action_handlers:
            for action, handler in action_handlers.items():
                self.soar.register_action_handler(action, handler)

    async def shutdown(self) -> None:
        """Shutdown telemetry system."""
        await self.streamer.stop()

    async def record_event(self, event: AuthTelemetryEvent) -> str:
        """Record telemetry event to all systems."""
        # 1. Append to immutable audit log
        event_hash = await self.audit_log.append(event)

        # 2. Stream to external systems
        await self.streamer.stream(event)

        # 3. Process through SOAR
        executions = await self.soar.process_event(event)

        # 4. Generate alerts
        for execution in executions:
            if execution.success and execution.actions_executed:
                alert = SecurityAlert(
                    title=f"Playbook Executed: {execution.rule_id}",
                    description=f"Actions: {[a.value for a in execution.actions_executed]}",
                    severity=AlertSeverity.HIGH,
                    category="soar_execution",
                    recommended_actions=execution.actions_executed,
                    auto_executed=execution.actions_executed,
                    indicators={"execution_id": execution.execution_id},
                )
                for handler in self._alert_handlers:
                    try:
                        await handler(alert)
                    except Exception:
                        pass

        return event_hash

    def register_alert_handler(self, handler: Callable) -> None:
        """Register alert handler."""
        self._alert_handlers.append(handler)

    async def create_telemetry_event(
        self,
        event_type: TelemetryEventType,
        user_id: str = "",
        ip_address: str = "",
        risk_score: float = 0.0,
        threat_categories: list[str] = None,
        mitigation_actions: list[str] = None,
        **kwargs,
    ) -> AuthTelemetryEvent:
        """Create and record telemetry event."""
        event = AuthTelemetryEvent(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            risk_score=risk_score,
            threat_categories=threat_categories or [],
            mitigation_actions=mitigation_actions or [],
            **kwargs,
        )

        # Determine severity from risk score
        if risk_score >= 0.9:
            event.severity = AlertSeverity.CRITICAL
        elif risk_score >= 0.7:
            event.severity = AlertSeverity.HIGH
        elif risk_score >= 0.5:
            event.severity = AlertSeverity.MEDIUM
        elif risk_score >= 0.3:
            event.severity = AlertSeverity.LOW
        else:
            event.severity = AlertSeverity.INFO

        await self.record_event(event)
        return event


# Global telemetry manager
telemetry_manager = TelemetryManager()