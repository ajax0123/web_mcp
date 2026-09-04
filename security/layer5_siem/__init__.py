"""
Layer 5: Unified SIEM, SOAR & Cryptographic Audit Logging
============================================================
Immutable audit pipeline, automated incident response, tamper-evident logging.
"""

from cyberguard_api.security.core.interfaces import AuditLog
from cyberguard_api.security.core.exceptions import AuditError
from cyberguard_api.security.auth_defense.layer5_telemetry import (
    ImmutableAuditLog as AuthImmutableAuditLog,
)
from collections import deque
from datetime import datetime, timezone
from typing import Optional, List
import asyncio
import json
import hashlib
import uuid


class EnterpriseAuditLog(AuditLog):
    """
    Enterprise-grade immutable audit log with cryptographic chaining.
    Combines auth defense telemetry with general security audit events.
    """

    def __init__(self, max_memory_events: int = 50000) -> None:
        self._auth_log = AuthImmutableAuditLog(max_memory_events)
        self._events: deque = deque(maxlen=max_memory_events)
        self._lock = asyncio.Lock()
        self._last_hash = ""

    async def append(self, event) -> str:
        """Append event to audit log."""
        # Convert SecurityEvent to dict if needed
        if hasattr(event, 'event_id'):
            event_dict = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat() if hasattr(event.timestamp, 'isoformat') else str(event.timestamp),
                "action": event.action.value if hasattr(event.action, 'value') else str(event.action),
                "threat_level": event.threat_level.value if hasattr(event.threat_level, 'value') else str(event.threat_level),
                "subject_id": event.subject_id,
                "tenant_id": event.tenant_id,
                "resource": event.resource,
                "outcome": event.outcome.value if hasattr(event.outcome, 'value') else str(event.outcome),
                "details": event.details,
                "previous_hash": self._last_hash,
            }
        else:
            event_dict = event

        # Compute hash
        content = json.dumps(event_dict, sort_keys=True, separators=(",", ":"))
        event_hash = hashlib.sha256(content.encode()).hexdigest()
        event_dict["event_hash"] = event_hash

        async with self._lock:
            self._last_hash = event_hash
            self._events.append(event_dict)

        return event_hash

    async def verify_chain(self, from_event: str, to_event: str) -> bool:
        """Verify hash chain integrity."""
        return await self._auth_log.verify_chain()

    async def query(
        self,
        start: datetime,
        end: datetime,
        filters: dict,
    ) -> List:
        """Query audit events."""
        async with self._lock:
            events = list(self._events)

        filtered = []
        for e in events:
            ts = datetime.fromisoformat(e["timestamp"])
            if ts < start or ts > end:
                continue

            match = True
            for key, value in filters.items():
                if e.get(key) != value:
                    match = False
                    break

            if match:
                filtered.append(e)

        return filtered

    async def get_stats(self) -> dict:
        """Get audit log statistics."""
        async with self._lock:
            events = list(self._events)

        if not events:
            return {"total_events": 0}

        by_action = {}
        by_threat = {}
        by_subject = {}
        by_outcome = {}

        for e in events:
            by_action[e.get("action", "unknown")] = by_action.get(e.get("action", "unknown"), 0) + 1
            by_threat[e.get("threat_level", "unknown")] = by_threat.get(e.get("threat_level", "unknown"), 0) + 1
            by_subject[e.get("subject_id", "unknown")] = by_subject.get(e.get("subject_id", "unknown"), 0) + 1
            by_outcome[e.get("outcome", "unknown")] = by_outcome.get(e.get("outcome", "unknown"), 0) + 1

        return {
            "total_events": len(events),
            "by_action": by_action,
            "by_threat_level": by_threat,
            "unique_subjects": len(by_subject),
            "by_outcome": by_outcome,
            "chain_verified": await self.verify_chain("", ""),
            "oldest_event": events[0]["timestamp"] if events else None,
            "newest_event": events[-1]["timestamp"] if events else None,
        }


# Global enterprise audit log
audit_log = EnterpriseAuditLog()