"""
Layer 2: Automated Containment & Isolation
===========================================
CrowdStrike Paradigm: Programmatic hooks for instant sandboxing,
network isolation, or termination of compromised sessions/containers.
"""

from __future__ import annotations

import asyncio
import os
import signal
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ContainmentAction(str, Enum):
    """Types of containment actions."""
    SESSION_ISOLATE = "session_isolate"
    SESSION_TERMINATE = "session_terminate"
    CONTAINER_ISOLATE = "container_isolate"
    CONTAINER_TERMINATE = "container_terminate"
    PROCESS_TERMINATE = "process_terminate"
    NETWORK_QUARANTINE = "network_quarantine"
    FILESYSTEM_FREEZE = "filesystem_freeze"
    ACCOUNT_LOCK = "account_lock"


class ContainmentStatus(str, Enum):
    """Containment operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ContainmentOrder:
    """Containment order/request."""
    order_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: ContainmentAction = ContainmentAction.SESSION_ISOLATE
    target_id: str = ""  # session_id, container_id, pid, etc.
    reason: str = ""
    threat_level: str = "high"
    requested_by: str = "system"
    metadata: dict[str, Any] = field(default_factory=dict)
    status: ContainmentStatus = ContainmentStatus.PENDING
    completed_at: Optional[datetime] = None
    result: dict[str, Any] = field(default_factory=dict)


@dataclass
class IsolationPolicy:
    """Policy defining containment triggers."""
    policy_id: str
    name: str
    trigger_conditions: dict[str, Any]  # e.g., {"anomaly_score": "> 0.9", "threat_types": ["sql_injection"]}
    actions: list[ContainmentAction]
    auto_execute: bool = True
    cooldown_seconds: int = 300
    max_executions_per_hour: int = 10


class ContainmentController(ABC):
    """Abstract containment controller."""

    @abstractmethod
    async def isolate_session(self, session_id: str, reason: str) -> bool:
        pass

    @abstractmethod
    async def isolate_container(self, container_id: str, reason: str) -> bool:
        pass

    @abstractmethod
    async def terminate_process(self, pid: int, reason: str) -> bool:
        pass


class LocalContainmentController(ContainmentController):
    """
    Local containment controller for development/single-host environments.
    In production, this would integrate with Kubernetes, container runtimes, etc.
    """

    def __init__(self) -> None:
        self._active_containments: dict[str, ContainmentOrder] = {}
        self._session_store: dict[str, dict[str, Any]] = {}  # In-memory session tracking
        self._container_store: dict[str, dict[str, Any]] = {}  # Container tracking
        self._lock = asyncio.Lock()

    async def isolate_session(self, session_id: str, reason: str) -> bool:
        """Isolate user session by marking it as quarantined."""
        order = ContainmentOrder(
            action=ContainmentAction.SESSION_ISOLATE,
            target_id=session_id,
            reason=reason,
        )

        async with self._lock:
            self._active_containments[order.order_id] = order
            order.status = ContainmentStatus.IN_PROGRESS

            # Mark session as isolated
            if session_id in self._session_store:
                self._session_store[session_id]["isolated"] = True
                self._session_store[session_id]["isolation_reason"] = reason
                self._session_store[session_id]["isolated_at"] = datetime.now(timezone.utc).isoformat()

            order.status = ContainmentStatus.COMPLETED
            order.completed_at = datetime.now(timezone.utc)
            order.result = {"isolated": True, "session_id": session_id}

        return True

    async def terminate_session(self, session_id: str, reason: str) -> bool:
        """Terminate user session completely."""
        order = ContainmentOrder(
            action=ContainmentAction.SESSION_TERMINATE,
            target_id=session_id,
            reason=reason,
        )

        async with self._lock:
            self._active_containments[order.order_id] = order
            order.status = ContainmentStatus.IN_PROGRESS

            if session_id in self._session_store:
                self._session_store[session_id]["terminated"] = True
                self._session_store[session_id]["termination_reason"] = reason
                self._session_store[session_id]["terminated_at"] = datetime.now(timezone.utc).isoformat()
                # Remove from active sessions
                del self._session_store[session_id]

            order.status = ContainmentStatus.COMPLETED
            order.completed_at = datetime.now(timezone.utc)
            order.result = {"terminated": True, "session_id": session_id}

        return True

    async def isolate_container(self, container_id: str, reason: str) -> bool:
        """Isolate container (network namespace, filesystem, etc.)."""
        order = ContainmentOrder(
            action=ContainmentAction.CONTAINER_ISOLATE,
            target_id=container_id,
            reason=reason,
        )

        async with self._lock:
            self._active_containments[order.order_id] = order
            order.status = ContainmentStatus.IN_PROGRESS

            if container_id in self._container_store:
                self._container_store[container_id]["isolated"] = True
                self._container_store[container_id]["isolation_reason"] = reason
                self._container_store[container_id]["isolated_at"] = datetime.now(timezone.utc).isoformat()

            order.status = ContainmentStatus.COMPLETED
            order.completed_at = datetime.now(timezone.utc)
            order.result = {"isolated": True, "container_id": container_id}

        return True

    async def terminate_container(self, container_id: str, reason: str) -> bool:
        """Terminate container."""
        order = ContainmentOrder(
            action=ContainmentAction.CONTAINER_TERMINATE,
            target_id=container_id,
            reason=reason,
        )

        async with self._lock:
            self._active_containments[order.order_id] = order
            order.status = ContainmentStatus.IN_PROGRESS

            if container_id in self._container_store:
                self._container_store[container_id]["terminated"] = True
                self._container_store[container_id]["termination_reason"] = reason
                self._container_store[container_id]["terminated_at"] = datetime.now(timezone.utc).isoformat()
                del self._container_store[container_id]

            order.status = ContainmentStatus.COMPLETED
            order.completed_at = datetime.now(timezone.utc)
            order.result = {"terminated": True, "container_id": container_id}

        return True

    async def terminate_process(self, pid: int, reason: str) -> bool:
        """Terminate suspicious process."""
        order = ContainmentOrder(
            action=ContainmentAction.PROCESS_TERMINATE,
            target_id=str(pid),
            reason=reason,
        )

        async with self._lock:
            self._active_containments[order.order_id] = order
            order.status = ContainmentStatus.IN_PROGRESS

            try:
                os.kill(pid, signal.SIGTERM)
                # Give it a moment
                await asyncio.sleep(0.5)
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Already dead

                order.status = ContainmentStatus.COMPLETED
                order.result = {"terminated": True, "pid": pid}
            except ProcessLookupError:
                order.status = ContainmentStatus.FAILED
                order.result = {"terminated": False, "error": "process_not_found"}
            except PermissionError:
                order.status = ContainmentStatus.FAILED
                order.result = {"terminated": False, "error": "permission_denied"}

            order.completed_at = datetime.now(timezone.utc)

        return order.status == ContainmentStatus.COMPLETED

    async def quarantine_network(self, target_id: str, reason: str) -> bool:
        """Quarantine network access for target."""
        # In production, would use iptables, eBPF, or CNI plugins
        order = ContainmentOrder(
            action=ContainmentAction.NETWORK_QUARANTINE,
            target_id=target_id,
            reason=reason,
        )

        async with self._lock:
            self._active_containments[order.order_id] = order
            order.status = ContainmentStatus.IN_PROGRESS
            # Simulated
            order.status = ContainmentStatus.COMPLETED
            order.completed_at = datetime.now(timezone.utc)
            order.result = {"quarantined": True, "target": target_id}

        return True

    def register_session(self, session_id: str, metadata: dict[str, Any]) -> None:
        """Register session for tracking."""
        self._session_store[session_id] = {
            **metadata,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "isolated": False,
            "terminated": False,
        }

    def register_container(self, container_id: str, metadata: dict[str, Any]) -> None:
        """Register container for tracking."""
        self._container_store[container_id] = {
            **metadata,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "isolated": False,
            "terminated": False,
        }

    def get_containment_status(self, order_id: str) -> Optional[ContainmentOrder]:
        """Get containment order status."""
        return self._active_containments.get(order_id)

    def get_active_containments(self) -> list[ContainmentOrder]:
        """Get all active containment orders."""
        return list(self._active_containments.values())

    def get_session_status(self, session_id: str) -> Optional[dict[str, Any]]:
        """Get session status."""
        return self._session_store.get(session_id)

    def get_container_status(self, container_id: str) -> Optional[dict[str, Any]]:
        """Get container status."""
        return self._container_store.get(container_id)


class AutoContainmentEngine:
    """
    Automated containment engine that evaluates policies and triggers containment.
    """

    def __init__(self, controller: ContainmentController) -> None:
        self.controller = controller
        self._policies: list[IsolationPolicy] = []
        self._execution_history: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    def add_policy(self, policy: IsolationPolicy) -> None:
        """Add isolation policy."""
        self._policies.append(policy)

    def remove_policy(self, policy_id: str) -> None:
        """Remove isolation policy."""
        self._policies = [p for p in self._policies if p.policy_id != policy_id]

    async def evaluate_and_execute(
        self,
        context: dict[str, Any],
        source: str = "telemetry",
    ) -> list[ContainmentOrder]:
        """
        Evaluate all policies against context and execute matching ones.
        Returns list of executed containment orders.
        """
        executed = []

        for policy in self._policies:
            if await self._matches_policy(policy, context):
                # Check cooldown
                if not await self._check_cooldown(policy):
                    continue

                # Execute actions
                for action in policy.actions:
                    order = await self._execute_action(action, context, policy.policy_id)
                    executed.append(order)

                # Record execution
                async with self._lock:
                    self._execution_history.append({
                        "policy_id": policy.policy_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "context": context,
                        "orders": [o.order_id for o in executed],
                    })

        return executed

    async def _matches_policy(self, policy: IsolationPolicy, context: dict[str, Any]) -> bool:
        """Check if context matches policy trigger conditions."""
        for key, condition in policy.trigger_conditions.items():
            value = context.get(key)
            if value is None:
                return False

            # Parse condition (e.g., "> 0.9", "in [sql_injection, rce]")
            if isinstance(condition, str):
                if condition.startswith("> "):
                    threshold = float(condition[2:])
                    if not (isinstance(value, (int, float)) and value > threshold):
                        return False
                elif condition.startswith(">= "):
                    threshold = float(condition[3:])
                    if not (isinstance(value, (int, float)) and value >= threshold):
                        return False
                elif condition.startswith("< "):
                    threshold = float(condition[2:])
                    if not (isinstance(value, (int, float)) and value < threshold):
                        return False
                elif condition.startswith("in "):
                    # Parse list
                    import ast
                    try:
                        allowed = ast.literal_eval(condition[3:])
                        if value not in allowed:
                            return False
                    except Exception:
                        return False
                elif condition == "true":
                    if not value:
                        return False
                elif condition == "false":
                    if value:
                        return False
            elif isinstance(condition, (int, float)):
                if value != condition:
                    return False
            elif isinstance(condition, list):
                if value not in condition:
                    return False
            else:
                if value != condition:
                    return False

        return True

    async def _check_cooldown(self, policy: IsolationPolicy) -> bool:
        """Check if policy is in cooldown."""
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - policy.cooldown_seconds

        recent_executions = [
            e for e in self._execution_history
            if e["policy_id"] == policy.policy_id
            and datetime.fromisoformat(e["timestamp"]).timestamp() > cutoff
        ]

        return len(recent_executions) < policy.max_executions_per_hour

    async def _execute_action(
        self,
        action: ContainmentAction,
        context: dict[str, Any],
        policy_id: str,
    ) -> ContainmentOrder:
        """Execute containment action."""
        target_id = context.get("session_id") or context.get("container_id") or context.get("pid") or "unknown"
        reason = f"Auto-containment: {policy_id} - {context.get('trigger', 'policy_match')}"

        if action == ContainmentAction.SESSION_ISOLATE:
            await self.controller.isolate_session(target_id, reason)
        elif action == ContainmentAction.SESSION_TERMINATE:
            await self.controller.terminate_session(target_id, reason)
        elif action == ContainmentAction.CONTAINER_ISOLATE:
            await self.controller.isolate_container(target_id, reason)
        elif action == ContainmentAction.CONTAINER_TERMINATE:
            await self.controller.terminate_container(target_id, reason)
        elif action == ContainmentAction.PROCESS_TERMINATE:
            pid = context.get("pid")
            if pid:
                await self.controller.terminate_process(pid, reason)
        elif action == ContainmentAction.NETWORK_QUARANTINE:
            await self.controller.quarantine_network(target_id, reason)

        return ContainmentOrder(
            action=action,
            target_id=target_id,
            reason=reason,
            status=ContainmentStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
        )


# Global containment controller
containment_controller = LocalContainmentController()
auto_containment = AutoContainmentEngine(containment_controller)