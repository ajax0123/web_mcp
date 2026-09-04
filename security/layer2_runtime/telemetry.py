"""
Layer 2: Runtime Telemetry & Behavioral EDR/XDR
================================================
CrowdStrike Paradigm: Real-time process execution metrics, memory usage,
execution anomalies, behavioral baselines.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional
from collections import defaultdict, deque
import psutil


class TelemetryEventType(str, Enum):
    """Types of telemetry events."""
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    MEMORY_SAMPLE = "memory_sample"
    CPU_SAMPLE = "cpu_sample"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACCESS = "file_access"
    MODULE_LOAD = "module_load"
    THREAD_CREATE = "thread_create"
    EXCEPTION = "exception"
    API_CALL = "api_call"
    MODEL_INFERENCE = "model_inference"
    ANOMALY_DETECTED = "anomaly_detected"


class AnomalyType(str, Enum):
    """Types of behavioral anomalies."""
    MEMORY_SPIKE = "memory_spike"
    CPU_SPIKE = "cpu_spike"
    UNEXPECTED_NETWORK = "unexpected_network"
    UNEXPECTED_FILE_ACCESS = "unexpected_file_access"
    UNEXPECTED_MODULE_LOAD = "unexpected_module_load"
    EXCESSIVE_THREADS = "excessive_threads"
    RECURSIVE_CALLS = "recursive_calls"
    TIMING_ANOMALY = "timing_anomaly"
    INJECTION_ATTEMPT = "injection_attempt"
    DESERIALIZATION_ATTACK = "deserialization_attack"


@dataclass
class TelemetryEvent:
    """Runtime telemetry event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: TelemetryEventType = TelemetryEventType.API_CALL
    process_id: int = field(default_factory=os.getpid)
    thread_id: int = field(default_factory=lambda: threading.get_ident())
    details: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralBaseline:
    """Behavioral baseline for anomaly detection."""
    subject_id: str
    metric: str
    mean: float
    std_dev: float
    min_value: float
    max_value: float
    sample_count: int
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AnomalyDetection:
    """Detected behavioral anomaly."""
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    subject_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.TIMING_ANOMALY
    severity: float = 0.0  # 0.0 - 1.0
    observed_value: float = 0.0
    expected_range: tuple[float, float] = (0.0, 0.0)
    details: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)


class TelemetryCollector:
    """
    Real-time telemetry collector for runtime behavioral monitoring.
    Streams process execution metrics, memory, CPU, and execution anomalies.
    """

    def __init__(
        self,
        sample_interval: float = 1.0,
        max_events: int = 10000,
        anomaly_threshold: float = 3.0,  # Standard deviations
    ) -> None:
        self.sample_interval = sample_interval
        self.max_events = max_events
        self.anomaly_threshold = anomaly_threshold

        self._events: deque[TelemetryEvent] = deque(maxlen=max_events)
        self._baselines: dict[str, BehavioralBaseline] = {}
        self._anomalies: list[AnomalyDetection] = []
        self._running = False
        self._collector_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

        # Callbacks for real-time alerting
        self._anomaly_callbacks: list[Callable[[AnomalyDetection], None]] = []

    async def start(self) -> None:
        """Start telemetry collection."""
        if self._running:
            return
        self._running = True
        self._collector_task = asyncio.create_task(self._collection_loop())

    async def stop(self) -> None:
        """Stop telemetry collection."""
        self._running = False
        if self._collector_task:
            self._collector_task.cancel()
            try:
                await self._collector_task
            except asyncio.CancelledError:
                pass

    async def _collection_loop(self) -> None:
        """Main collection loop."""
        process = psutil.Process(os.getpid())

        while self._running:
            try:
                # Collect process metrics
                await self._collect_process_metrics(process)

                # Collect thread info
                await self._collect_thread_info(process)

                # Collect network connections
                await self._collect_network_connections(process)

                await asyncio.sleep(self.sample_interval)
            except asyncio.CancelledError:
                break
            except Exception:
                pass  # Never crash the collector

    async def _collect_process_metrics(self, process: psutil.Process) -> None:
        """Collect process memory and CPU metrics."""
        try:
            mem_info = process.memory_info()
            cpu_percent = process.cpu_percent()

            event = TelemetryEvent(
                event_type=TelemetryEventType.MEMORY_SAMPLE,
                details={
                    "rss_bytes": mem_info.rss,
                    "vms_bytes": mem_info.vms,
                    "percent": process.memory_percent(),
                },
            )
            await self.record_event(event)

            event = TelemetryEvent(
                event_type=TelemetryEventType.CPU_SAMPLE,
                details={"percent": cpu_percent},
            )
            await self.record_event(event)

            # Check for anomalies
            await self._check_metric_anomaly("memory_rss", mem_info.rss / 1024 / 1024)  # MB
            await self._check_metric_anomaly("cpu_percent", cpu_percent)

        except Exception:
            pass

    async def _collect_thread_info(self, process: psutil.Process) -> None:
        """Collect thread information."""
        try:
            threads = process.threads()
            thread_count = len(threads)

            event = TelemetryEvent(
                event_type=TelemetryEventType.THREAD_CREATE,
                details={"thread_count": thread_count},
            )
            await self.record_event(event)

            await self._check_metric_anomaly("thread_count", float(thread_count))

        except Exception:
            pass

    async def _collect_network_connections(self, process: psutil.Process) -> None:
        """Collect network connections."""
        try:
            connections = process.connections()
            for conn in connections:
                if conn.status == "ESTABLISHED":
                    event = TelemetryEvent(
                        event_type=TelemetryEventType.NETWORK_CONNECTION,
                        details={
                            "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            "status": conn.status,
                            "family": conn.family.name if conn.family else None,
                            "type": conn.type.name if conn.type else None,
                        },
                    )
                    await self.record_event(event)
        except Exception:
            pass

    async def record_event(self, event: TelemetryEvent) -> None:
        """Record telemetry event."""
        async with self._lock:
            self._events.append(event)

    async def record_api_call(
        self,
        endpoint: str,
        method: str,
        duration_ms: float,
        status_code: int,
        context: dict[str, Any],
    ) -> None:
        """Record API call telemetry."""
        event = TelemetryEvent(
            event_type=TelemetryEventType.API_CALL,
            details={
                "endpoint": endpoint,
                "method": method,
                "duration_ms": duration_ms,
                "status_code": status_code,
            },
            context=context,
        )
        await self.record_event(event)
        await self._check_metric_anomaly(f"api_latency_{endpoint}", duration_ms)

    async def record_model_inference(
        self,
        model_name: str,
        input_shape: tuple,
        duration_ms: float,
        context: dict[str, Any],
    ) -> None:
        """Record ML model inference telemetry."""
        event = TelemetryEvent(
            event_type=TelemetryEventType.MODEL_INFERENCE,
            details={
                "model_name": model_name,
                "input_shape": str(input_shape),
                "duration_ms": duration_ms,
            },
            context=context,
        )
        await self.record_event(event)

    async def _check_metric_anomaly(self, metric: str, value: float) -> None:
        """Check if metric value is anomalous."""
        baseline = self._baselines.get(metric)
        if not baseline or baseline.sample_count < 10:
            # Update baseline
            await self._update_baseline(metric, value)
            return

        # Check if value is outside threshold standard deviations
        z_score = abs(value - baseline.mean) / max(baseline.std_dev, 0.001)
        if z_score > self.anomaly_threshold:
            anomaly = AnomalyDetection(
                subject_id=f"process_{os.getpid()}",
                anomaly_type=self._map_metric_to_anomaly(metric),
                severity=min(1.0, z_score / 10.0),
                observed_value=value,
                expected_range=(
                    baseline.mean - self.anomaly_threshold * baseline.std_dev,
                    baseline.mean + self.anomaly_threshold * baseline.std_dev,
                ),
                details={"metric": metric, "z_score": z_score, "baseline_mean": baseline.mean},
            )
            await self._handle_anomaly(anomaly)

        # Update baseline with new value
        await self._update_baseline(metric, value)

    def _map_metric_to_anomaly(self, metric: str) -> AnomalyType:
        """Map metric to anomaly type."""
        mapping = {
            "memory_rss": AnomalyType.MEMORY_SPIKE,
            "cpu_percent": AnomalyType.CPU_SPIKE,
            "thread_count": AnomalyType.EXCESSIVE_THREADS,
        }
        for key, anomaly in mapping.items():
            if key in metric:
                return anomaly
        return AnomalyType.TIMING_ANOMALY

    async def _update_baseline(self, metric: str, value: float) -> None:
        """Update behavioral baseline using exponential moving average."""
        baseline = self._baselines.get(metric)
        alpha = 0.1  # EMA factor

        if baseline is None:
            baseline = BehavioralBaseline(
                subject_id=f"process_{os.getpid()}",
                metric=metric,
                mean=value,
                std_dev=0.0,
                min_value=value,
                max_value=value,
                sample_count=1,
            )
        else:
            old_mean = baseline.mean
            baseline.mean = alpha * value + (1 - alpha) * baseline.mean
            baseline.std_dev = alpha * (value - old_mean) ** 2 + (1 - alpha) * baseline.std_dev ** 2
            baseline.std_dev = baseline.std_dev ** 0.5
            baseline.min_value = min(baseline.min_value, value)
            baseline.max_value = max(baseline.max_value, value)
            baseline.sample_count += 1
            baseline.updated_at = datetime.now(timezone.utc)

        self._baselines[metric] = baseline

    async def _handle_anomaly(self, anomaly: AnomalyDetection) -> None:
        """Handle detected anomaly."""
        self._anomalies.append(anomaly)

        # Trigger callbacks
        for callback in self._anomaly_callbacks:
            try:
                callback(anomaly)
            except Exception:
                pass

    def register_anomaly_callback(self, callback: Callable[[AnomalyDetection], None]) -> None:
        """Register callback for anomaly notifications."""
        self._anomaly_callbacks.append(callback)

    def get_events(
        self,
        event_type: Optional[TelemetryEventType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[TelemetryEvent]:
        """Get recent telemetry events."""
        events = list(self._events)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if since:
            events = [e for e in events if e.timestamp >= since]
        return events[-limit:]

    def get_anomalies(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[AnomalyDetection]:
        """Get recent anomalies."""
        anomalies = self._anomalies
        if since:
            anomalies = [a for a in anomalies if a.timestamp >= since]
        return anomalies[-limit:]

    def get_baselines(self) -> dict[str, BehavioralBaseline]:
        """Get all behavioral baselines."""
        return dict(self._baselines)


# Global telemetry collector
telemetry_collector = TelemetryCollector()