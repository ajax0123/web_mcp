"""
observability.py
================================================================================
Request-scoped tracing, structured JSON logging, Prometheus metrics, and a shared
sanitised-error helper. Lives OUTSIDE ``cyberguard_api/security/`` (that tree is
owned by the security track).

Audit findings addressed: PP-H2, PP-H4, PP-L5 (and used by PP-M8).

Wiring (from ``main.py``)::

    from cyberguard_api.observability import configure_logging, install_observability
    configure_logging()                       # before the app is built
    install_observability(app)                # after the other middleware

Everything here is dependency-light: only ``prometheus_client`` (a pinned
runtime dependency). If it is somehow missing, ``/metrics`` degrades to a 501
and the rest of the module still works.
================================================================================
"""

from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )

    _HAVE_PROM = True
except Exception:  # pragma: no cover - only if the pin is missing
    _HAVE_PROM = False

# ============================================================================
# Request-id context
# ============================================================================

_REQUEST_ID: ContextVar[str] = ContextVar("cyberguard_request_id", default="-")
_REQUEST_ID_HEADER = "x-request-id"


def current_request_id() -> str:
    """The id bound to the request currently being served, or ``"-"`` outside one."""
    return _REQUEST_ID.get()


def new_correlation_id() -> str:
    return uuid.uuid4().hex


# ============================================================================
# Structured JSON logging (PP-H4)
# ============================================================================

class JsonLogFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, msg, request_id, + extras."""

    _RESERVED = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", None) or current_request_id(),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and key not in payload and not key.startswith("_"):
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = repr(value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class _RequestIdLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = current_request_id()
        return True


_LOGGING_CONFIGURED = False


def configure_logging(level: str | int | None = None) -> None:
    """Route the root logger to stdout as line-delimited JSON. Idempotent."""
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return
    lvl = level or "INFO"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    handler.addFilter(_RequestIdLogFilter())

    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(lvl)
    # uvicorn.error flows through our handler; uvicorn.access is SILENCED — the
    # ObservabilityMiddleware emits the one structured "request" line per request
    # (A-L2). Belt-and-suspenders: also pass --no-access-log to uvicorn.
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
    acc = logging.getLogger("uvicorn.access")
    acc.handlers[:] = []
    acc.propagate = False
    acc.disabled = True
    _LOGGING_CONFIGURED = True


# ============================================================================
# Prometheus metrics (PP-H4)
# ============================================================================

if _HAVE_PROM:
    _REGISTRY = CollectorRegistry()
    _REQ_TOTAL = Counter(
        "cyberguard_http_requests_total",
        "HTTP requests",
        ["method", "path", "status"],
        registry=_REGISTRY,
    )
    _REQ_LATENCY = Histogram(
        "cyberguard_http_request_duration_seconds",
        "HTTP request latency",
        ["method", "path"],
        registry=_REGISTRY,
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
else:  # pragma: no cover
    _REGISTRY = None


_UNMATCHED_LABEL = "<unmatched>"


def _route_template(scope: Scope) -> str:
    """
    Low-cardinality metric label (A-M2).

    A request that matched a route -> the route's template (``/users/{id}/...``).
    A request that matched NOTHING (a 404 / probe / scan) -> a single constant
    ``<unmatched>`` label, so a flood of distinct unmatched paths cannot create
    one time series each and exhaust the registry.
    """
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if path else _UNMATCHED_LABEL


def metrics_asgi_response() -> Response:
    if not _HAVE_PROM:
        raise HTTPException(status_code=501, detail="metrics unavailable (prometheus_client missing)")
    return Response(generate_latest(_REGISTRY), media_type=CONTENT_TYPE_LATEST)


# ============================================================================
# Middleware: bind X-Request-ID, time the request, count it
# ============================================================================

class ObservabilityMiddleware:
    """
    Pure-ASGI: read/generate ``X-Request-ID``, bind it to the contextvar, echo it
    on the response, record latency + a request counter.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._log = logging.getLogger("cyberguard.access")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = ""
        for name, value in scope.get("headers", []):
            if name == _REQUEST_ID_HEADER.encode():
                incoming = value.decode("latin-1")[:128].strip()
                break
        request_id = incoming or new_correlation_id()
        token = _REQUEST_ID.set(request_id)

        method = scope.get("method", "GET")
        started = time.perf_counter()
        status_holder = {"code": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
                headers = list(message.get("headers", []))
                headers.append((_REQUEST_ID_HEADER.encode(), request_id.encode()))
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - started
            path = _route_template(scope)
            code = status_holder["code"]
            if _HAVE_PROM:
                try:
                    _REQ_TOTAL.labels(method, path, str(code)).inc()
                    _REQ_LATENCY.labels(method, path).observe(elapsed)
                except Exception:  # pragma: no cover
                    pass
            self._log.info(
                "request",
                extra={
                    "request_id": request_id,
                    "route": path,
                    "method": method,
                    "status": code,
                    "latency_ms": round(elapsed * 1000, 2),
                },
            )
            _REQUEST_ID.reset(token)


def install_observability(app: FastAPI) -> None:
    """Add the observability middleware and mount the rate-limit-exempt /metrics."""
    app.add_middleware(ObservabilityMiddleware)

    # A-L3: async route, exemption applied at definition (same pattern as /health).
    limiter = getattr(app.state, "limiter", None)

    async def _metrics() -> Response:
        return metrics_asgi_response()

    if limiter is not None:
        try:
            _metrics = limiter.exempt(_metrics)
        except Exception:  # pragma: no cover
            pass
    app.add_api_route("/metrics", _metrics, methods=["GET"], include_in_schema=False)


# ============================================================================
# Shared sanitised error (PP-H2 / PP-L5)
# ============================================================================

def sanitized_error(
    kind: str,
    exc: BaseException | None = None,
    *,
    status_code: int = 500,
    client_message: str | None = None,
    logger: logging.Logger | None = None,
) -> HTTPException:
    """
    Log the real exception server-side against the request id; return an
    ``HTTPException`` whose body carries only a generic message + that id.

    ``correlation_id`` in the body == the ``X-Request-ID`` on the response, so an
    operator can pivot from a client report straight to the structured log line.
    """
    correlation_id = current_request_id()
    if correlation_id in ("", "-", None):
        correlation_id = new_correlation_id()
    log = logger or logging.getLogger("cyberguard.api")
    log.error(
        "%s failed",
        kind,
        exc_info=exc,
        extra={"request_id": correlation_id, "error_kind": kind, "http_status": status_code},
    )
    detail = {
        "error": client_message or ("Service temporarily unavailable" if status_code == 503 else "Internal error"),
        "correlation_id": correlation_id,
    }
    return HTTPException(status_code=status_code, detail=detail)
