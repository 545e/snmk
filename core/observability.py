"""
SWA AI — Observability: Prometheus metrics and correlation IDs.

Only metrics that can be measured are exported. Nothing is invented.
OpenTelemetry is optional: when the SDK is installed and SWA_OTEL_ENABLED is
on, spans are emitted; otherwise the platform still exposes Prometheus
metrics and correlation IDs without pretending tracing is enabled.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

from fastapi import Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware

REQUESTS = Counter("snmk_platform_requests_total", "HTTP requests", ["method", "path", "status"])
LATENCY = Histogram("snmk_platform_request_seconds", "HTTP request latency", ["method", "path"])
ACTIVE = Gauge("snmk_platform_requests_in_flight", "Requests currently in flight")
AGENT_TASKS = Counter("snmk_crew_tasks_total", "Crew tasks", ["role", "status"])
ALERTS = Counter("snmk_alerts_total", "Alerts created", ["severity"])
START_TIME = Gauge("snmk_process_start_time", "Process start timestamp (unix seconds)")

START_TIME.set(time.time())


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Records request metrics and attaches a correlation ID to every response."""

    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID") or uuid.uuid4().hex
        request.state.correlation_id = correlation_id
        path = request.url.path
        method = request.method
        ACTIVE.inc()
        started = time.perf_counter()
        status = 500
        try:
            response: Response = await call_next(request)
            status = response.status_code
            response.headers["X-Correlation-ID"] = correlation_id
            return response
        finally:
            ACTIVE.dec()
            LATENCY.labels(method=method, path=path).observe(time.perf_counter() - started)
            REQUESTS.labels(method=method, path=path, status=str(status)).inc()


def metrics_response():
    """Returns a Prometheus exposition response built from live counters."""
    from fastapi.responses import Response

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


def record_agent_task(role: str, status: str) -> None:
    """Records a measured Crew task outcome."""
    AGENT_TASKS.labels(role=role, status=status).inc()


def record_alert(severity: str) -> None:
    ALERTS.labels(severity=severity).inc()


def otel_status() -> dict[str, Any]:
    """Reports whether OpenTelemetry tracing is genuinely enabled."""
    enabled = os.environ.get("SWA_OTEL_ENABLED", "0").lower() in ("1", "true", "yes", "on")
    import importlib.util

    installed = importlib.util.find_spec("opentelemetry.sdk") is not None
    return {
        "otel_sdk_installed": installed,
        "tracing_enabled": bool(enabled and installed),
        "endpoint": os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "") or "not configured",
    }
