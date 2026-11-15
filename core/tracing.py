"""
SNMK Enterprise Observability — Distributed Tracing Engine (OpenTelemetry & Tempo)
Provides W3C tracecontext propagation, span generation, and correlation across
HTTP endpoints, database operations, CrewAI agents, and security tool executions.
"""

from __future__ import annotations

import contextlib
import logging
import time
import uuid
from collections.abc import Iterator
from typing import Any

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False

logger = logging.getLogger("snmk.tracing")

_TRACER_NAME = "snmk.cybersecurity.platform"


class SNMKSpan:
    """Lightweight deterministic tracing span for environments without heavy OTLP SDKs."""
    def __init__(self, name: str, trace_id: str, span_id: str, parent_id: str | None = None, attributes: dict[str, Any] | None = None):
        self.name = name
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_id = parent_id
        self.attributes = attributes or {}
        self.start_time = time.time()
        self.end_time: float | None = None
        self.status = "OK"
        self.status_description = ""

    def set_attribute(self, key: str, value: Any) -> None:
        # Never store sensitive keys or credentials in trace attributes
        lower_k = key.lower()
        if any(s in lower_k for s in ("password", "secret", "key", "token", "auth")):
            self.attributes[key] = "[REDACTED]"
        else:
            self.attributes[key] = str(value)

    def set_status(self, status: str, description: str = "") -> None:
        self.status = status
        self.status_description = description

    def finish(self) -> None:
        self.end_time = time.time()


class SNMKTracer:
    """Enterprise distributed tracer managing span hierarchies and trace correlation."""
    def __init__(self, service_name: str = "snmk-backend"):
        self.service_name = service_name
        self._active_spans: list[SNMKSpan] = []
        if _OTEL_AVAILABLE:
            self._otel_tracer = trace.get_tracer(_TRACER_NAME)
        else:
            self._otel_tracer = None

    @contextlib.contextmanager
    def start_span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
        parent_trace_id: str | None = None
    ) -> Iterator[SNMKSpan]:
        trace_id = parent_trace_id or uuid.uuid4().hex
        span_id = uuid.uuid4().hex[:16]
        span = SNMKSpan(name=name, trace_id=trace_id, span_id=span_id, attributes=attributes)
        
        # Also mirror to OpenTelemetry if available
        otel_span = None
        if self._otel_tracer:
            otel_span = self._otel_tracer.start_span(name)

        try:
            yield span
            span.finish()
            if otel_span:
                otel_span.set_status(Status(StatusCode.OK))
        except Exception as exc:
            span.set_status("ERROR", str(exc))
            span.finish()
            if otel_span:
                otel_span.set_status(Status(StatusCode.ERROR, str(exc)))
                otel_span.record_exception(exc)
            raise
        finally:
            if otel_span:
                otel_span.end()


# Global singleton tracer
tracer = SNMKTracer()


def extract_trace_id_from_header(traceparent: str | None) -> str:
    """Extracts or generates a 32-character hex trace ID from W3C traceparent header."""
    if not traceparent or not isinstance(traceparent, str):
        return uuid.uuid4().hex
    parts = traceparent.split("-")
    if len(parts) >= 4 and len(parts[1]) == 32:
        return parts[1]
    return uuid.uuid4().hex


def generate_traceparent(trace_id: str | None = None) -> str:
    """Generates standard W3C traceparent header (00-<trace_id>-<span_id>-01)."""
    t_id = trace_id or uuid.uuid4().hex
    s_id = uuid.uuid4().hex[:16]
    return f"00-{t_id}-{s_id}-01"
