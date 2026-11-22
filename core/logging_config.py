"""
SNMK Enterprise Observability — Structured Logging & Loki Integration Engine
Implements structured JSON logging, credential redaction, request correlation tracing,
and asynchronous streaming to Grafana Loki.
"""

from __future__ import annotations

import contextvars
import datetime
import json
import logging
import os
import re
import sys
import threading
import time
from typing import Any

import requests
from core.error_sanitizer import safe_log_text

# Context variables for request tracing across async tasks
current_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("current_request_id", default="")
current_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("current_trace_id", default="")
current_agent_id: contextvars.ContextVar[str] = contextvars.ContextVar("current_agent_id", default="")
current_task_id: contextvars.ContextVar[str] = contextvars.ContextVar("current_task_id", default="")

# Sensitive patterns that must be redacted from all log outputs
SENSITIVE_LOG_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9_\-\.]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key[\"'\s:=]+)[A-Za-z0-9_\-\.]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(secret[\"'\s:=]+)[A-Za-z0-9_\-\.]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password[\"'\s:=]+)[^\"'\s&]{3,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token[\"'\s:=]+)[A-Za-z0-9_\-\.]{16,}"), r"\1[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
]


def redact_sensitive_log_text(text: str) -> str:
    """Replaces credentials, keys, and tokens with safe redaction markers."""
    if not text:
        return ""
    result = text
    for pattern, repl in SENSITIVE_LOG_PATTERNS:
        result = pattern.sub(repl, result)
    return result


class JSONLogFormatter(logging.Formatter):
    """
    Standardized JSON log formatter compatible with Grafana Loki, Fluentbit, and Logstash.
    Extracts correlation IDs, trace IDs, and agent identifiers automatically.
    """
    def __init__(self, service_name: str = "snmk-backend", environment: str = "production"):
        super().__init__()
        self.service_name = service_name
        self.environment = environment

    def format(self, record: logging.LogRecord) -> str:
        # Resolve correlation context
        req_id = getattr(record, "request_id", "") or current_request_id.get()
        trace_id = getattr(record, "trace_id", "") or current_trace_id.get()
        agent_id = getattr(record, "agent_id", "") or current_agent_id.get()
        task_id = getattr(record, "task_id", "") or current_task_id.get()

        raw_message = record.getMessage()
        safe_message = redact_sensitive_log_text(raw_message)

        log_entry: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "service": self.service_name,
            "environment": self.environment,
            "message": safe_message,
        }

        if req_id:
            log_entry["request_id"] = req_id
        if trace_id:
            log_entry["trace_id"] = trace_id
        if agent_id:
            log_entry["agent_id"] = agent_id
        if task_id:
            log_entry["task_id"] = task_id

        if record.exc_info:
            log_entry["exception"] = redact_sensitive_log_text(self.formatException(record.exc_info))

        return json.dumps(log_entry)


class LokiLoggingHandler(logging.Handler):
    """
    Asynchronous non-blocking HTTP log pusher to Grafana Loki.
    Buffers logs in memory and flushes periodically to avoid impacting application latency.
    """
    def __init__(self, loki_url: str = "http://localhost:3100", batch_size: int = 50, flush_interval: float = 2.0):
        super().__init__()
        self.loki_url = loki_url.rstrip("/") + "/loki/api/v1/push"
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._flusher_loop, daemon=True)
        self._thread.start()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            log_line = self.format(record)
            nanoseconds = str(int(time.time() * 1e9))
            entry = [nanoseconds, log_line]
            with self._lock:
                self._buffer.append(entry)
                if len(self._buffer) >= self.batch_size:
                    self._flush_locked()
        except Exception:  # noqa: BLE001
            self.handleError(record)

    def _flush_locked(self) -> None:
        if not self._buffer:
            return
        payload = {
            "streams": [
                {
                    "stream": {
                        "job": "snmk",
                        "app": "snmk-cybersecurity-platform"
                    },
                    "values": list(self._buffer)
                }
            ]
        }
        self._buffer.clear()
        try:
            requests.post(self.loki_url, json=payload, timeout=2.0)
        except Exception:  # noqa: BLE001, S110
            # Silent fallback when Loki is unreachable in offline mode
            logging.getLogger(__name__).debug("Suppressed exception (audited empty handler)", exc_info=True)

    def _flusher_loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(self.flush_interval)
            with self._lock:
                self._flush_locked()

    def close(self) -> None:
        self._stop_event.set()
        with self._lock:
            self._flush_locked()
        super().close()


def setup_observability_logging(
    level: str = "INFO",
    json_mode: bool = True,
    loki_url: str | None = None
) -> None:
    """Configures root and SWA loggers with structured JSON formatting and optional Loki streaming."""
    root_logger = logging.getLogger()
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to prevent duplicate lines
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    # Console stream handler
    console_handler = logging.StreamHandler(sys.stdout)
    if json_mode:
        formatter = JSONLogFormatter(
            service_name="snmk-backend",
            environment=os.getenv("ENVIRONMENT", "production")
        )
    else:
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Optional Loki Handler
    active_loki_url = loki_url or os.getenv("LOKI_URL")
    if active_loki_url:
        try:
            loki_handler = LokiLoggingHandler(loki_url=active_loki_url)
            loki_handler.setFormatter(JSONLogFormatter(service_name="snmk-backend"))
            root_logger.addHandler(loki_handler)
        except Exception as exc:  # noqa: BLE001
            root_logger.warning(f"Could not initialize Loki logging handler: {safe_log_text(exc)}")
