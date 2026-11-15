"""
Unit and Integration Tests for SNMK Grafana Observability, Prometheus Metrics & Tracing.
"""

import json
import logging
import os

from fastapi.testclient import TestClient

from core.logging_config import JSONLogFormatter, redact_sensitive_log_text
from core.metrics import (
    APP_UPTIME_SECONDS,
    DB_AVAILABLE,
    refresh_live_telemetry,
)
from core.tracing import tracer
from web.server import app

client = TestClient(app)


def test_prometheus_metrics_endpoint():
    """Verify that /metrics serves standard Prometheus exposition format."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    assert "X-Request-ID" in response.headers
    assert "traceparent" in response.headers

    body = response.text
    assert "snmk_app_uptime_seconds" in body
    assert "snmk_http_requests_total" in body
    assert "snmk_db_available" in body
    assert "snmk_ai_agents_registered_total" in body
    assert "snmk_security_tools_registered_total" in body


def test_http_metrics_recording():
    """Verify that HTTP requests increment request counters and record latency."""
    client.get("/health")
    metrics_res = client.get("/metrics")
    assert 'snmk_http_requests_total{endpoint="/health",method="GET",status_code="200"}' in metrics_res.text


def test_http_error_metrics_recording():
    """Verify that HTTP 4xx and 5xx errors increment error counters."""
    client.get("/nonexistent-endpoint-for-404-check")
    metrics_res = client.get("/metrics")
    assert "snmk_http_errors_total" in metrics_res.text


def test_traceparent_propagation():
    """Verify W3C traceparent extraction and correlation propagation."""
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    span_id = "00f067aa0ba902b7"
    custom_traceparent = f"00-{trace_id}-{span_id}-01"

    res = client.get("/health", headers={"traceparent": custom_traceparent})
    assert res.status_code == 200
    assert "traceparent" in res.headers
    assert trace_id in res.headers["traceparent"]
    assert res.headers["X-Trace-ID"] == trace_id


def test_json_log_redaction():
    """Verify that sensitive credentials, tokens, and passwords are redacted from log outputs."""
    raw_message = "User authenticated with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and api_key=sk-proj-supersecretkey123456"
    safe_message = redact_sensitive_log_text(raw_message)

    assert "eyJhbGci" not in safe_message
    assert "sk-proj-supersecretkey123456" not in safe_message
    assert "[REDACTED]" in safe_message

    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="DB connect password=SecretPassword123!",
        args=(),
        exc_info=None
    )
    formatter = JSONLogFormatter(service_name="test-service")
    formatted_json = formatter.format(record)
    parsed = json.loads(formatted_json)

    assert "SecretPassword123!" not in parsed["message"]
    assert "[REDACTED]" in parsed["message"]
    assert parsed["level"] == "INFO"
    assert parsed["service"] == "test-service"


def test_live_telemetry_refresh():
    """Verify that refresh_live_telemetry updates gauges with valid data."""
    refresh_live_telemetry()
    assert APP_UPTIME_SECONDS._value.get() >= 0
    assert DB_AVAILABLE._value.get() in (0, 1)


def test_tracer_span_execution():
    """Verify distributed tracer creates and closes spans."""
    with tracer.start_span("unit_test_span", attributes={"test.attr": "value"}) as span:
        assert span.name == "unit_test_span"
        assert span.attributes["test.attr"] == "value"
        span.set_attribute("password", "leak_attempt")
        assert span.attributes["password"] == "[REDACTED]"
    assert span.end_time is not None
    assert span.status == "OK"


def test_grafana_dashboards_validity():
    """Verify that all 15 required Grafana dashboards exist with valid schema."""
    dashboards_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "deploy", "monitoring", "grafana", "dashboards")
    assert os.path.isdir(dashboards_dir)

    expected_dashboards = [
        "01-executive-overview.json",
        "02-application-health.json",
        "03-backend-api-performance.json",
        "04-ai-agent-monitoring.json",
        "05-crewai-langchain-monitoring.json",
        "06-automation-engine-monitoring.json",
        "07-cybersecurity-tool-health.json",
        "08-vulnerability-scan-monitoring.json",
        "09-database-monitoring.json",
        "10-system-resources.json",
        "11-network-monitoring.json",
        "12-docker-container-monitoring.json",
        "13-error-and-failure-monitoring.json",
        "14-cicd-pipeline-monitoring.json",
        "15-llm-usage-cost-monitoring.json"
    ]

    for fname in expected_dashboards:
        fpath = os.path.join(dashboards_dir, fname)
        assert os.path.isfile(fpath), f"Missing dashboard file: {fname}"
        with open(fpath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            assert "title" in data
            assert "panels" in data
            assert len(data["panels"]) > 0
            assert data["schemaVersion"] >= 36
