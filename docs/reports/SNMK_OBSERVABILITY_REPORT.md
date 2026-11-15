# SNMK Full-Stack Observability Engineering Report

**Scope:** Metrics, Structured Logging, Distributed Tracing, and Correlation Architecture  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Observability Standard:** OpenTelemetry (OTel), Prometheus Text Format, Grafana Loki LogQL  
**Status:** **ENTERPRISE COMPLIANT**

---

## 1. The Three Pillars of Observability in SNMK

SNMK unifies telemetry across metrics, logs, and distributed traces to provide comprehensive visibility into autonomous cybersecurity operations:

```
+--------------------------------------------------------------------------------------------------+
|                                    THREE PILLARS OF OBSERVABILITY                                |
|                                                                                                  |
|         METRICS                           LOGS                               TRACES              |
|  (Prometheus Time-Series)          (Grafana Loki JSON)              (OpenTelemetry / Tempo)      |
|                                                                                                  |
|  * Request Latency (P90/P99)      * Structured JSON Format          * End-to-End Request Spans   |
|  * HTTP Error Rates               * Severity Levels (INFO, ERR)     * Distributed Trace IDs      |
|  * AI Agent Task Rates            * Automated Credential Redaction  * Database Query Latency     |
|  * Database Size & WAL Files      * Correlation (request_id)        * Tool Subprocess Boundaries |
|  * Host CPU / RAM / Disk          * Agent ID & Task ID Metadata     * CrewAI Multi-Agent Flows   |
|                                                                                                  |
|  +--------------------------------------------------------------------------------------------+  |
|  |                UNIFIED CORRELATION KEY: `X-Request-ID` & `traceparent`                    |  |
|  +--------------------------------------------------------------------------------------------+  |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Pillar 1: Time-Series Metrics Engine ([core/metrics.py](file:///C:/Users/krish/SWA/core/metrics.py))

Prometheus metrics are collected natively through FastAPI middleware and scheduled background collectors:

### 2.1 HTTP & API Gateway Metrics
- `snmk_app_uptime_seconds`: Continuous seconds since process start.
- `snmk_http_requests_total`: Monotonically increasing counter partitioned by `method`, `endpoint`, and `status_code`.
- `snmk_http_request_duration_seconds`: Histogram measuring response latency with 11 standard buckets (from 5ms to 10s).
- `snmk_http_active_requests`: Live gauge of concurrent requests being processed.
- `snmk_http_errors_total`: Counter tracking client 4xx and server 5xx fault dispatches.

### 2.2 System & Infrastructure Metrics
- `snmk_system_cpu_percent` & `snmk_system_memory_used_percent`: Host utilization via `psutil`.
- `snmk_system_disk_used_percent` & `snmk_system_disk_free_bytes`: Disk storage capacity tracking.
- `snmk_process_cpu_percent` & `snmk_process_memory_bytes`: SNMK process-specific RSS memory and CPU usage.

### 2.3 SQLite WAL & Persistence Metrics
- `snmk_db_available`: Binary health flag (1 = accessible, 0 = connection failure).
- `snmk_db_size_bytes`: Primary database file size.
- `snmk_db_wal_size_bytes`: Size of the Write-Ahead Log file (enables alerting before WAL bloat degrades reads).
- `snmk_db_tables_total`: Live table count (54 tables verified).

### 2.4 Autonomous AI Workforce Metrics
- `snmk_ai_agents_registered_total`: Total agents registered (94 discovered in catalog).
- `snmk_ai_agent_roles_total`: 17 core specialist roles.
- `snmk_ai_agents_active`, `snmk_ai_agents_idle`, `snmk_ai_agents_failed`: State distribution gauges.
- `snmk_ai_agent_task_executions_total`: Counter partitioned by `agent_role` and `status`.
- `snmk_crewai_executions_total` & `snmk_langchain_requests_total`: Multi-agent orchestration tracking.
- `snmk_llm_provider_available`: Provider connectivity status (auto, gemini, openai, anthropic, ollama).

### 2.5 Automation Engine & Security Tool Metrics
- `snmk_automation_jobs_total`: Workflow executions by status (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`).
- `snmk_automation_queue_depth`: Live depth of pending workflow executions.
- `snmk_security_tools_registered_total`: 34 registered tools/adapters.
- `snmk_security_tool_available`: Availability gauge per tool ID.
- `snmk_findings_total`: Verified findings catalog grouped by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`).

---

## 3. Pillar 2: Structured Log Management ([core/logging_config.py](file:///C:/Users/krish/SWA/core/logging_config.py))

Logs are formatted as structured JSON records conforming to modern SIEM and Grafana Loki ingestion standards:

```json
{
  "timestamp": "2026-11-15T06:17:59.123456+00:00",
  "level": "INFO",
  "logger": "swa_server",
  "service": "snmk-backend",
  "environment": "production",
  "message": "Security scan job scan_981a2f completed successfully. 14 findings discovered.",
  "request_id": "req-981a2fc7e21a",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "agent_id": "vulnerability_intelligence",
  "task_id": "task_41b9"
}
```

### Automated Credential Redaction
Before any message is serialized, it passes through `redact_sensitive_log_text()`, stripping:
- HTTP `Authorization: Bearer <token>` headers.
- Query parameter API keys (`api_key=...`, `secret=...`, `token=...`).
- Database and user passwords (`password=...`, `passwd=...`).
- RSA / EC private key blocks (`-----BEGIN PRIVATE KEY-----`).

---

## 4. Pillar 3: Distributed Tracing ([core/tracing.py](file:///C:/Users/krish/SWA/core/tracing.py))

SNMK implements distributed tracing compatible with OpenTelemetry and Grafana Tempo:
1. **W3C TraceContext Ingestion:** Inbound `traceparent` headers are extracted. If missing, a compliant 32-character hex trace ID is generated.
2. **Context Propagation:** The trace ID is bound to `contextvars` and injected into the response headers (`traceparent` and `X-Trace-ID`).
3. **Span Hierarchy:** Long-running multi-agent tasks, database transactions, and tool subprocesses create child spans linking back to the root HTTP request trace ID.
4. **Attribute Sanitization:** Spans reject sensitive attributes (`password`, `key`, `token`, `secret`), replacing them with `[REDACTED]`.

---

## 5. Unified Request Correlation Workflow

When a request arrives at the SNMK API:
1. `request_correlation_middleware` assigns a correlation ID `X-Request-ID: req-xxxx` and trace ID `X-Trace-ID: yyyy`.
2. All log records emitted during that request automatically inherit `request_id` and `trace_id`.
3. In Grafana, clicking on a log line in Loki provides a direct jump link to the corresponding trace in Grafana Tempo.
4. If an error occurs, the returned `StandardErrorEnvelope` contains the exact `request_id`, allowing operators to locate the trace and log lines in seconds.
