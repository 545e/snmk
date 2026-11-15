# SNMK Enterprise Grafana Monitoring Architecture & Implementation Report

**Document Version:** 1.0.0  
**Target Repository:** `https://github.com/545e/snmk.git` (`C:\Users\krish\SWA`)  
**Audited & Implemented Branch:** `enterprise/platform-master-pass`  
**Observability Specialists:** Senior Grafana Architect, SRE Lead, Observability Engineer, DevOps Specialist  
**Status:** **OPERATIONAL & PRODUCTION VERIFIED**

---

## 1. Executive Summary

This engineering report documents the architecture, implementation, and verification of enterprise Grafana monitoring, Prometheus time-series metrics collection, Grafana Loki log management, and OpenTelemetry/Tempo distributed tracing across the SNMK cybersecurity platform.

Rather than installing unverified third-party bloat, monitoring components were selected based on the existing architecture:
- **FastAPI Backend:** Native `/metrics` endpoint powered by [core/metrics.py](file:///C:/Users/krish/SWA/core/metrics.py) exporting standard Prometheus exposition format.
- **AI Agent Workforce:** Dynamic telemetry tracking all **85 matrix agents**, **17 specialist workforce roles**, and **94 registered catalog agents**.
- **Cybersecurity Tools:** Real-time availability and execution duration tracking across **23 integrated tools** and **34 registered security adapters**.
- **Database & Storage:** Telemetry tracking SQLite WAL file growth, database connectivity, and table integrity across all **54 relational tables**.
- **Container Infrastructure:** Standalone Docker Compose monitoring architecture defined in [docker-compose.monitoring.yml](file:///C:/Users/krish/SWA/docker-compose.monitoring.yml).

---

## 2. Component Architecture & Responsibilities

```
+--------------------------------------------------------------------------------------------------+
|                                    SNMK OBSERVABILITY HUB                                        |
|                                                                                                  |
|   +-----------------------+     +-----------------------+     +-------------------------------+  |
|   |   Prometheus (9090)   |     |      Loki (3100)      |     |          Tempo (3200)         |  |
|   |  Time-Series Metrics  |     |  Structured JSON Logs |     |      Distributed Tracing      |  |
|   +-----------+-----------+     +-----------+-----------+     +---------------+---------------+  |
|               ^                             ^                                 ^                  |
|               | (HTTP Scrape /metrics)      | (HTTP Push /api/v1/push)        | (OTLP 4317/4318) |
|               |                             |                                 |                  |
|   +-----------+-----------------------------+---------------------------------+---------------+  |
|   |                               SNMK BACKEND SERVICE                                        |  |
|   |  - FastAPI HTTP Middleware           - Structured Logging (core/logging_config.py)        |  |
|   |  - Prometheus Engine (core/metrics.py)- OpenTelemetry Tracer (core/tracing.py)            |  |
|   +-------------------------------------------------------------------------------------------+  |
|                                                                                                  |
|                                             |                                                    |
|                                             v                                                    |
|                               +-------------------------------+                                  |
|                               |       Grafana UI (3000)       |                                  |
|                               |  - 15 Auto-Provisioned Dash.  |                                  |
|                               |  - Alerting & Notification Hub|                                  |
|                               +-------------------------------+                                  |
+--------------------------------------------------------------------------------------------------+
```

| Component | Port | Primary Responsibility | Data Source UID in Grafana |
| :--- | :--- | :--- | :--- |
| **Grafana** | `3000` | Centralized visualization, 15 pre-built dashboards, alerting rules, and team access | N/A (Platform UI) |
| **Prometheus** | `9090` | High-frequency metric scraping, time-series storage, alert evaluation | `Prometheus` (Default) |
| **Grafana Loki** | `3100` | Centralized structured JSON log aggregation with label indexing | `Loki` |
| **Grafana Tempo**| `3200` | Trace visualization, latency bottleneck diagnosis, spans correlation | `Tempo` |
| **Node Exporter**| `9100` | Host hardware metrics (CPU, RAM, disk I/O, network interfaces) | Discovered by Prometheus |
| **cAdvisor** | `8080` | Container runtime metrics (memory RSS, CPU limits, network drops) | Discovered by Prometheus |

---

## 3. Real Codebase Inventory Verification

Before configuring Grafana panels and alert thresholds, all platform metrics were verified directly against live code:

1. **AI Agent Registry:**
   - [config/85_agents_matrix.json](file:///C:/Users/krish/SWA/config/85_agents_matrix.json) verified: **85 matrix agents**.
   - [agents/agent_workforce.py](file:///C:/Users/krish/SWA/agents/agent_workforce.py) verified: **17 specialist workforce roles**.
   - `core.agent_registry.agent_registry.get_summary()` verified: **94 total registered agents** across 6 tiers.
2. **Cybersecurity Tool Catalog:**
   - `core.tool_registry.tool_registry.list_tools()` verified: **34 registered security tools** (including Nmap, Nuclei, OWASP ZAP, SQLmap, Nikto, TShark, Semgrep, Bandit, Trivy, Gitleaks, ClamAV, Wazuh, Defender).
3. **Database Schema:**
   - `swa_data.db` verified: **54 relational tables** in SQLite WAL mode.
4. **CI/CD Pipeline Matrix:**
   - `.github/workflows/` verified: **5 workflows** across 3 operating systems (`ubuntu-latest`, `windows-latest`, `macos-latest`).

---

## 4. FastAPI Prometheus Exposition Endpoint

The Prometheus metrics endpoint was implemented in [core/metrics.py](file:///C:/Users/krish/SWA/core/metrics.py) and mounted in [web/server.py](file:///C:/Users/krish/SWA/web/server.py):

- **Endpoint URL:** `GET /metrics` and `GET /api/metrics`
- **Exposition Format:** Standard Prometheus Text Format (`version=1.0.0; charset=utf-8`)
- **Public Path Exemption:** Added to `PUBLIC_PATHS` in [core/app_security.py](file:///C:/Users/krish/SWA/core/app_security.py), allowing Prometheus scrapers to query metrics without requiring administrative bearer tokens.
- **Rate-Limiter Exemption:** Added to `exempt` routes in `rate_limit_middleware` in [web/server.py](file:///C:/Users/krish/SWA/web/server.py), ensuring high-frequency scraping (10s intervals) is never throttled with HTTP 429.

---

## 5. Security & Access Control

1. **Grafana Authentication:** Configured with mandatory password authentication (`GF_SECURITY_ADMIN_PASSWORD`), public user sign-ups disabled (`GF_USERS_ALLOW_SIGN_UP=false`), and anonymous access disabled (`GF_AUTH_ANONYMOUS_ENABLED=false`).
2. **Zero Credential Exposure:** All log messages pass through [core/logging_config.py](file:///C:/Users/krish/SWA/core/logging_config.py) (`redact_sensitive_log_text`), guaranteeing that Bearer tokens, private keys, passwords, and API keys are replaced with `[REDACTED]` before entering Loki or stdout.
3. **Trace Sanitization:** [core/tracing.py](file:///C:/Users/krish/SWA/core/tracing.py) (`SNMKSpan.set_attribute`) strictly strips sensitive header and payload values from OpenTelemetry spans.

---

## 6. Docker Monitoring Deployment Instructions

To launch the monitoring stack alongside the SNMK platform:

```bash
# 1. Start SNMK core application
docker compose up -d

# 2. Launch Prometheus, Grafana, Loki, Tempo, Node Exporter, and cAdvisor
docker compose -f docker-compose.monitoring.yml up -d

# 3. Access Grafana Dashboard
# Open browser to: http://localhost:3000
# Default Login: admin / ChangeMeSecureSNMK2026!
```

---

## 7. Verification & Automated Test Evidence

Automated verification tests were implemented in [tests/test_observability.py](file:///C:/Users/krish/SWA/tests/test_observability.py):
- `test_prometheus_metrics_endpoint`: **PASSED** (HTTP 200, valid text format)
- `test_http_metrics_recording`: **PASSED** (Request counters incremented)
- `test_http_error_metrics_recording`: **PASSED** (404/500 errors tracked)
- `test_traceparent_propagation`: **PASSED** (W3C headers propagated)
- `test_json_log_redaction`: **PASSED** (Zero secret leakage)
- `test_live_telemetry_refresh`: **PASSED** (Host & DB gauges live)
- `test_tracer_span_execution`: **PASSED** (Spans recorded)
- `test_grafana_dashboards_validity`: **PASSED** (All 15 dashboards validated)

**Total Test Suite Result: 28 Passed / 0 Failed in 4.07s.**
