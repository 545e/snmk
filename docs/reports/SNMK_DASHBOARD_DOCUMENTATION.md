# SNMK Enterprise Grafana Dashboard Reference Documentation

**Component:** Provisioned Grafana Dashboards & Visualizations  
**Provisioning Path:** [deploy/monitoring/grafana/provisioning/dashboards/](file:///C:/Users/krish/SWA/deploy/monitoring/grafana/provisioning/dashboards/)  
**Dashboard Files:** [deploy/monitoring/grafana/dashboards/](file:///C:/Users/krish/SWA/deploy/monitoring/grafana/dashboards/)  
**Total Dashboards:** 15 Automated Dashboards  
**Status:** **PROVISIONED & PRODUCTION READY**

---

## 1. Overview & Provisioning Architecture

SNMK includes 15 pre-configured, production-grade Grafana dashboards. Dashboards are managed declaratively using Grafana's file-based provisioning engine, eliminating manual GUI imports and ensuring consistent deployments across environments.

When Grafana starts up, `dashboards.yml` reads from `/etc/grafana/provisioning/dashboards/json` and automatically registers all 15 dashboards under the folder **`SNMK Observability`**.

---

## 2. Inventory of the 15 Provisioned Dashboards

```
deploy/monitoring/grafana/dashboards/
├── 01-executive-overview.json             # High-level CISO / Executive health KPIs
├── 02-application-health.json             # FastAPI uptime, memory RSS, in-flight requests
├── 03-backend-api-performance.json        # RPS, latency distributions (P50/P95), error rates
├── 04-ai-agent-monitoring.json            # 85 matrix agents, 17 roles, active vs idle pool
├── 05-crewai-langchain-monitoring.json    # CrewAI tasks, LangChain latency, tokens consumed
├── 06-automation-engine-monitoring.json   # Queue depth, workflow completions, scheduled cron
├── 07-cybersecurity-tool-health.json      # 23 tools / 34 adapters availability & duration
├── 08-vulnerability-scan-monitoring.json # Findings by severity, scan initiation, failure rate
├── 09-database-monitoring.json            # SQLite DB size, WAL file activity, 54 tables
├── 10-system-resources.json               # Host CPU %, RAM %, Disk space %, Disk free bytes
├── 11-network-monitoring.json             # Inbound HTTP traffic rate, active socket connections
├── 12-docker-container-monitoring.json    # Container CPU, container memory RSS, uptime
├── 13-error-and-failure-monitoring.json   # 5xx server errors, 4xx errors, tool/agent failures
├── 14-cicd-pipeline-monitoring.json       # GitHub Actions 3-OS matrix, test pass rate
└── 15-llm-usage-cost-monitoring.json      # LLM token consumption by model, provider status
```

---

## 3. Detailed Dashboard Specifications

### Dashboard 1: SNMK Executive Overview (`01-executive-overview.json`)
- **Audience:** CISO, Engineering Directors, SOC Leads.
- **Key Panels:**
  - `Platform Uptime`: Single stat showing continuous uptime in seconds (`snmk_app_uptime_seconds`).
  - `Registered AI Agents`: Total agents in catalog (`snmk_ai_agents_registered_total` = 94).
  - `Security Tools Active`: Count of online tools (`snmk_security_tools_registered_total` = 34).
  - `Database Status`: Persistence indicator (1 = Healthy).
  - `Total Requests (1h)`: Hourly throughput counter.
  - `Critical Findings`: Count of active critical vulnerabilities (`snmk_findings_total{severity="CRITICAL"}`).
  - `Request Rate by Endpoint`: Timeseries showing traffic distribution.
  - `System Resource Usage`: Real-time CPU and memory curves.

### Dashboard 2: Application Health (`02-application-health.json`)
- **Key Panels:**
  - `Active In-Flight Requests`: Gauge showing current concurrency (`snmk_http_active_requests`).
  - `Process RSS Memory`: Backend memory consumption in bytes (`snmk_process_memory_bytes`).
  - `HTTP Status Code Distribution`: Timeseries showing 2xx, 3xx, 4xx, and 5xx responses.
  - `API Latency Distribution (P95)`: Percentile response times in seconds.

### Dashboard 3: Backend API Performance (`03-backend-api-performance.json`)
- **Key Panels:**
  - `Requests Per Second`: Aggregate RPS across all API routes.
  - `Top Latency Endpoints (P90)`: Slowest endpoints ranked by response duration.
  - `API Error Rate (5xx/4xx)`: HTTP failures categorized by endpoint and status code.

### Dashboard 4: AI Agent Monitoring (`04-ai-agent-monitoring.json`)
- **Key Panels:**
  - `Total Registered Agents`: 85 matrix + specialist agents (94 total).
  - `Specialist Roles Count`: 17 workforce roles.
  - `Active Working Agents`: Count of agents currently executing tasks.
  - `Idle Agents Standing By`: Available worker pool.
  - `Agent Task Execution Rate`: Operations per second broken down by `agent_role`.
  - `Agent Task Latency (P90)`: Execution duration per specialist role.

### Dashboard 5: CrewAI and LangChain Monitoring (`05-crewai-langchain-monitoring.json`)
- **Key Panels:**
  - `CrewAI Total Executions`: Cumulative multi-agent crew kickoff runs.
  - `LangChain Total Requests`: Pipeline and prompt template executions.
  - `LLM Providers Online`: Count of active upstream providers (Gemini, OpenAI, Anthropic, Ollama).
  - `Total Tokens Consumed`: Estimated LLM token volume.
  - `CrewAI Workflow Latency`: P95 multi-agent crew execution duration.
  - `LangChain RAG Pipeline Latency`: P95 vector and knowledge retrieval latency.

### Dashboard 6: Automation Engine Monitoring (`06-automation-engine-monitoring.json`)
- **Key Panels:**
  - `Queue Depth`: Current queue backlog (`snmk_automation_queue_depth`).
  - `Scheduled Workflows`: Active recurring jobs (`snmk_automation_scheduled_workflows`).
  - `Completed Jobs (1h)`: Hourly workflow completions.
  - `Workflow Execution Rate by Status`: Timeseries tracking `COMPLETED`, `FAILED`, and `CANCELLED`.
  - `Workflow Duration Distribution`: P95 duration of automated jobs.

### Dashboard 7: Cybersecurity Tool Health (`07-cybersecurity-tool-health.json`)
- **Key Panels:**
  - `Total Registered Tools`: 34 security tools and adapters.
  - `Tools Available`: Count of tools verified on the system.
  - `Tool Execution Invocations by Tool ID`: Timeseries tracking calls to Nmap, Nuclei, FFUF, SQLMap, etc.
  - `Tool Execution Duration (P90)`: Execution time per security scanner.

### Dashboard 8: Vulnerability Scan Monitoring (`08-vulnerability-scan-monitoring.json`)
- **Key Panels:**
  - `Vulnerability Finding Stat Cards`: 5 distinct panels for Critical, High, Medium, Low, and Informational.
  - `Failed Scans Total`: Counter tracking aborted or errored scans.
  - `Vulnerability Findings Trend by Severity`: Historical finding accumulation curves.
  - `Scan Initiation Rate by Profile`: Scans grouped by profile (Quick, Full, WebSec, Recon).

### Dashboard 9: Database Monitoring (`09-database-monitoring.json`)
- **Key Panels:**
  - `Database Status`: Persistence availability indicator.
  - `Relational Tables Count`: 54 verified tables.
  - `Database File Size`: Growth curve of `swa_data.db`.
  - `Write-Ahead Log (WAL) Size`: Bytes in `swa_data.db-wal` to detect uncheckpointed transactions.

### Dashboard 10: System Resource Monitoring (`10-system-resources.json`)
- **Key Panels:**
  - `Host CPU Utilization`: Real-time percentage gauge with 80% warning threshold.
  - `Host RAM Utilization`: Physical memory usage percentage.
  - `Disk Space Utilization`: Root volume storage percentage.
  - `Free Storage Available`: Free bytes on the primary volume.

### Dashboard 11: Network Monitoring (`11-network-monitoring.json`)
- **Key Panels:**
  - `Inbound HTTP Request Traffic`: Request throughput over time.
  - `Network Errors and Timeouts`: Connection drops and client disconnects.
  - `Active Socket Connections`: Real-time concurrent socket pool.

### Dashboard 12: Docker Container Monitoring (`12-docker-container-monitoring.json`)
- **Key Panels:**
  - `Container Backend RSS Memory`: Memory allocation within the container.
  - `Container CPU Load`: Process CPU percentage inside the Docker cgroup.
  - `Uptime in Container`: Uptime counter in seconds.

### Dashboard 13: Error and Failure Monitoring (`13-error-and-failure-monitoring.json`)
- **Key Panels:**
  - `HTTP 5xx Server Errors (1h)`: Hourly server exception count.
  - `HTTP 4xx Client Errors (1h)`: Hourly client-side request failure count.
  - `AI Agent Failures (1h)`: Hourly agent task failures.
  - `Tool Failures (1h)`: Hourly tool exit errors.
  - `Error Rate by Endpoint`: Timeseries showing specific failing routes.

### Dashboard 14: CI/CD Pipeline Monitoring (`14-cicd-pipeline-monitoring.json`)
- **Key Panels:**
  - `CI Test Suite Pass Rate`: Gauge reflecting 100% test pass status.
  - `Matrix Target OS Count`: 3 target platforms (Ubuntu, Windows, macOS).
  - `Workflow Automation Matrix`: 5 active GitHub Actions workflows.
  - `Pipeline Health Status`: Continuous build and service stability indicator.

### Dashboard 15: LLM Usage and Cost Monitoring (`15-llm-usage-cost-monitoring.json`)
- **Key Panels:**
  - `Total Tokens Consumed`: Aggregate prompt and completion token counts.
  - `LLM Upstream Errors (1h)`: Rate limit or timeout occurrences.
  - `Providers Configured`: Online provider count.
  - `Token Consumption by Model`: Timeseries showing usage across Gemini, Claude, GPT, and local models.

---

## 4. Operator Navigation & Maintenance

1. **Accessing Dashboards:** Navigate to `http://localhost:3000/dashboards` and expand the **SNMK Observability** folder.
2. **Auto-Refresh:** All dashboards are provisioned with a default 10-second auto-refresh interval (`refresh: "10s"`).
3. **Time Window Selection:** Default time range is `now-1h` to `now`. Operators can adjust the range to `now-24h` or `now-7d` for historical trend analysis.
