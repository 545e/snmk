# SNMK Enterprise Alerting & Notification Policy Report

**Component:** Intelligent Alerting & SLA Violation Detection Engine  
**Configuration File:** [deploy/monitoring/prometheus/alert_rules.yml](file:///C:/Users/krish/SWA/deploy/monitoring/prometheus/alert_rules.yml)  
**Standard:** Google SRE Alerting Best Practices & Prometheus Alerting Rules v2  
**Status:** **ACTIVE & PROVISIONED**

---

## 1. Alerting Strategy & Philosophy

SNMK's alerting architecture is designed around high-signal, actionable notifications that prioritize user impact over raw system noise. To eliminate alert fatigue and flapping:
- **Duration Windows (`for:` clauses):** Every alert requires sustained violation (from 15s to 5m) before triggering notifications, filtering out transient spikes.
- **Symptom-Based Thresholds:** Alerts target degraded end-user experience (e.g., error rate > 5%, latency > 500ms) rather than arbitrary internal metrics.
- **Tiered Severity:** Incidents are partitioned into `critical` (immediate page required) and `warning` (business hours triage).

---

## 2. Configured Prometheus Alert Rules Inventory

| Alert Name | Severity | Condition / PromQL Expression | Duration (`for`) | Operational Action |
| :--- | :--- | :--- | :--- | :--- |
| **`SNMKApplicationDown`** | `critical` | `up{job="snmk-platform"} == 0` | 30s | Restart backend service; inspect container logs for OOM or fatal startup crashes. |
| **`SNMKHighApiErrorRate`** | `critical` | `(rate(errors[2m]) / rate(requests[2m])) * 100 > 5` | 2m | Inspect Loki logs for 500 status codes; review recent code commits or bad payloads. |
| **`SNMKHighApiLatency`** | `warning` | `histogram_quantile(0.95, rate(duration[2m])) > 0.5` | 2m | Inspect slow database queries or slow upstream security tool dispatches. |
| **`SNMKHighCpuUtilization`** | `warning` | `snmk_system_cpu_percent > 85` | 3m | Identify runaway tool subprocesses (e.g., Masscan/FFUF threads) or worker loops. |
| **`SNMKHighMemoryUtilization`** | `warning` | `snmk_system_memory_used_percent > 85` | 3m | Inspect process RSS; trigger garbage collection or scale container memory reservation. |
| **`SNMKLowDiskSpace`** | `critical` | `snmk_system_disk_used_percent > 85` | 2m | Purge aged report artifacts, rotate container logs, or expand storage volume. |
| **`SNMKDatabaseUnavailable`** | `critical` | `snmk_db_available == 0` | 15s | Check filesystem permissions on `swa_data.db`; verify lock file contention. |
| **`SNMKDatabaseWalBloat`** | `warning` | `snmk_db_wal_size_bytes > 268435456` (256MB) | 5m | Execute manual WAL checkpoint (`PRAGMA wal_checkpoint(TRUNCATE);`). |
| **`SNMKAutomationQueueBacklog`** | `warning` | `snmk_automation_queue_depth > 50` | 3m | Scale worker concurrency; check if in-flight jobs are stuck on slow network tools. |
| **`SNMKAutomationFailures`** | `critical` | `increase(snmk_automation_jobs_total{status="FAILED"}[5m]) > 5` | 1m | Review workflow parameters; verify scan target reachability and scope policies. |
| **`SNMKAgentExecutionFailure`** | `warning` | `increase(snmk_ai_agent_task_executions_total{status="FAILED"}[5m]) > 3` | 1m | Check LLM provider rate limits or malformed agent prompt outputs. |
| **`SNMKLLMProviderDown`** | `warning` | `snmk_llm_provider_available == 0` | 2m | Verify provider API keys, credit balance, and upstream status pages. |
| **`SNMKSecurityToolFailure`** | `warning` | `increase(snmk_security_tool_executions_total{status="FAILED"}[5m]) > 3` | 1m | Verify tool binary installation in host PATH or inspect subprocess stderr output. |

---

## 3. Severity Tiers & Response Expectations

### Tier 1: Critical (`severity: critical`)
- **Target SLA:** Response within 15 minutes.
- **Routing:** Triggers high-priority notifications (PagerDuty, Opsgenie, or emergency Slack webhook).
- **Triggers:** Platform down, database offline, API error rate > 5%, or disk space exhaustion.

### Tier 2: Warning (`severity: warning`)
- **Target SLA:** Triage within 4 hours.
- **Routing:** Standard engineering Slack/Discord channel or ticketing system.
- **Triggers:** High latency, memory usage > 85%, SQLite WAL bloat, single agent failures, or upstream LLM provider degradation.

---

## 4. Notification Integration Paths

Prometheus alert rules evaluate against Prometheus server and dispatch through Alertmanager:

```yaml
# deploy/monitoring/prometheus/alertmanager.yml (Example Integration)
route:
  group_by: ['alertname', 'tier']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'slack-security-ops'
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty-critical'

receivers:
  - name: 'slack-security-ops'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#snmk-soc-alerts'
        send_resolved: true

  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_INTEGRATION_KEY'
```

---

## 5. Verification & Syntax Validation

The alert rule definitions in [deploy/monitoring/prometheus/alert_rules.yml](file:///C:/Users/krish/SWA/deploy/monitoring/prometheus/alert_rules.yml) were verified against Prometheus YAML schema standards:
- All 13 alert rules contain valid PromQL expressions referencing verified live metrics.
- Annotations and labels conform to Prometheus v2 specifications.
- Units and formatting strings (`{{ $value | humanize1024 }}`) adhere to Go template formatting.
