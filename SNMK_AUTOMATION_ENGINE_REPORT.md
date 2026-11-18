# SNMK Enterprise Automation Engine Architecture & Operations Report

**Component:** SNMK Autonomous Security Workflow & Job Scheduling Engine (`core/automation_engine.py`)  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Operational Mode:** Asyncio Event Loop + Persistent SQLite Job Store  
**Status:** **OPERATIONAL & HIGHLY RESILIENT**

---

## 1. Executive Summary

The SNMK Automation Engine powers autonomous cybersecurity workflows across the enterprise lifecycle, including automated attack surface discovery, recurring vulnerability scanning, multi-agent AI assessments, human-in-the-loop remediation approvals, and compliance report distribution.

During this engineering audit, the engine's execution lifecycle, job cancellation routines, thread safety, and persistence mechanisms were analyzed and reinforced.

---

## 2. Architecture & Workflow Model

```
+--------------------------------------------------------------------------------+
|                           SNMK AUTOMATION ENGINE                               |
|                                                                                |
|   +-----------------------+     +-----------------------+                      |
|   |   Workflow Schedule   |     |    API / Manual Run   |                      |
|   |  (Cron / Time Delay)  |     |   (POST /api/wf/run)  |                      |
|   +-----------+-----------+     +-----------+-----------+                      |
|               |                             |                                  |
|               +-------------->+<------------+                                  |
|                               |                                                |
|                               v                                                |
|                   +-----------------------+                                    |
|                   |  Execution Controller |                                    |
|                   | (UUID, State Machine) |                                    |
|                   +-----------+-----------+                                    |
|                               |                                                |
|       +-----------------------+-----------------------+                        |
|       |                       |                       |                        |
|       v                       v                       v                        |
| +------------+        +---------------+        +---------------+               |
| | Step 1:    |------->| Step 2:       |------->| Step 3:       |               |
| | Tool Exec  |        | Agent Dispatch|        | Remediation / |               |
| | (Amass/Nmap|        | (CrewAI/SWA)  |        | Approval Gate |               |
| +------------+        +---------------+        +---------------+               |
|                                                                                |
+--------------------------------------------------------------------------------+
```

### 2.1 Workflow Definition Schema
Workflows are defined with declarative steps containing:
- `step_id`: Unique identifier within the workflow.
- `step_type`: `tool` (security scanner), `agent` (specialist AI worker), `approval` (human-in-the-loop gate), `report` (report generator), or `remediation` (patch generation).
- `parameters`: Target domains, port ranges, tool flags, or agent configurations.
- `on_failure`: Configurable error handling policy (`ABORT`, `CONTINUE`, or `RETRY`).
- `timeout_sec`: Enforced maximum wall-clock execution time per step.

### 2.2 Execution Controller & State Machine
Every execution transitions through a well-defined state machine:
- `PENDING` -> `RUNNING` -> `COMPLETED` / `FAILED` / `CANCELLED` / `TIMED_OUT`
All state transitions are committed immediately to the SQLite database to withstand process restarts without data loss.

---

## 3. Key Enhancements Implemented in Audit

### 3.1 Deterministic Execution Cancellation (`cancel_execution`)
- **Problem:** Previously, in-flight workflow executions lacked a clean cancellation API. Terminating a parent scan left orphan subprocesses running in the background.
- **Solution:** Added `cancel_execution(exec_id: str)` to `core/automation_engine.py`. This method:
  1. Checks if the execution is currently in `RUNNING` or `PENDING` status.
  2. Updates database execution status to `CANCELLED` with a UTC timestamp.
  3. Signals running worker tasks to terminate and cleans up child PID references.

### 3.2 Scheduled Workflow Introspection (`get_scheduled_workflows`)
- Added `get_scheduled_workflows()` to allow the SOC dashboard, REST APIs, and CLI tools to inspect active recurring cron and interval schedules with next-run forecasts.

### 3.3 Scope & Permission Guardrails
- Before any workflow executes an active scanner tool step (such as Nmap or SQLMap), target parameters are passed through `core/scope_policy.py` to prevent unauthorized out-of-scope probes.

---

## 4. Multi-Agent Integration with Automation Workflows

The Automation Engine bridges traditional deterministic CLI tools with cognitive AI agents:
1. **Reconnaissance Stage:** Amass / Subfinder tools execute via `core/cyber_tools.py`.
2. **Analysis Stage:** Discovered targets and open ports are handed off to `core/crewai_adapter.py` agents.
3. **Reasoning & Triage:** `core/langchain_adapter.py` analyzes HTTP response headers, extracts findings, and verifies non-destructive attack vectors.
4. **Remediation Stage:** Remediation Engine generates code patches and WAF rules.
5. **Approval Stage:** The workflow pauses in `WAITING_APPROVAL` status until a SOC analyst approves or rejects the action via the REST API.

---

## 5. Reliability & Fault Tolerance Assessment

- **Database Concurrency:** Leverages SQLite WAL mode, preventing database lock contention during concurrent workflow step updates.
- **Resource Quotas:** Memory and CPU limits prevent individual runaway tools from degrading platform availability.
- **Zero Secret Exposure:** Workflow execution logs automatically mask API keys and credentials before writing to the database or serializing to REST endpoints.
