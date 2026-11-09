# MULTI-AGENT WORKFLOWS & THREAT ORCHESTRATION

> **Audit corrections applied 2026-11-07 (read first):**
> - The diagram below is the **intended** pipeline. In code, the real loop is: `POST /api/scans` → `SWAOrchestrator.execute()` (ReconAgent → AttackSurfaceAgent → optional FuzzerAgent → plugin_manager/VulnHunter fan-out → optional Nuclei (if binary installed) → ExploitValidatorAgent (httpx re-probe + optional LLM) → RemediationAgent) → knowledge-graph ingest → EASM drift → report generation.
> - `/api/agents/collaborate` now runs a **real bounded pipeline**: Stage 1 attack-surface dispatch, Stage 2 dependency-confusion dispatch, Stage 3 deterministic posture scoring from stored findings, Stage 4 exploit-validation dispatch, Stage 5 remediation dispatch, Stage 6 report generation explicitly `NOT_RUN`. Each stage reports its true status (`COMPLETED`, `FAILED`, `NOT_EXECUTABLE`, `NOT_RUN`); overall status is `COMPLETED`, `DEGRADED`, or `NOT_COMPLETED` accordingly.
> - Claims like "delegation depth bounded to 5 handoffs" were never enforced in code and are retained below only as design intent. Actual bounds: orchestrator pipeline is linear; `execute_all_85_agents` uses a semaphore of 4 and a 60-second per-agent timeout; LLM `reason()` uses bounded history (last 8 messages).
> - Approval gates are enforced only in the automation engine for non-lab targets (`requires_approval` steps pause as `PENDING_APPROVAL`); the agent-dispatch path itself does not yet flip agents into `WAITING_FOR_APPROVAL`.

## End-to-End Task Delegation, Context Passing, and Kill Chain Correlation

### 1. The Standard Security Assessment Workflow

```text
[Step 1: Scoped Reconnaissance]
  AssetDiscoveryAgent ──► Subdomain & DNS enumeration
          │
          ▼
[Step 2: Service & Perimeter Probing]
  PortScannerAgent & WebCrawlerAgent ──► Open ports, endpoints, technologies
          │
          ▼
[Step 3: Multi-Vector Vulnerability Analysis]
  VulnHunterAgent & OWASP Agents ──► Injection, auth, and configuration checks
          │
          ▼
[Step 4: Non-Destructive Exploit Validation]
  ExploitValidatorAgent ──► Generates minimal cURL reproduction PoC
          │
          ▼
[Step 5: Threat Correlation & Risk Analysis]
  IncidentCorrelatorAgent ──► Maps findings into 7-stage Cyber Kill Chain
  RiskAnalyzerAgent       ──► Calculates contextual CVSS v3.1 score
          │
          ▼
[Step 6: Defensive Remediation Planning]
  RemediationPlannerAgent ──► Synthesizes code fixes and WAF blocking rules
          │
          ▼
[Step 7: Reporting & Export]
  ReportGeneratorAgent    ──► Compiles executive PDF, HTML, SARIF, and Nessus XML
```

---

### 2. Guardrails Against Runaway Execution
- **Infinite Loop Prevention**: Task delegation depth is bounded to a maximum of 5 recursive handoffs.
- **Human Approval Gates**: High-impact operations (e.g. active exploitation or destructive probes) transition agent state to `WAITING_FOR_APPROVAL` until approved via the Approval Gates UI.
- **Unified Context Object**: Each agent receives a validated `ScanJob` and passes structured `VulnerabilityFinding` instances to downstream workers.
