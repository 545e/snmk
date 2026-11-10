# MULTI-AGENT WORKFLOWS & THREAT ORCHESTRATION

> **AUDIT CORRECTION — 2026-11-11 (read first):** a concurrent `51116f4` bulk sync reverted the 2026-11-07 corrections to this document. This file still describes aspirational/design-intent behavior in places, NOT verified reality. Verified fact:
> - No LLM round trip is verified anywhere (all providers `NOT_CONFIGURED`; mode = `heuristic_fallback`).
> - RAG is BM25 (sparse), NOT embeddings/vector search. Memory is regex-scrubbed, not guaranteed.
> - Tool execution is deterministic adapters; LLM function/tool calling does not exist.
> - `ai_training.py` is a simulation; tier-4 agents return static dicts; 85/85 dispatch != capability.
> - `SWA_ENFORCE_ALLOWLIST=1` disables dynamic session authorization; `SWA_AUTH_ENABLED=true` (or a real `SWA_API_KEY`) gates `/api/*`.
> - The 12-vector LLM harness is deterministic rules, not a live red-teamer.
> - CISA KEV/EPSS endpoints hit live feeds (1h cache); 503 on failure.
> See `docs/IMPLEMENTATION_REPORT.md` (addendum), `docs/TESTING_AND_VERIFICATION.md`, `docs/COMPLETE_AI_SYSTEM_INVENTORY.md`.

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
