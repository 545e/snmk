# AI AGENT ARCHITECTURE & 85-SPECIALIST WORKFORCE

> **Audit corrections applied 2026-11-07 (read first), updated 2026-11-09 for the current tree:**
> - The Nov-08 commit `11f54d9` ("activate and wire all 85 agents… 100% execution pass rate") wired handlers for **every** tier. "Executed" now means: the dispatched unit of code ran and returned a dict — not that it performed deep analysis. Be precise:
>   - **Tier 1 (17)**: DB-summary generators (e.g., SupervisorAgent returns a static 19-step plan). Not LLM agents.
>   - **Tier 2 (9)**: real execution (recon/attack-surface/fuzzer/dep-confusion/vuln-hunter/exploit-validator/remediation) — 8s–90s timeouts, some against loopback or lab targets.
>   - **Tier 3 (10)**: real plugin probe (httpx) + optional LLM synthesis.
>   - **Tier 4 (32)**: generic import + instantiation; **many handlers return static capability dicts rather than computed results** (e.g. `knowledge_graph_engine` returns hardcoded `{"nodes": 150, "edges": 320}`; `cyber_deploy_engine` returns `deployment_stages: 15`; `multi_injection_suite` returns `injection_classes: 27`). These are plausibility stubs, not measurements. A few do real work (`scope_enforcement_policy` calls `validate_target` genuinely; `risk_scoring_engine` computes via `compute_posture_score` if present).
>   - **Tier 5 (17)**: tool inventory lookup — reports adapter status; does not run external binaries.
> - `test_all_85_agents` enshrines "85 COMPLETED" as the pass condition. It proves dispatch completeness, nothing more. Our original honest `NOT_EXECUTABLE` tier-4 reporting was replaced by these handlers in the same commit.
> - `execute_all_85_agents` is real (bounded parallel dispatch; see `core/agent_registry.py`); per-agent timeout is 120 s; overall status `COMPLETED`/`DEGRADED` reflects failures.
> - **No LLM round trip occurs without a configured provider key**; with placeholders the system is in `heuristic_fallback` mode.
> - Lifecycle vocabulary in code: `AVAILABLE/ACTIVE/RUNNING/COMPLETED/FAILED/REGISTERED/NOT_EXECUTABLE`. The diagram below is illustrative of design intent, not enforced end-to-end.
>

## SNMK / SWA Autonomous Multi-Agent Hierarchy

The platform registers, coordinates, and executes 85 specialist agents organized across five operational tiers.

### Operational Tiers

1. **Workforce Tier (17 Agents)**:
   - `SupervisorAgent`: Global multi-agent planning and workflow orchestration.
   - `AssetDiscoveryAgent`: Autonomous target perimeter mapping and host enumeration.
   - `PortScannerAgent`: Multi-protocol port prober and service banner grabber.
   - `WebCrawlerAgent`: Deep DOM explorer and parameter discovery prober.
   - `ApiInspectorAgent`: REST, GraphQL, and SOAP API schema extractor.
   - `CloudSecurityAuditorAgent`: AWS, Azure, GCP, and IMDSv1/v2 metadata auditor.
   - `IdentityAccessAuditorAgent`: OAuth, JWT, SAML, and session governance auditor.
   - `VulnHunterAgent`: Multi-vector vulnerability scanner and proof-of-concept synthesizer.
   - `ExploitValidatorAgent`: Non-destructive exploit validation and cURL PoC generation.
   - `ThreatIntelligenceAgent`: Threat actor tracking and MITRE ATT&CK mapping.
   - `RiskAnalyzerAgent`: Contextual CVSS v3.1 scoring and business impact analyst.
   - `RemediationPlannerAgent`: Code patch generator and WAF defense synthesizer.
   - `ReportGeneratorAgent`: Multi-format executive, SARIF, and PDF reporting.
   - `ComplianceAuditorAgent`: SOC 2, ISO 27001, HIPAA, and PCI-DSS compliance verifier.
   - `AttackSurfaceManagerAgent`: EASM drift analysis and shadow IT discovery.
   - `IncidentCorrelatorAgent`: Multi-stage Cyber Kill Chain correlation.
   - `SystemHealthMonitorAgent`: Platform diagnostic and integrity monitor.

2. **Offensive & Reconnaissance Tier (9 Agents)**:
   - Specialized agents for Subdomain Enumeration, DNS Intelligence, Directory Brute-Forcing, Header Auditing, SSL/TLS Cipher Analysis, Parameter Fuzzing, CORS Probing, and Open Redirect Detection.

3. **OWASP Top 10 Plugins Tier (10 Modernized v3.0.0 Agents)**:
   - `A01: Broken Access Control`: IDOR, path traversal, BOLA prober.
   - `A02: Cryptographic Failures`: Weak cipher, TLS 1.0/1.1, hardcoded key auditor.
   - `A03: Injection Prober`: SQLi, NoSQLi, Command Injection, LDAP, SpEL.
   - `A04: Insecure Design`: Business logic flaw and rate limiting auditor.
   - `A05: Security Misconfiguration`: CSP, HSTS, CORS, debug endpoints.
   - `A06: Vulnerable Components`: Third-party CVE and dependency auditor.
   - `A07: Auth & Session Failures`: Session fixation, cookie security, JWT flaws.
   - `A08: Software & Data Integrity`: Deserialization, SRI, supply chain tampering.
   - `A09: Logging & Monitoring`: Audit trail integrity, log injection.
   - `A10: SSRF & Cloud Metadata`: IMDSv1, internal loopback, webhook abuse.

4. **Core Engines Tier (32 Specialized Engines)**:
   - Dedicated algorithmic modules including SQLi Engine, WAF Bypass Engine, REA Engine, Knowledge Graph Engine, Risk Engine, Remediation Engine, and Forensics Engine.

5. **Tool Adapters Tier (17 Native Adapters)**:
   - Verified integration adapters interfacing internal and standard cybersecurity utilities (Nmap, Amass, Nuclei, Subfinder, Dirsearch, TestSSL, Wfuzz, SQLMap, etc.).

---

### Agent Lifecycle States

```text
[REGISTERED] ──► [INITIALIZING] ──► [READY] ──► [QUEUED] ──► [RUNNING]
                                                                │
     ┌──────────────────────┬───────────────────────────────────┤
     ▼                      ▼                                   ▼
[COMPLETED]        [WAITING_FOR_APPROVAL]              [TOOL_EXECUTION]
                            │                                   │
                            └───────────────► ◄─────────────────┘
```
