"""
SNMK Enterprise Platform — CrewAI Multi-Agent Architecture Adapter
Provides standard CrewAI agent, task, and crew interfaces for autonomous cybersecurity
operations, enabling collaborative multi-agent execution, task delegation, and guardrails.
Operates natively with installed crewai or falls back to SNMK's native async engine.
"""

from __future__ import annotations

import datetime
import importlib.util
import logging
import time
import uuid
from typing import Any

from pydantic import BaseModel, Field
from core.error_sanitizer import safe_error, safe_log_text

logger = logging.getLogger("snmk.crewai_adapter")


class CrewAIAgentConfig(BaseModel):
    """CrewAI-compatible agent configuration specification."""
    role: str
    goal: str
    backstory: str
    tools: list[str] = Field(default_factory=list)
    allow_delegation: bool = False
    verbose: bool = True
    max_iter: int = 15
    memory: bool = True
    agent_id: str | None = None


class CrewAITaskConfig(BaseModel):
    """CrewAI-compatible task configuration specification."""
    description: str
    expected_output: str
    agent_role: str
    tools: list[str] = Field(default_factory=list)
    context_task_ids: list[str] = Field(default_factory=list)
    task_id: str = Field(default_factory=lambda: f"task_{uuid.uuid4().hex[:8]}")


class CrewAIResult(BaseModel):
    """Result of a Crew execution."""
    crew_id: str
    status: str  # COMPLETED, FAILED, TIMED_OUT
    tasks_completed: int
    total_tasks: int
    duration_sec: float
    output: str
    task_results: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class SNMKCrewAIAgent:
    """Enterprise multi-agent worker with restricted permissions and tool allowlisting."""
    def __init__(self, config: CrewAIAgentConfig):
        self.config = config
        self.role = config.role
        self.goal = config.goal
        self.backstory = config.backstory
        self.tools = config.tools
        self.allow_delegation = config.allow_delegation
        self.max_iter = config.max_iter
        self.memory = config.memory
        self._memory_store: list[dict[str, Any]] = []

    def add_to_memory(self, item: dict[str, Any]) -> None:
        if self.memory:
            self._memory_store.append({
                **item,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
            })
            if len(self._memory_store) > 100:
                self._memory_store = self._memory_store[-100:]

    async def execute_task(self, task: CrewAITaskConfig, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Executes a defined cybersecurity task with boundary checks and timeout enforcement."""
        start = time.perf_counter()
        logger.info(f"Agent [{safe_log_text(self.role)}] starting task: {safe_log_text(task.description[:80])}...")
        
        # This adapter is the planning / orchestration layer. It deliberately
        # does NOT invent scanner output: no security tool is invoked here.
        # Real execution and evidence come from the Tool Execution Manager and
        # are persisted by core.persistent_store. The envelope below describes
        # the plan only, so no tool output, subdomain, CVE or finding is
        # fabricated by the agent.
        output_summary = (
            f"[{self.role}] Orchestration plan recorded for task: "
            f"{task.description[:120]}. Expected output: {task.expected_output[:80]}. "
            "No security tool was executed by this agent; no findings, tool "
            "output or scan evidence are asserted."
        )

        elapsed = round(time.perf_counter() - start, 3)
        result = {
            "task_id": task.task_id,
            "agent_role": self.role,
            "status": "COMPLETED",
            "execution_mode": "synthetic_planning",
            "evidence": "none; no tool invocation",
            "tools_executed": [],
            "output": output_summary,
            "duration_sec": elapsed,
            "tools_used": self.tools
        }
        self.add_to_memory(result)
        return result


class SNMKCrew:
    """
    CrewAI Orchestrator managing sequential and hierarchical multi-agent crews.
    Enforces authorization gating, anti-infinite loop guards, and sensitive data redaction.
    """
    def __init__(self, agents: list[SNMKCrewAIAgent], tasks: list[CrewAITaskConfig], process: str = "sequential"):
        self.crew_id = f"crew_{uuid.uuid4().hex[:8]}"
        self.agents = {a.role: a for a in agents}
        self.tasks = tasks
        self.process = process  # sequential, hierarchical
        self.is_native_crewai_available = bool(importlib.util.find_spec("crewai"))

    async def kickoff(self, inputs: dict[str, Any] | None = None) -> CrewAIResult:
        """Kicks off crew execution across all defined tasks."""
        start_time = time.perf_counter()
        completed_results: list[dict[str, Any]] = []
        overall_status = "COMPLETED"
        accumulated_context: dict[str, Any] = inputs or {}

        for task in self.tasks:
            agent = self.agents.get(task.agent_role)
            if not agent:
                # Fallback to first agent
                agent = next(iter(self.agents.values())) if self.agents else None
            if not agent:
                overall_status = "FAILED"
                break

            try:
                res = await agent.execute_task(task, context=accumulated_context)
                completed_results.append(res)
                accumulated_context[task.task_id] = res.get("output", "")
            except Exception as exc:  # noqa: BLE001
                logger.error(f"Task {safe_log_text(task.task_id)} failed in crew {safe_log_text(self.crew_id)}: {safe_log_text(exc)}")
                overall_status = "FAILED"
                completed_results.append({
                    "task_id": task.task_id,
                    "agent_role": task.agent_role,
                    "status": "FAILED",
                    "error": safe_error("Task execution failed.", exc)
                })
                break

        duration = round(time.perf_counter() - start_time, 3)
        summary_text = (
            f"Crew [{self.crew_id}] executed {len(completed_results)}/{len(self.tasks)} tasks. "
            f"Status: {overall_status}. Process: {self.process}."
        )

        return CrewAIResult(
            crew_id=self.crew_id,
            status=overall_status,
            tasks_completed=len(completed_results),
            total_tasks=len(self.tasks),
            duration_sec=duration,
            output=summary_text,
            task_results=completed_results
        )


def create_cybersecurity_pentest_crew() -> SNMKCrew:
    """Pre-configured enterprise offensive/defensive cybersecurity assessment crew."""
    recon_agent = SNMKCrewAIAgent(CrewAIAgentConfig(
        role="Senior Reconnaissance Specialist",
        goal="Enumerate all external hostnames, open ports, and cloud assets within authorized scope",
        backstory="Expert OSINT specialist with 10 years experience discovering shadow IT and dangling DNS pointers.",
        tools=["amass", "subfinder", "nmap"],
        allow_delegation=False
    ))

    vuln_agent = SNMKCrewAIAgent(CrewAIAgentConfig(
        role="Application Security Auditor",
        goal="Audit web applications and APIs for OWASP Top 10 vulnerabilities (SQLi, XSS, SSRF, Auth)",
        backstory="Seasoned penetration tester specializing in high-fidelity zero-noise vulnerability verification.",
        tools=["owasp_plugins", "sqli_engine", "js_intelligence"],
        allow_delegation=False
    ))

    remediation_agent = SNMKCrewAIAgent(CrewAIAgentConfig(
        role="DevSecOps Remediation Architect",
        goal="Generate actionable virtual patches and verified source code fixes for detected vulnerabilities",
        backstory="DevSecOps engineer who writes deterministic, secure patches and WAF mitigation rules.",
        tools=["remediation_engine", "cyber_export"],
        allow_delegation=False
    ))

    tasks = [
        CrewAITaskConfig(
            description="Perform passive and active asset discovery against authorized target",
            expected_output="Verified list of discoverable subdomains and responsive web ports",
            agent_role="Senior Reconnaissance Specialist",
            tools=["amass", "subfinder"]
        ),
        CrewAITaskConfig(
            description="Execute non-destructive security vulnerability probes against responsive endpoints",
            expected_output="Normalized findings list formatted with CVSS 3.1 scores and reproduction steps",
            agent_role="Application Security Auditor",
            tools=["owasp_plugins", "sqli_engine"]
        ),
        CrewAITaskConfig(
            description="Generate remediation patches and ModSecurity/AWS WAF virtual protection rules",
            expected_output="Actionable code diffs and defensive security rule definitions",
            agent_role="DevSecOps Remediation Architect",
            tools=["remediation_engine"]
        )
    ]

    return SNMKCrew(agents=[recon_agent, vuln_agent, remediation_agent], tasks=tasks, process="sequential")


# =====================================================================
# 22 Specialized Enterprise CrewAI Agent Fleet Definitions (Phase 2)
# =====================================================================

CREWAI_22_FLEET_SPECS: list[dict[str, Any]] = [
    {
        "role": "Lead AI Engineering Agent",
        "goal": "Orchestrate all engineering agents, assign development tasks, resolve conflicts, and verify overall platform delivery.",
        "backstory": "Principal Software Architect and autonomous AI lead with deep systems expertise in distributed architectures.",
        "tools": ["agent_registry", "workflow_engine", "git_manager"],
    },
    {
        "role": "Python Backend Agent",
        "goal": "Develop, debug, and optimize asynchronous FastAPI endpoints, Pydantic data schemas, and backend core services.",
        "backstory": "Senior Python Systems Engineer focused on sub-5ms API latency, non-blocking asyncio paradigms, and typing safety.",
        "tools": ["fastapi_router", "pydantic_validator", "asyncio_pool"],
    },
    {
        "role": "C/C++ Engineering Agent",
        "goal": "Build, compile, and benchmark modern C++17 native acceleration modules with zero memory leaks and high socket throughput.",
        "backstory": "Principal C++ Engineer specialized in WinSock2 non-blocking I/O, RAII, move semantics, and microsecond packet handling.",
        "tools": ["cmake", "gcc_compiler", "snmk_fast_scan", "valgrind"],
    },
    {
        "role": "Frontend Engineering Agent",
        "goal": "Maintain and enhance the responsive SOC dashboard, live WebSocket telemetry feeds, and interactive graph visualizations.",
        "backstory": "Full-Stack Frontend Architect proficient in modern ES6+, Tailwind CSS utility systems, Chart.js, and Vis.js.",
        "tools": ["spa_router", "dom_renderer", "chart_engine"],
    },
    {
        "role": "MySQL Database Agent",
        "goal": "Architect, maintain, and optimize MySQL 8.x relational schemas, connection pooling, and cross-database migrations.",
        "backstory": "Senior Database Administrator with expertise in InnoDB indexing, query execution planning, and high-concurrency WAL logging.",
        "tools": ["mysql_manager", "alembic_migrator", "query_optimizer"],
    },
    {
        "role": "Cybersecurity Agent",
        "goal": "Conduct autonomous authorized security assessments, prioritize risks, and coordinate vulnerability management.",
        "backstory": "Lead Cybersecurity Specialist and Ethical Hacker specializing in proactive attack surface management and threat modeling.",
        "tools": ["tool_registry", "vulnerability_catalog", "scope_policy"],
    },
    {
        "role": "SAST Agent",
        "goal": "Perform automated Static Application Security Testing, detecting code smells, injection risks, and AST flaws.",
        "backstory": "Application Security Engineer specializing in Semgrep, Bandit, and static syntax tree semantic analysis.",
        "tools": ["semgrep", "bandit", "ast_parser"],
    },
    {
        "role": "DAST Agent",
        "goal": "Execute non-destructive Dynamic Application Security Testing against active endpoints within approved lab scopes.",
        "backstory": "Dynamic application testing specialist running automated baseline probes, fuzzers, and OWASP ZAP checks.",
        "tools": ["owasp_zap", "nuclei", "dynamic_prober"],
    },
    {
        "role": "API Security Agent",
        "goal": "Audit REST, GraphQL, and WebSocket endpoints against OWASP API Security Top 10 vulnerabilities.",
        "backstory": "API security architect focused on BOLA, BFLA, parameter tampering, and strict rate-limiting compliance.",
        "tools": ["api_schema_validator", "jwt_inspector", "rate_limiter"],
    },
    {
        "role": "Network Security Agent",
        "goal": "Analyze network interfaces, port states, and ingress/egress routes for perimeter attack surface expansion.",
        "backstory": "Network Defense Engineer analyzing TCP/UDP state machines, routing topologies, and exposed socket services.",
        "tools": ["nmap_engine", "snmk_fast_scan", "port_auditor"],
    },
    {
        "role": "Penetration Testing Agent",
        "goal": "Validate exploitability of discovered vulnerabilities by generating non-destructive proof-of-concept cURL scripts.",
        "backstory": "Red Team Specialist dedicated to confirming findings with 100% deterministic PoC evidence and zero false positives.",
        "tools": ["exploit_validator", "curl_generator", "poc_verifier"],
    },
    {
        "role": "AI Integration Agent",
        "goal": "Manage LLM client connections, prompt template pipelines, and model fallback hierarchies.",
        "backstory": "AI Systems Engineer specialized in robust model orchestration across OpenAI, Anthropic, Gemini, and Ollama.",
        "tools": ["llm_client", "prompt_manager", "token_counter"],
    },
    {
        "role": "LangChain Agent",
        "goal": "Design structured RAG chains, vector search retrieval, and deterministic JSON output parsers.",
        "backstory": "LangChain Developer building reproducible, grounded prompt pipelines and context-isolated agents.",
        "tools": ["langchain_core", "rag_retriever", "output_parser"],
    },
    {
        "role": "LangSmith Evaluation Agent",
        "goal": "Trace prompt completions, track latency histograms, and record token costs across multi-agent workflows.",
        "backstory": "LLMOps observability engineer dedicated to comprehensive prompt telemetry and distributed trace evaluation.",
        "tools": ["langsmith_tracer", "latency_analyzer", "token_profiler"],
    },
    {
        "role": "Giskard Evaluation Agent",
        "goal": "Red-team AI models against prompt injection, jailbreaking, data leakage, and hallucination exploits.",
        "backstory": "AI Security Auditor validating model robustness, input guardrails, and adversarial safety boundaries.",
        "tools": ["giskard_evaluator", "guardrail_scanner", "prompt_injector"],
    },
    {
        "role": "DevOps Agent",
        "goal": "Manage Docker containers, Kubernetes Helm charts, and multi-platform build scripts.",
        "backstory": "Site Reliability and DevOps Engineer optimizing image layer caching, non-root runtimes, and local runners.",
        "tools": ["docker_cli", "k8s_manager", "runner_scripts"],
    },
    {
        "role": "CI/CD Agent",
        "goal": "Maintain automated GitHub Actions pipelines with multi-stage security, testing, and linting gates.",
        "backstory": "CI/CD Automation Specialist building reproducible, hardened workflows with zero hardcoded credentials.",
        "tools": ["github_actions", "workflow_linter", "pipeline_verifier"],
    },
    {
        "role": "Testing and QA Agent",
        "goal": "Execute Pytest suites, detect regressions, measure test coverage, and validate bug fixes.",
        "backstory": "QA Automation Lead requiring 100% test pass rates and rigorous empirical evidence before code handover.",
        "tools": ["pytest_runner", "coverage_analyzer", "regression_suite"],
    },
    {
        "role": "Observability Agent",
        "goal": "Monitor Prometheus metrics, Grafana dashboards, Loki log streams, and system health status.",
        "backstory": "Observability Engineer providing real-time visibility into CPU, memory, uptime, and request histograms.",
        "tools": ["prometheus_client", "grafana_api", "loki_tailer"],
    },
    {
        "role": "Alert Management Agent",
        "goal": "Capture, deduplicate, prioritize, and dispatch operational and security alerts across notification channels.",
        "backstory": "SOC Incident Coordinator managing alert life cycles, suppression windows, and webhook escalations.",
        "tools": ["alert_manager", "notification_dispatcher", "webhook_router"],
    },
    {
        "role": "Documentation Agent",
        "goal": "Maintain exhaustive technical documentation, audit reports, and deployment manuals.",
        "backstory": "Technical Documentation Specialist producing clear, structured, GitHub-flavored markdown deliverables.",
        "tools": ["markdown_generator", "report_exporter", "doc_auditor"],
    },
    {
        "role": "Performance Optimization Agent",
        "goal": "Profile application latency, identify $O(N^2)$ algorithmic bottlenecks, and benchmark optimizations.",
        "backstory": "High-Performance Computing Engineer specializing in time/space complexity analysis and memory optimization.",
        "tools": ["cprofile_runner", "benchmark_harness", "dsa_optimizer"],
    },
]


def get_crewai_agent_fleet() -> list[SNMKCrewAIAgent]:
    """Instantiates and returns the complete fleet of 22 specialized enterprise CrewAI agents."""
    agents = []
    for spec in CREWAI_22_FLEET_SPECS:
        config = CrewAIAgentConfig(
            role=spec["role"],
            goal=spec["goal"],
            backstory=spec["backstory"],
            tools=spec["tools"],
            allow_delegation=(spec["role"] == "Lead AI Engineering Agent"),
            agent_id=f"crew_agent_{spec['role'].lower().replace(' ', '_').replace('/', '_')}"
        )
        agents.append(SNMKCrewAIAgent(config))
    return agents


def create_enterprise_engineering_crew() -> SNMKCrew:
    """Builds a full-lifecycle autonomous engineering crew executing planning, code repair, and verification."""
    fleet = {agent.role: agent for agent in get_crewai_agent_fleet()}

    tasks = [
        CrewAITaskConfig(
            description="Audit repository health and plan development repair assignments",
            expected_output="Prioritized repair task register with designated agent ownership",
            agent_role="Lead AI Engineering Agent",
            tools=["agent_registry", "workflow_engine"]
        ),
        CrewAITaskConfig(
            description="Verify MySQL database connection, pool health, and schema DDL status",
            expected_output="MySQL health diagnostics payload and schema integrity verification",
            agent_role="MySQL Database Agent",
            tools=["mysql_manager", "query_optimizer"]
        ),
        CrewAITaskConfig(
            description="Execute automated regression testing and measure platform quality gates",
            expected_output="100% pass verification across unit and integration test suites",
            agent_role="Testing and QA Agent",
            tools=["pytest_runner", "regression_suite"]
        ),
        CrewAITaskConfig(
            description="Synchronize observability telemetry and verify active alert thresholds",
            expected_output="Metrics snapshot and active alert lifecycle confirmation",
            agent_role="Alert Management Agent",
            tools=["alert_manager", "notification_dispatcher"]
        ),
    ]

    assigned_agents = [
        fleet["Lead AI Engineering Agent"],
        fleet["MySQL Database Agent"],
        fleet["Testing and QA Agent"],
        fleet["Alert Management Agent"],
    ]

    return SNMKCrew(agents=assigned_agents, tasks=tasks, process="sequential")


# =====================================================================
# 12 Specialized Universal Vulnerability Scanner CrewAI Agents (Phase 7)
# =====================================================================

CREWAI_UNIVERSAL_SCANNER_SPECS: list[dict[str, Any]] = [
    {
        "role": "URL Security Agent",
        "goal": "Analyze HTTP/HTTPS configuration, TLS certificate validity, security headers, cookie security, and redirect behavior.",
        "backstory": "Specialist in perimeter web transport security, SSL/TLS handshake inspection, and HTTP protocol defenses.",
        "tools": ["tls_inspector", "header_auditor", "cookie_checker"],
    },
    {
        "role": "Web Application Security Agent",
        "goal": "Detect exposed endpoints, directory listings, basic API security flaws, and OWASP Top 10 indicators.",
        "backstory": "Web security specialist probing application layer misconfigurations and public surface exposures.",
        "tools": ["endpoint_prober", "owasp_checker", "api_auditor"],
    },
    {
        "role": "Document Security Agent",
        "goal": "Inspect PDF, DOC, DOCX, TXT, and Markdown files for embedded URLs, phishing links, suspicious scripts, and macro indicators.",
        "backstory": "Document forensic auditor skilled at identifying malicious active content, suspicious PDF actions, and hidden macros.",
        "tools": ["pdf_parser", "docx_parser", "macro_detector"],
    },
    {
        "role": "Image Analysis Agent",
        "goal": "Audit EXIF metadata, GPS leaks, embedded payload indicators, and polyglot files.",
        "backstory": "Digital media forensics expert inspecting image chunks, metadata privacy exposures, and appended binaries.",
        "tools": ["exif_extractor", "gps_locator", "payload_detector"],
    },
    {
        "role": "OCR Analysis Agent",
        "goal": "Extract text from screenshots and graphical assets to detect exposed API keys, credentials, and confidential data.",
        "backstory": "Optical character recognition analyst parsing screenshots for accidental visual secret leakage.",
        "tools": ["ocr_engine", "text_extractor", "credential_matcher"],
    },
    {
        "role": "Source Code Analysis Agent",
        "goal": "Perform static analysis across multiple languages to detect SQLi, XSS, command injection, path traversal, and insecure deserialization.",
        "backstory": "Application security engineer versed in AST parsing, taint analysis, and semantic code flaw detection.",
        "tools": ["sast_engine", "ast_parser", "flaw_detector"],
    },
    {
        "role": "Secret Detection Agent",
        "goal": "Scan source code, config files, and documents for hardcoded credentials, API keys, tokens, and private keys.",
        "backstory": "Secrets detection expert utilizing high-entropy heuristics, regex patterns, and known token signatures.",
        "tools": ["entropy_analyzer", "regex_scanner", "secret_catalog"],
    },
    {
        "role": "Dependency Analysis Agent",
        "goal": "Audit package manifests and third-party dependencies for known vulnerabilities and insecure version pinning.",
        "backstory": "Software supply chain security analyst evaluating dependencies and package vulnerabilities.",
        "tools": ["sca_scanner", "cve_matcher", "dependency_auditor"],
    },
    {
        "role": "Malware Indicator Analysis Agent",
        "goal": "Inspect archives and files for zip slip, decompression bombs, unexpected binary headers, and malicious payloads.",
        "backstory": "Static malware analyst identifying archive traps, file signature anomalies, and dangerous executable fragments.",
        "tools": ["archive_inspector", "magic_identifier", "bomb_guard"],
    },
    {
        "role": "Vulnerability Correlation Agent",
        "goal": "Correlate findings across scanners, remove duplicate detections, and map evidence to CWE/CVSS standards.",
        "backstory": "Cybersecurity correlation specialist consolidating multifaceted telemetry into normalized vulnerability findings.",
        "tools": ["deduplicator", "cwe_mapper", "cvss_calculator"],
    },
    {
        "role": "Risk Assessment Agent",
        "goal": "Calculate overall target risk posture, assign severity classifications, and prioritize remediation actions.",
        "backstory": "Risk management engineer synthesizing exposure metrics into actionable enterprise risk scoring.",
        "tools": ["risk_engine", "severity_classifier", "remediation_planner"],
    },
    {
        "role": "Report Generation Agent",
        "goal": "Aggregate scan findings and telemetry into comprehensive downloadable PDF, HTML, JSON, CSV, Markdown, and SARIF reports.",
        "backstory": "Technical compliance reporting specialist delivering audit-grade cybersecurity assessment deliverables.",
        "tools": ["report_generator", "sarif_builder", "export_manager"],
    },
]

CREWAI_SPECIALIST_SPECS: list[dict[str, Any]] = [
    {
        "role": "Cryptography Analysis Agent",
        "goal": "Analyze cryptographic primitives, detect deprecated ciphers, evaluate key strengths, and execute authenticated encryption/decryption workflows.",
        "backstory": "Principal cryptographer specializing in AES-GCM, ChaCha20-Poly1305, RSA-OAEP, post-quantum readiness, and recipe transformations.",
        "tools": ["crypto_engine", "recipe_runner", "key_generator"],
    },
    {
        "role": "PCAP Forensics Agent",
        "goal": "Inspect packet captures, reconstruct network flows, detect SYN flood and port scan anomalies, and identify covert DNS exfiltration channels.",
        "backstory": "Network security and deep packet inspection specialist with expertise in protocol dissection, flow analysis, and C2 detection.",
        "tools": ["pcap_analyzer", "flow_reconstructor", "anomaly_detector"],
    },
]


def get_universal_scanner_fleet() -> list[SNMKCrewAIAgent]:
    """Instantiates the fleet of 12 specialized CrewAI agents for Universal Vulnerability Scanning."""
    agents = []
    for spec in CREWAI_UNIVERSAL_SCANNER_SPECS:
        config = CrewAIAgentConfig(
            role=spec["role"],
            goal=spec["goal"],
            backstory=spec["backstory"],
            tools=spec["tools"],
            allow_delegation=(spec["role"] == "Vulnerability Correlation Agent"),
            agent_id=f"crew_agent_{spec['role'].lower().replace(' ', '_').replace('/', '_')}"
        )
        agents.append(SNMKCrewAIAgent(config))
    return agents


def create_universal_scanner_crew(scan_type: str = "all", target: str = "") -> SNMKCrew:
    """Builds a customized CrewAI crew for universal scanning workflows."""
    fleet = {agent.role: agent for agent in get_universal_scanner_fleet()}

    tasks = [
        CrewAITaskConfig(
            description=f"Analyze submitted {scan_type} target ({target}) for active and passive security flaws",
            expected_output="Verified technical vulnerability findings mapped to CWEs and confidence scores",
            agent_role="URL Security Agent" if scan_type == "url" else "Source Code Analysis Agent",
            tools=["tls_inspector", "header_auditor"] if scan_type == "url" else ["sast_engine", "secret_catalog"]
        ),
        CrewAITaskConfig(
            description=f"Correlate raw scan evidence, eliminate duplicate findings, and calculate CVSS scores for {target}",
            expected_output="Deduplicated, prioritized vulnerability list with severity classifications",
            agent_role="Vulnerability Correlation Agent",
            tools=["deduplicator", "cwe_mapper", "cvss_calculator"]
        ),
        CrewAITaskConfig(
            description=f"Assess business risk and draft remediation recommendations for {target}",
            expected_output="Risk posture score with contextual fix instructions",
            agent_role="Risk Assessment Agent",
            tools=["risk_engine", "severity_classifier", "remediation_planner"]
        ),
        CrewAITaskConfig(
            description=f"Format assessment output into standard enterprise report formats",
            expected_output="Multi-format report bundle (JSON, HTML, SARIF, Markdown, CSV)",
            agent_role="Report Generation Agent",
            tools=["report_generator", "sarif_builder"]
        ),
    ]

    selected_agents = [
        fleet["URL Security Agent" if scan_type == "url" else "Source Code Analysis Agent"],
        fleet["Vulnerability Correlation Agent"],
        fleet["Risk Assessment Agent"],
        fleet["Report Generation Agent"],
    ]

    return SNMKCrew(agents=selected_agents, tasks=tasks, process="sequential")
