"""
SWA AI — AI Automation & Security Workflow Orchestration Engine
Provides autonomous, multi-step, human-gated cybersecurity workflows using
registered AI agents, security tools, and threat intelligence adapters.
"""

import os
import json
import time
import uuid
import asyncio
import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from core.database import db
from core.scope_policy import scope_policy, ScopeViolation
from core.agent_registry import AgentRegistry


class WorkflowStep(BaseModel):
    step_id: str
    name: str
    description: str = ""
    agent_id: Optional[str] = None
    tool_id: Optional[str] = None
    action_type: str = "agent_task"  # scope_check, recon, agent_task, tool_run, risk_analysis, remediation, approval_gate, report_gen
    input_config: Dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False
    condition: Optional[str] = None  # e.g. "findings_count > 0"
    timeout_sec: int = 120


class AutomationWorkflow(BaseModel):
    id: str
    name: str
    description: str
    category: str = "Vulnerability Assessment"
    enabled: bool = True
    trigger_type: str = "manual"  # manual, scheduled, continuous
    schedule_cron: Optional[str] = None
    steps: List[WorkflowStep] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    last_run_at: Optional[str] = None
    last_status: Optional[str] = "IDLE"


class WorkflowExecutionRecord(BaseModel):
    id: str
    workflow_id: str
    workflow_name: str
    target: str
    status: str = "RUNNING"  # RUNNING, COMPLETED, FAILED, PAUSED, PENDING_APPROVAL
    current_step: int = 0
    total_steps: int = 0
    started_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_sec: float = 0.0
    initiated_by: str = "Security_Operator"
    step_logs: List[Dict[str, Any]] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


DEFAULT_WORKFLOWS: List[AutomationWorkflow] = [
    AutomationWorkflow(
        id="wf-full-pentest-01",
        name="Autonomous Full-Scope Attack Surface & Penetration Audit",
        description="Comprehensive 11-step enterprise pipeline: scope validation, passive & active recon, multi-agent vulnerability assessment, findings normalization, risk analysis, remediation, human approval gating, and compliance reporting.",
        category="Comprehensive Pentest",
        enabled=True,
        trigger_type="manual",
        steps=[
            WorkflowStep(
                step_id="step-1",
                name="Scope Validation & Target Policy Enforcement",
                description="Validates target against authorized domain scope and prevents malicious SSRF.",
                action_type="scope_check",
                input_config={"enforce_rfc1918": True, "block_cloud_imds": True}
            ),
            WorkflowStep(
                step_id="step-2",
                name="Asset Discovery & Subdomain Enumeration",
                description="Discovers attack surface assets and live DNS hostnames using OWASP Amass.",
                action_type="recon",
                tool_id="amass",
                agent_id="attack_surface_agent",
                input_config={"passive_only": False, "concurrency": 20}
            ),
            WorkflowStep(
                step_id="step-3",
                name="Infrastructure Reconnaissance & Port Scanning",
                description="Surfaces open ports, web listeners, and service banners.",
                action_type="tool_run",
                tool_id="nmap",
                agent_id="network_recon_agent",
                # nmap is not installed on this host; step is recorded as SIMULATED, not executed
                input_config={"top_ports": 100, "service_detect": True}
            ),
            WorkflowStep(
                step_id="step-4",
                name="Specialist Security Agent Workforce Dispatch",
                description="Synchronizes 5-tier multi-agent workforce and assigns assessment targets.",
                action_type="agent_task",
                agent_id="supervisor",
                input_config={"task": "Initialize autonomous pentesting campaign"}
            ),
            WorkflowStep(
                step_id="step-5",
                name="Active Vulnerability Probing & Injection Checks",
                description="Executes SQL injection, XSS, SSRF, and authentication bypass probes.",
                action_type="agent_task",
                agent_id="fuzzer_agent",
                input_config={"scan_profile": "standard", "test_sqli": True, "test_xss": True}
            ),
            WorkflowStep(
                step_id="step-6",
                name="Findings Ingestion & Normalization",
                description="Normalizes raw vulnerabilities into CVSS/CWE formatted security records.",
                action_type="risk_analysis",
                input_config={"deduplicate": True, "correlate_cwe": True}
            ),
            WorkflowStep(
                step_id="step-7",
                name="Risk Posture Scoring & Threat Modeling",
                description="Calculates enterprise security score using canonical posture formula.",
                action_type="risk_analysis",
                input_config={"formula": "CRIT*30 + HIGH*18 + MED*8 + LOW*3 + INFO*1"}
            ),
            WorkflowStep(
                step_id="step-8",
                name="Automated Remediation & Virtual Patch Synthesis",
                description="Generates actionable code fixes and WAF mitigation rules (ModSecurity, AWS WAF).",
                action_type="remediation",
                agent_id="remediation_agent",
                input_config={"generate_waf_rules": True}
            ),
            WorkflowStep(
                step_id="step-9",
                name="Human-in-the-Loop Sensitive Action Approval Gate",
                description="Pauses workflow for authorized human sign-off before active exploitation or disruptive fixes.",
                action_type="approval_gate",
                requires_approval=True,
                input_config={"action_type": "EXPLOIT_VALIDATION"}
            ),
            WorkflowStep(
                step_id="step-10",
                name="Post-Fix Retest & Verification Probes",
                description="Autonomous re-verification probes against identified vulnerability endpoints.",
                action_type="agent_task",
                agent_id="remediation_lifecycle_agent",
                input_config={"verify_remediation": True}
            ),
            WorkflowStep(
                step_id="step-11",
                name="Final Compliance & Technical Report Generation",
                description="Generates signed Executive & Technical Audit Reports in HTML, JSON, Markdown, and SARIF.",
                action_type="report_gen",
                input_config={"formats": ["html", "json", "sarif", "markdown"]}
            )
        ]
    ),
    AutomationWorkflow(
        id="wf-web-owasp-02",
        name="Continuous OWASP Top 10 Web Vulnerability Assessment",
        description="Focused web application security assessment auditing injection, broken auth, SSRF, and sensitive data exposure.",
        category="Web Application Security",
        enabled=True,
        trigger_type="manual",
        steps=[
            WorkflowStep(
                step_id="step-1",
                name="Scope Validation",
                action_type="scope_check",
                input_config={}
            ),
            WorkflowStep(
                step_id="step-2",
                name="Web Crawler & Attack Surface Mapping",
                action_type="agent_task",
                agent_id="web_pentester",
                input_config={"crawl_depth": 3}
            ),
            WorkflowStep(
                step_id="step-3",
                name="OWASP Injection Probing (SQLi, XSS, SSRF)",
                action_type="agent_task",
                agent_id="web_pentester",
                input_config={"sqli": True, "xss": True, "ssrf": True}
            ),
            WorkflowStep(
                step_id="step-4",
                name="WAF Virtual Patch Generation",
                action_type="remediation",
                input_config={"target_format": "modsecurity"}
            ),
            WorkflowStep(
                step_id="step-5",
                name="Export Audit Report",
                action_type="report_gen",
                input_config={"formats": ["html", "sarif"]}
            )
        ]
    ),
    AutomationWorkflow(
        id="wf-api-security-03",
        name="API Security, Token & IDOR Vulnerability Audit",
        description="Automated REST/GraphQL endpoint discovery, authentication fuzzing, and broken object level authorization (BOLA) verification.",
        category="API Security",
        enabled=True,
        trigger_type="manual",
        steps=[
            WorkflowStep(
                step_id="step-1",
                name="API Scope & Spec Ingestion",
                action_type="scope_check",
                input_config={"probe_openapi": True}
            ),
            WorkflowStep(
                step_id="step-2",
                name="Token Security & JWT Signature Fuzzing",
                action_type="agent_task",
                agent_id="web_pentester",
                input_config={"jwt_attacks": ["none_alg", "weak_hmac"]}
            ),
            WorkflowStep(
                step_id="step-3",
                name="IDOR & Parameter Tampering Probes",
                action_type="agent_task",
                agent_id="web_pentester",
                input_config={"fuzz_ids": True}
            ),
            WorkflowStep(
                step_id="step-4",
                name="Generate API Security Report",
                action_type="report_gen",
                input_config={"formats": ["json", "html"]}
            )
        ]
    ),
    AutomationWorkflow(
        id="wf-llm-redteam-04",
        name="Adversarial AI / LLM Prompt Injection & Security Audit",
        description="Autonomous red teaming against configured LLMs testing for prompt injection, jailbreaks, training data extraction, and SSRF via LLM.",
        category="AI Security",
        enabled=True,
        trigger_type="manual",
        steps=[
            WorkflowStep(
                step_id="step-1",
                name="AI Model Integration Health Check",
                action_type="scope_check",
                input_config={"verify_ai_provider": True}
            ),
            WorkflowStep(
                step_id="step-2",
                name="Adversarial Prompt Injection & Jailbreak Probes",
                action_type="tool_run",
                tool_id="llm_redteam",
                input_config={"test_categories": ["DIRECT_INJECTION", "SYSTEM_LEAKAGE", "SAFETY_JAILBREAK"]}
            ),
            WorkflowStep(
                step_id="step-3",
                name="AI Safety Score & Vulnerability Compilation",
                action_type="risk_analysis",
                input_config={"eval_mode": "strict"}
            ),
            WorkflowStep(
                step_id="step-4",
                name="AI Compliance & Red Team Audit Report",
                action_type="report_gen",
                input_config={"formats": ["html", "json"]}
            )
        ]
    )
]


class AutomationEngine:
    def __init__(self):
        self._ensure_tables()
        self._seed_default_workflows()

    def _get_connection(self):
        return db.get_connection()

    def _ensure_tables(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS automation_workflows (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT DEFAULT 'Vulnerability Assessment',
                enabled INTEGER DEFAULT 1,
                trigger_type TEXT DEFAULT 'manual',
                schedule_cron TEXT,
                steps TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_run_at TEXT,
                last_status TEXT DEFAULT 'IDLE'
            )
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS workflow_executions (
                id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                current_step INTEGER DEFAULT 0,
                total_steps INTEGER DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_sec REAL DEFAULT 0.0,
                initiated_by TEXT DEFAULT 'Security_Operator',
                step_logs TEXT,
                summary TEXT,
                error TEXT
            )
            """)
            conn.commit()

    def _seed_default_workflows(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM automation_workflows")
            if cursor.fetchone()[0] == 0:
                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                for wf in DEFAULT_WORKFLOWS:
                    cursor.execute("""
                    INSERT INTO automation_workflows (id, name, description, category, enabled, trigger_type, schedule_cron, steps, created_at, updated_at, last_run_at, last_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        wf.id, wf.name, wf.description, wf.category,
                        1 if wf.enabled else 0, wf.trigger_type, wf.schedule_cron,
                        json.dumps([s.model_dump() for s in wf.steps]),
                        now, now, None, "IDLE"
                    ))
                conn.commit()

    def list_workflows(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, description, category, enabled, trigger_type, schedule_cron, steps, created_at, updated_at, last_run_at, last_status FROM automation_workflows ORDER BY created_at ASC")
            rows = cursor.fetchall()
            workflows = []
            for r in rows:
                steps_data = json.loads(r[7]) if r[7] else []
                workflows.append({
                    "id": r[0],
                    "name": r[1],
                    "description": r[2],
                    "category": r[3],
                    "enabled": bool(r[4]),
                    "trigger_type": r[5],
                    "schedule_cron": r[6],
                    "steps": steps_data,
                    "steps_count": len(steps_data),
                    "created_at": r[8],
                    "updated_at": r[9],
                    "last_run_at": r[10],
                    "last_status": r[11] or "IDLE"
                })
            return workflows

    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, description, category, enabled, trigger_type, schedule_cron, steps, created_at, updated_at, last_run_at, last_status FROM automation_workflows WHERE id = ?", (workflow_id,))
            r = cursor.fetchone()
            if not r:
                return None
            steps_data = json.loads(r[7]) if r[7] else []
            return {
                "id": r[0],
                "name": r[1],
                "description": r[2],
                "category": r[3],
                "enabled": bool(r[4]),
                "trigger_type": r[5],
                "schedule_cron": r[6],
                "steps": steps_data,
                "steps_count": len(steps_data),
                "created_at": r[8],
                "updated_at": r[9],
                "last_run_at": r[10],
                "last_status": r[11] or "IDLE"
            }

    def create_workflow(self, workflow_data: Dict[str, Any]) -> Dict[str, Any]:
        wf_id = workflow_data.get("id") or f"wf_{uuid.uuid4().hex[:8]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        name = workflow_data.get("name", "Custom Security Automation")
        desc = workflow_data.get("description", "")
        cat = workflow_data.get("category", "Custom Automation")
        enabled = 1 if workflow_data.get("enabled", True) else 0
        trigger = workflow_data.get("trigger_type", "manual")
        cron = workflow_data.get("schedule_cron")
        steps = workflow_data.get("steps", [])
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO automation_workflows (id, name, description, category, enabled, trigger_type, schedule_cron, steps, created_at, updated_at, last_run_at, last_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (wf_id, name, desc, cat, enabled, trigger, cron, json.dumps(steps), now, now, None, "IDLE"))
            conn.commit()
        return self.get_workflow(wf_id)

    def update_workflow(self, workflow_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        existing = self.get_workflow(workflow_id)
        if not existing:
            return None
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        name = updates.get("name", existing["name"])
        desc = updates.get("description", existing["description"])
        cat = updates.get("category", existing["category"])
        enabled = 1 if updates.get("enabled", existing["enabled"]) else 0
        trigger = updates.get("trigger_type", existing["trigger_type"])
        cron = updates.get("schedule_cron", existing["schedule_cron"])
        steps = updates.get("steps", existing["steps"])
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE automation_workflows
            SET name = ?, description = ?, category = ?, enabled = ?, trigger_type = ?, schedule_cron = ?, steps = ?, updated_at = ?
            WHERE id = ?
            """, (name, desc, cat, enabled, trigger, cron, json.dumps(steps), now, workflow_id))
            conn.commit()
        return self.get_workflow(workflow_id)

    def delete_workflow(self, workflow_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM automation_workflows WHERE id = ?", (workflow_id,))
            conn.commit()
            return cursor.rowcount > 0

    def duplicate_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        original = self.get_workflow(workflow_id)
        if not original:
            return None
        clone_data = original.copy()
        clone_data["id"] = f"wf_clone_{uuid.uuid4().hex[:6]}"
        clone_data["name"] = f"{original['name']} (Copy)"
        return self.create_workflow(clone_data)

    def toggle_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        wf = self.get_workflow(workflow_id)
        if not wf:
            return None
        new_state = not wf["enabled"]
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE automation_workflows SET enabled = ? WHERE id = ?", (1 if new_state else 0, workflow_id))
            conn.commit()
        return self.get_workflow(workflow_id)

    def list_executions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, workflow_id, workflow_name, target, status, current_step, total_steps, started_at, completed_at, duration_sec, initiated_by, summary, error FROM workflow_executions ORDER BY started_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            executions = []
            for r in rows:
                executions.append({
                    "id": r[0],
                    "workflow_id": r[1],
                    "workflow_name": r[2],
                    "target": r[3],
                    "status": r[4],
                    "current_step": r[5],
                    "total_steps": r[6],
                    "started_at": r[7],
                    "completed_at": r[8],
                    "duration_sec": r[9],
                    "initiated_by": r[10],
                    "summary": json.loads(r[11]) if r[11] else {},
                    "error": r[12]
                })
            return executions

    def get_execution(self, exec_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, workflow_id, workflow_name, target, status, current_step, total_steps, started_at, completed_at, duration_sec, initiated_by, step_logs, summary, error FROM workflow_executions WHERE id = ?", (exec_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return {
                "id": r[0],
                "workflow_id": r[1],
                "workflow_name": r[2],
                "target": r[3],
                "status": r[4],
                "current_step": r[5],
                "total_steps": r[6],
                "started_at": r[7],
                "completed_at": r[8],
                "duration_sec": r[9],
                "initiated_by": r[10],
                "step_logs": json.loads(r[11]) if r[11] else [],
                "summary": json.loads(r[12]) if r[12] else {},
                "error": r[13]
            }

    async def execute_workflow(self, workflow_id: str, target: str, initiated_by: str = "Security_Operator") -> Dict[str, Any]:
        """
        Executes an automation workflow sequentially step-by-step against the authorized target.
        Enforces target scoping, records step telemetry, and updates persistent database state.
        """
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")
        if not wf["enabled"]:
            raise ValueError(f"Workflow {wf['name']} is currently disabled")

        # 1. Target scope verification
        is_lab = scope_policy.is_lab_target(target)
        val_res = scope_policy.validate_target(target, explicit_lab_authorization=is_lab)
        if not val_res.is_allowed:
            raise ScopeViolation(f"Target scope validation failed for {target}: {val_res.reason}")

        exec_id = f"exec_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
        start_time_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        t0 = time.time()
        steps = wf.get("steps", [])
        total_steps = len(steps)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO workflow_executions (id, workflow_id, workflow_name, target, status, current_step, total_steps, started_at, completed_at, duration_sec, initiated_by, step_logs, summary, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (exec_id, wf["id"], wf["name"], target, "RUNNING", 0, total_steps, start_time_iso, None, 0.0, initiated_by, "[]", "{}", None))
            cursor.execute("UPDATE automation_workflows SET last_run_at = ?, last_status = ? WHERE id = ?", (start_time_iso, "RUNNING", wf["id"]))
            conn.commit()

        step_logs = []
        overall_status = "COMPLETED"
        error_msg = None

        for idx, step in enumerate(steps, start=1):
            step_start = time.time()
            step_name = step.get("name", f"Step {idx}")
            action_type = step.get("action_type", "agent_task")
            requires_appr = step.get("requires_approval", False)
            
            # Step execution record
            step_rec = {
                "step_index": idx,
                "step_id": step.get("step_id", f"s{idx}"),
                "name": step_name,
                "action_type": action_type,
                "agent_id": step.get("agent_id"),
                "tool_id": step.get("tool_id"),
                "status": "RUNNING",
                "output": None,
                "error": None,
                "duration_sec": 0.0
            }

            try:
                # Handle approval gate step
                if requires_appr and not is_lab:
                    step_rec["status"] = "PENDING_APPROVAL"
                    step_rec["output"] = f"Approval gate held: Human authorization required for action {step.get('input_config', {}).get('action_type', 'SENSITIVE_OPERATION')} on {target}."
                    step_logs.append(step_rec)
                    overall_status = "PENDING_APPROVAL"
                    break

                # Dispatch step action
                if action_type == "scope_check":
                    step_rec["output"] = f"Target {target} validated against enterprise scope policy. Lab mode: {is_lab}."
                    step_rec["status"] = "SUCCESS"
                elif action_type == "recon":
                    from core.agent_registry import agent_registry
                    import asyncio as _asyncio
                    recon_agent = step.get("agent_id") or "attack_surface_agent"
                    try:
                        rec = await _asyncio.wait_for(
                            agent_registry.dispatch_agent_by_id(recon_agent, scan_id=exec_id,
                                title=f"Automation recon: {step_name}", inputs={"target": target}),
                            timeout=90.0,
                        )
                        rec = rec or {}
                        step_rec["status"] = "SUCCESS" if rec.get("status") == "COMPLETED" else "FAILED"
                        step_rec["output"] = str((rec.get("outputs") or {}).get("summary") or rec.get("error_message") or "Recon dispatch returned no summary.")[:500]
                    except Exception as recon_err:
                        step_rec["status"] = "FAILED"
                        step_rec["output"] = f"Recon dispatch failed: {recon_err}"
                elif action_type == "tool_run":
                    tool = step.get("tool_id", "security_tool")
                    step_rec["status"] = "SIMULATED"
                    step_rec["output"] = (f"[SIMULATED] No safe in-process execution handler exists for tool '{tool}' "
                                           f"in automation workflows. Run the tool explicitly via /api/tools/{tool}/execute or a scan profile; "
                                           "this step did NOT execute anything.")
                elif action_type == "agent_task":
                    agent_id = step.get("agent_id", "supervisor")
                    from core.agent_registry import agent_registry
                    import asyncio as _asyncio
                    try:
                        rec = await _asyncio.wait_for(
                            agent_registry.dispatch_agent_by_id(
                                agent_id, scan_id=exec_id, title=step_name,
                                inputs={"target": target, **(step.get("input_config") or {})}),
                            timeout=90.0,
                        )
                        rec = rec or {"status": "NOT_EXECUTABLE"}
                        rec_status = str(rec.get("status") or "FAILED").upper()
                        step_rec["status"] = "SUCCESS" if rec_status == "COMPLETED" else rec_status
                        outputs = rec.get("outputs") or {}
                        step_rec["output"] = str(outputs.get("summary") or outputs.get("note") or rec.get("error_message") or f"Agent {agent_id} status: {rec_status}.")[:500]
                    except Exception as agent_err:
                        step_rec["status"] = "FAILED"
                        step_rec["output"] = f"Agent dispatch failed: {agent_err}"
                elif action_type == "risk_analysis":
                    from core.scoring import compute_posture
                    posture = compute_posture(db.list_findings())
                    step_rec["status"] = "SUCCESS"
                    step_rec["output"] = (f"Canonical posture computed from {posture['total']} stored findings: "
                                           f"score {posture['score']}/100, grade {posture['grade']}, risk {posture['risk']}.")
                elif action_type == "remediation":
                    from core.blue_team_engine import BlueTeamDefenseEngine
                    try:
                        report = BlueTeamDefenseEngine.generate_custom(target)
                        rules = report.get("summary", {})
                        step_rec["status"] = "SUCCESS"
                        step_rec["output"] = (f"Generated defensive rule set for {target}: {rules.get('generated_waf_rules', 0)} WAF rules, "
                                               f"{rules.get('generated_ids_signatures', 0)} IDS signatures, {rules.get('generated_siem_rules', 0)} SIEM rules, "
                                               f"{rules.get('generated_hardening_rules', 0)} hardening blocks (deterministic Blue Team engine, no model claim).")
                    except Exception as rem_err:
                        step_rec["status"] = "FAILED"
                        step_rec["output"] = f"Remediation generation failed: {rem_err}"
                elif action_type == "approval_gate":
                    step_rec["output"] = "Approval gate cleared (authorized lab or pre-approved context)."
                    step_rec["status"] = "SUCCESS"
                elif action_type == "report_gen":
                    step_rec["status"] = "NOT_EXECUTED"
                    step_rec["output"] = ("Report generation is not executed inside a workflow step. "
                                           "Use /api/reports/generate or /api/cyber/export/generate to produce the report artifact.")
                else:
                    step_rec["status"] = "NOT_EXECUTED"
                    step_rec["output"] = (f"No execution handler registered for action_type '{action_type}'. "
                                           "Step was NOT executed; this is a planning placeholder, not a completed action.")

            except Exception as e:
                step_rec["status"] = "FAILED"
                step_rec["error"] = str(e)
                error_msg = f"Step {idx} ({step_name}) failed: {str(e)}"
                overall_status = "FAILED"
                step_logs.append(step_rec)
                break

            step_rec["duration_sec"] = round(time.time() - step_start, 2)
            step_logs.append(step_rec)

        # Update final execution record
        duration = round(time.time() - t0, 2)
        completed_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        simulated_steps = sum(1 for s in step_logs if s["status"] == "SIMULATED")
        not_executed_steps = sum(1 for s in step_logs if s["status"] == "NOT_EXECUTED")
        if overall_status == "COMPLETED" and (simulated_steps or not_executed_steps):
            overall_status = "COMPLETED_PARTIAL"
        summary = {
            "total_steps": total_steps,
            "executed_steps": len(step_logs),
            "passed_steps": sum(1 for s in step_logs if s["status"] == "SUCCESS"),
            "failed_steps": sum(1 for s in step_logs if s["status"] == "FAILED"),
            "simulated_steps": simulated_steps,
            "not_executed_steps": not_executed_steps,
            "status": overall_status,
            "target": target
        }

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE workflow_executions
            SET status = ?, current_step = ?, completed_at = ?, duration_sec = ?, step_logs = ?, summary = ?, error = ?
            WHERE id = ?
            """, (overall_status, len(step_logs), completed_iso, duration, json.dumps(step_logs), json.dumps(summary), error_msg, exec_id))
            cursor.execute("UPDATE automation_workflows SET last_status = ? WHERE id = ?", (overall_status, wf["id"]))
            conn.commit()

        # Record audit log
        db.record_audit_log(
            action=f"WORKFLOW_EXECUTION_{overall_status}",
            actor=initiated_by,
            details=f"Automation workflow '{wf['name']}' executed on target {target}. Result: {overall_status} ({duration}s).",
            ip_address="127.0.0.1"
        )

        return self.get_execution(exec_id)


# Global singleton instance
automation_engine = AutomationEngine()
