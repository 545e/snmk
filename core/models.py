"""
SWA AI Autonomous Security Agent - Core Data Models
Pydantic schemas for targets, configs, findings, and scan jobs.
"""

import datetime
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanStatus(str, Enum):
    INITIALIZED = "INITIALIZED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ScanProfile(str, Enum):
    PASSIVE_RECON = "passive_recon"    # Pure passive OSINT, DNS, Certs, Header evaluation
    RECON_ONLY = "recon_only"          # Passive + Active OSINT, DNS brute force, ports
    QUICK = "quick"                    # Rapid surface scan & top misconfigs
    STANDARD = "standard"              # Balanced assessment: OWASP Top 10 + surface + fuzz
    FULL_RED_TEAM = "full_red_team"    # Deep recon, crawling, full exploit & validation
    OWASP_TOP10 = "owasp_top10"        # Systematic OWASP Top 10 web vulnerabilities
    API_SECURITY = "api_security"      # REST/GraphQL API parameter fuzzing & auth checks
    LAB_ASSESSMENT = "lab_assessment"  # Authorized local/test lab assessment (127.0.0.1, PortSwigger)
    ALL_TOOLS = "all_tools"            # Unified threat intel across all engines simultaneously

class ScanConfig(BaseModel):
    target_url: str = Field(..., description="Target domain, URL, or IP address")
    profile: ScanProfile = Field(default=ScanProfile.FULL_RED_TEAM)
    max_depth: int = Field(default=2, ge=1, le=5)
    concurrency: int = Field(default=15, ge=1, le=50)
    timeout_sec: int = Field(default=10, ge=2, le=60)
    custom_headers: dict[str, str] = Field(default_factory=dict)
    auth_bearer_token: str | None = None
    in_scope_regex: str | None = None
    enable_exploit_validation: bool = Field(default=True, description="Active PoC verification")
    enable_subdomain_enum: bool = Field(default=True, description="Perform passive and active subdomain enumeration")
    enable_fuzzing: bool = Field(default=True, description="Perform path and parameter fuzzing")
    fuzzing_wordlist_size: str = Field(default="medium", description="fast, medium, or deep")
    lab_mode: bool = Field(default=False, description="Authorize local lab testing (localhost, DVWA, PortSwigger)")
    enable_sqlmap_lab: bool = Field(default=False, description="Optional safe non-destructive SQLmap detection in lab mode")
    ai_provider: str | None = Field(default="auto", description="openai, anthropic, gemini, openrouter, ollama, or auto")
    ai_model: str | None = None
    ai_api_key: str | None = None
    ai_base_url: str | None = None

class VulnerabilityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    scan_id: str
    title: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    endpoint: str
    method: str = "GET"
    parameter: str | None = None
    description: str
    poc_curl: str = ""
    poc_explanation: str = ""
    request_evidence: str = ""
    response_evidence: str = ""
    remediation_advice: str = ""
    remediation_patch: str | None = None
    verified: bool = True
    confidence: str = Field(default="HIGH", description="Confidence level: CONFIRMED, HIGH, MEDIUM, LOW")
    detection_method: str = Field(default="AUTOMATED_PROBE", description="Method or source of detection")
    affected_asset: str | None = Field(default=None, description="Affected host, asset, or component")
    reproduction_steps: str | None = Field(default=None, description="Step-by-step reproduction guide")
    impact: str | None = Field(default=None, description="Security and business impact assessment")
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    lifecycle_status: str = Field(default="NEW", description="Finding lifecycle status code")
    verification_status: str = Field(default="NEEDS_VALIDATION", description="Independent verification status")
    remediation_status: str = Field(default="OPEN", description="Remediation lifecycle status")
    cvss_version: str = Field(default="3.1", description="CVSS version (e.g. 3.1, 4.0)")
    cve_id: str | None = Field(default=None, description="CVE identifier")
    cisco_sir: str | None = Field(default=None, description="Cisco Security Intelligence Rating")
    epss_score: float | None = Field(default=None, description="EPSS exploit prediction scoring probability")
    cisa_kev: int | None = Field(default=0, description="CISA Known Exploited Vulnerability indicator")
    poc_verification_state: str = Field(default="SCANNER DETECTED", description="PoC verification state badge")
    poc_verification_evidence: str | None = Field(default=None, description="Supporting PoC execution evidence")
    reviewer: str | None = Field(default=None, description="Analyst or agent reviewer")
    false_positive_reason: str | None = Field(default=None, description="Reason if marked false positive")
    last_status_change: str | None = Field(default=None, description="Timestamp of last status transition")

class DiscoveredEndpoint(BaseModel):
    url: str
    method: str = "GET"
    parameters: list[str] = Field(default_factory=list)
    status_code: int | None = None
    content_type: str | None = None
    title: str | None = None
    is_api: bool = False

class ReconResult(BaseModel):
    target: str
    ip_addresses: list[str] = Field(default_factory=list)
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    open_ports: list[dict[str, Any]] = Field(default_factory=list)
    technologies: list[dict[str, str]] = Field(default_factory=list)
    security_headers: dict[str, Any] = Field(default_factory=dict)
    ssl_info: dict[str, Any] = Field(default_factory=dict)
    subdomains: list[dict[str, Any]] = Field(default_factory=list)
    subdomain_metrics: dict[str, Any] = Field(default_factory=lambda: {
        "discovered": 0,
        "resolved": 0,
        "wildcard_filtered": 0,
        "failed_resolution": 0,
        "live_http": 0
    })
    fuzzing_results: list[dict[str, Any]] = Field(default_factory=list)
    fuzzed_parameters: list[dict[str, Any]] = Field(default_factory=list)
    sensitive_files: list[dict[str, Any]] = Field(default_factory=list)

class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:10]}")
    target_url: str
    status: ScanStatus = ScanStatus.PENDING
    profile: ScanProfile = ScanProfile.FULL_RED_TEAM
    progress_percent: int = 0
    current_phase: str = "Initialized"
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    error_message: str | None = None
    config: ScanConfig
    recon_data: ReconResult | None = None
    endpoints_count: int = 0

class LogEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).strftime("%H:%M:%S"))
    scan_id: str
    level: str = "INFO" # INFO, WARN, ERROR, SUCCESS, FINDING, AGENT
    agent: str = "Orchestrator"
    message: str
