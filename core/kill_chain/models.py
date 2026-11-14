"""
SWA AI — Cyber Kill Chain Data Models & Schemas
Enterprise-grade data models adhering to the Lockheed Martin Cyber Kill Chain and MITRE ATT&CK frameworks.
"""

from __future__ import annotations

import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class KillChainStageEnum(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "c2"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class StageStatusEnum(str, Enum):
    CRITICAL = "CRITICAL"      # Red
    HIGH = "HIGH"              # Orange
    MEDIUM = "MEDIUM"          # Yellow
    LOW = "LOW"                # Blue
    PROTECTED = "PROTECTED"    # Green
    NOT_ASSESSED = "NOT_ASSESSED"  # Grey


class ConfidenceLevelEnum(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    NOT_ASSESSED = "NOT_ASSESSED"


class IncidentStatusEnum(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    CONTAINED = "CONTAINED"
    REMEDIATED = "REMEDIATED"
    CLOSED = "CLOSED"


class ControlCapabilityEnum(str, Enum):
    DETECT = "Detect"
    DENY = "Deny"
    DISRUPT = "Disrupt"
    DEGRADE = "Degrade"
    DECEIVE = "Deceive"


class ControlStatusEnum(str, Enum):
    IMPLEMENTED = "IMPLEMENTED"
    VERIFIED = "VERIFIED"
    MISSING = "MISSING"
    UNVERIFIED = "UNVERIFIED"


class EvidenceItem(BaseModel):
    id: str
    stage: KillChainStageEnum
    artifact_type: str
    raw_data: str
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    source_tool: str = "SWA Core Scanner"
    affected_asset: str = "unknown"
    observed_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    evidence_hash: str | None = None
    confidence_level: ConfidenceLevelEnum = ConfidenceLevelEnum.SUSPECTED
    confidence_score: float = 75.0
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class ThreatIndicator(BaseModel):
    id: str
    indicator_type: str  # IP, DOMAIN, URL, MD5, SHA256, CVE
    value: str
    stage: KillChainStageEnum
    threat_actor: str | None = None
    malware_family: str | None = None
    reputation_score: float = 0.0  # 0.0 safe, 100.0 malicious
    provider: str = "Internal Intelligence"
    source_attribution: str = "Local Engine"
    verified: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
    first_seen: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    last_checked: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class KillChainFinding(BaseModel):
    id: str
    title: str
    stage: KillChainStageEnum
    severity: SeverityEnum = SeverityEnum.MEDIUM
    cve: str | None = None
    cwe: str | None = None
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None
    affected_host: str = "127.0.0.1"
    affected_endpoint: str | None = None
    http_status_code: int | None = None
    description: str = ""
    evidence: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    detection_source: str = "SWA Detection Engine"
    first_observed: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    last_observed: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    confidence_level: ConfidenceLevelEnum = ConfidenceLevelEnum.CONFIRMED
    confidence_score: float = 85.0  # 0.0 to 100.0 based on evidence quality & corroboration
    risk_score: float = 65.0        # 0.0 to 100.0 based on impact, asset criticality, exposure
    remediation: str = "Apply defense-in-depth security controls."
    references: list[str] = Field(default_factory=list)
    status: str = "OPEN"
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class StageAnalysisResult(BaseModel):
    stage: KillChainStageEnum
    status: StageStatusEnum = StageStatusEnum.NOT_ASSESSED
    score: float = 0.0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list[KillChainFinding] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    indicators: list[ThreatIndicator] = Field(default_factory=list)
    associated_assets: list[str] = Field(default_factory=list)
    security_controls: list[dict[str, Any]] = Field(default_factory=list)
    recommended_remediations: list[str] = Field(default_factory=list)
    summary: str = ""
    assessed_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class CorrelatedAttackPath(BaseModel):
    path_id: str
    target_asset: str
    stages_detected: list[KillChainStageEnum]
    progression_percentage: float  # e.g. 71.4% (5 of 7 stages)
    correlated_findings: list[str]
    root_cause_stage: KillChainStageEnum
    highest_severity: SeverityEnum
    composite_risk_score: float
    confidence_score: float
    attack_vector_summary: str
    mitre_chain: list[dict[str, str]]
    first_event_at: str
    latest_event_at: str


class SecurityControl(BaseModel):
    id: str
    stage: KillChainStageEnum
    name: str
    capability: ControlCapabilityEnum
    status: ControlStatusEnum = ControlStatusEnum.UNVERIFIED
    tool_mapping: str = ""
    description: str = ""
    last_verified_at: str | None = None
    coverage_score: float = 0.0


class IncidentRecord(BaseModel):
    id: str
    title: str
    severity: SeverityEnum = SeverityEnum.HIGH
    status: IncidentStatusEnum = IncidentStatusEnum.NEW
    assigned_analyst: str = "SecOps Lead"
    affected_assets: list[str] = Field(default_factory=list)
    description: str = ""
    stages_involved: list[KillChainStageEnum] = Field(default_factory=list)
    linked_findings: list[str] = Field(default_factory=list)
    linked_evidence: list[str] = Field(default_factory=list)
    attack_path_id: str | None = None
    containment_recommendations: list[str] = Field(default_factory=list)
    containment_actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    remediation_notes: str = ""
    audit_trail: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class KillChainOverview(BaseModel):
    total_findings: int = 0
    total_evidence_count: int = 0
    active_incidents_count: int = 0
    overall_risk_score: float = 0.0
    overall_confidence_score: float = 0.0
    stage_summaries: dict[str, dict[str, Any]] = Field(default_factory=dict)
    control_coverage_percentage: float = 0.0
    attack_paths: list[CorrelatedAttackPath] = Field(default_factory=list)
    system_health: dict[str, Any] = Field(default_factory=dict)
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
