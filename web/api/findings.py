"""
SNMK Vulnerability Findings, Lifecycle Triage, and Verification API Router
Handles vulnerability querying, CVSS metrics, false-positive auditing, and status transitions.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.database import db
from core.models import Severity, VulnerabilityFinding
from core.error_sanitizer import safe_error

logger = logging.getLogger("snmk.api.findings")
router = APIRouter(prefix="/findings", tags=["findings"])


class FindingTransitionRequest(BaseModel):
    status: Optional[str] = None
    remediation_status: Optional[str] = None
    notes: Optional[str] = None
    operator: str = "security_lead"


class FalsePositiveRequest(BaseModel):
    reason: str
    operator: str = "security_lead"


@router.get("/metrics")
async def get_findings_metrics() -> dict[str, Any]:
    """Returns 10-card summary counts, severity distribution, and status lifecycle counts."""
    return db.get_finding_metrics()


@router.get("")
async def list_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """List vulnerability findings with filtering by scan, severity, and remediation status."""
    findings = db.get_findings(scan_id=scan_id) if scan_id else db.list_all_findings()
    if severity:
        findings = [f for f in findings if (getattr(f, "severity", "") or "").upper() == severity.upper()]
    if status:
        findings = [f for f in findings if (getattr(f, "status", "") or "").upper() == status.upper()]

    total = len(findings)
    paged = findings[offset : offset + limit]
    return {
        "total": total,
        "count": len(paged),
        "limit": limit,
        "offset": offset,
        "findings": [f.dict() if hasattr(f, "dict") else dict(f) for f in paged],
    }


@router.get("/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    """Retrieve full details, CVSS vector, evidence payload, and remediation guidance for a finding."""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return finding.dict() if hasattr(finding, "dict") else dict(finding)


@router.post("/{finding_id}/transition")
async def transition_finding_state(finding_id: str, req: FindingTransitionRequest) -> dict[str, Any]:
    """Transition a finding's lifecycle status or remediation status with auditable tracking."""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    updated = db.transition_finding_status(
        finding_id=finding_id,
        new_status=req.status,
        remediation_status=req.remediation_status,
        operator=req.operator,
        notes=req.notes,
    )
    return {"status": "success", "finding_id": finding_id, "updated": updated}


@router.post("/{finding_id}/false-positive")
async def mark_false_positive(finding_id: str, req: FalsePositiveRequest) -> dict[str, Any]:
    """Flag a finding as a verified false positive with documented justification."""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    db.mark_finding_false_positive(
        finding_id=finding_id,
        reason=req.reason,
        operator=req.operator,
    )
    return {"status": "success", "finding_id": finding_id, "marked_false_positive": True}


@router.get("/{finding_id}/history")
async def get_finding_history(finding_id: str) -> dict[str, Any]:
    """Retrieve immutable audit log of status changes and verification notes for a finding."""
    history = db.get_finding_status_history(finding_id)
    return {"finding_id": finding_id, "history": history}
