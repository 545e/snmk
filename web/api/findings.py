"""
SNMK Vulnerability Findings, Lifecycle Triage, and Verification API Router
Handles vulnerability querying, CVSS metrics, false-positive auditing, and status transitions.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from core.database import db

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
    response: Response,
    scan_id: Optional[str] = None,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    lifecycle_status: Optional[str] = None,
    remediation_status: Optional[str] = None,
    poc_state: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "cvss_score",
    sort_order: str = "desc",
    paged: bool = False,
) -> Any:
    """Retrieve vulnerability findings with multi-dimensional filtering, pagination, and sorting."""
    if not (search or severity or lifecycle_status or remediation_status or poc_state or paged or offset > 0 or limit != 100):
        findings = db.list_findings(scan_id=scan_id)
        response.headers["X-Total-Count"] = str(len(findings))
        return findings

    items, total = db.list_findings_advanced(
        search=search,
        severity=severity,
        lifecycle_status=lifecycle_status,
        remediation_status=remediation_status,
        poc_state=poc_state,
        scan_id=scan_id,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    response.headers["X-Total-Count"] = str(total)
    if paged:
        return {
            "items": [item.model_dump() if hasattr(item, "model_dump") else (item.dict() if hasattr(item, "dict") else dict(item)) for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    return items


@router.get("/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    """Retrieve full details, CVSS vector, evidence payload, and remediation guidance for a finding."""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    data = finding.model_dump() if hasattr(finding, "model_dump") else (finding.dict() if hasattr(finding, "dict") else dict(finding))
    data["history"] = db.get_finding_status_history(finding_id)
    return data


@router.post("/{finding_id}/transition")
async def transition_finding_state(finding_id: str, req: FindingTransitionRequest) -> dict[str, Any]:
    """Transition a finding's lifecycle status or remediation status with auditable tracking."""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    updated = False
    if req.status:
        updated = db.transition_finding_status(
            finding_id=finding_id,
            new_status=req.status,
            status_type="LIFECYCLE",
            actor=req.operator,
            reason=req.notes or "",
        )
    if req.remediation_status:
        updated = db.transition_finding_status(
            finding_id=finding_id,
            new_status=req.remediation_status,
            status_type="REMEDIATION",
            actor=req.operator,
            reason=req.notes or "",
        )
    return {"status": "success", "finding_id": finding_id, "updated": updated}


@router.post("/{finding_id}/false-positive")
async def mark_false_positive(finding_id: str, req: FalsePositiveRequest) -> dict[str, Any]:
    """Flag a finding as a verified false positive with documented justification."""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

    success, msg = db.review_false_positive(
        finding_id=finding_id,
        reason=req.reason,
        reviewed_by=req.operator or "Senior Security Analyst",
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "finding_id": finding_id, "marked_false_positive": True}


@router.get("/{finding_id}/history")
async def get_finding_history(finding_id: str) -> dict[str, Any]:
    """Retrieve immutable audit log of status changes and verification notes for a finding."""
    history = db.get_finding_status_history(finding_id)
    return {"finding_id": finding_id, "history": history}
