"""
SNMK Scan Lifecycle Management API Router
Handles scan initiation, status checks, task cancellations, and historical comparisons.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.database import db
from core.models import ScanJob, ScanStatus, VulnerabilityFinding, LogEvent
from core.queue_manager import queue_manager

logger = logging.getLogger("snmk.api.scans")
router = APIRouter(prefix="/scans", tags=["scans"])


class CompareScansRequest(BaseModel):
    base_scan_id: str
    target_scan_id: str


@router.get("", response_model=list[ScanJob])
async def list_scans():
    """List all scans with status, duration, and finding counts, reconciling dead in-memory tasks."""
    scans = db.list_scans()
    active_ids = set(queue_manager.active_tasks.keys())
    for s in scans:
        if s.status == ScanStatus.RUNNING and s.id not in active_ids:
            s.status = ScanStatus.FAILED
            db.update_scan_status(s.id, ScanStatus.FAILED)
    return scans


@router.get("/{scan_id}", response_model=ScanJob)
async def get_scan(scan_id: str):
    """Get scan details, progress, and reconnaissance summary."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel an active background scan or reconcile an orphaned scan."""
    success = queue_manager.cancel_scan(scan_id)
    if not success:
        scan = db.get_scan(scan_id)
        if scan and scan.status == ScanStatus.RUNNING:
            db.update_scan_status(scan_id, ScanStatus.CANCELLED)
            return {"status": "reconciled", "scan_id": scan_id}
        raise HTTPException(status_code=404, detail="Scan not active or not found")
    db.update_scan_status(scan_id, ScanStatus.CANCELLED)
    return {"status": "cancelled", "scan_id": scan_id}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan record and its associated findings and logs."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    queue_manager.cancel_scan(scan_id)
    db.delete_scan(scan_id)
    return {"status": "deleted", "scan_id": scan_id}


@router.get("/{scan_id}/findings", response_model=list[VulnerabilityFinding])
async def get_scan_findings(scan_id: str):
    """Get all findings associated with a specific scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return db.get_findings(scan_id)


@router.get("/{scan_id}/logs", response_model=list[LogEvent])
async def get_scan_logs(scan_id: str):
    """Get all execution logs for a specific scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return db.get_logs(scan_id)


@router.post("/compare")
async def compare_scans(req: CompareScansRequest):
    """Compares two historical scans, calculating new vs resolved findings and score delta."""
    base_scan = db.get_scan(req.base_scan_id)
    target_scan = db.get_scan(req.target_scan_id)
    if not base_scan or not target_scan:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    base_findings = {f.title: f for f in db.get_findings(req.base_scan_id)}
    target_findings = {f.title: f for f in db.get_findings(req.target_scan_id)}

    new_findings = [f for t, f in target_findings.items() if t not in base_findings]
    resolved_findings = [f for t, f in base_findings.items() if t not in target_findings]
    persistent_findings = [f for t, f in target_findings.items() if t in base_findings]

    return {
        "base_scan_id": req.base_scan_id,
        "target_scan_id": req.target_scan_id,
        "new_findings_count": len(new_findings),
        "resolved_findings_count": len(resolved_findings),
        "persistent_findings_count": len(persistent_findings),
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
    }
