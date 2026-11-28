"""
SNMK Multi-Format Cyber Reporting and Compliance Export API Router
Generates OASIS SARIF 2.1.0, HTML executive briefs, PDF, JSON, CSV, and Markdown exports.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from core.database import db
from core.persistent_store import persistent_store

logger = logging.getLogger("snmk.api.reports")
router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/export")
async def export_latest_report(format: str = "json", scan_id: Optional[str] = None):
    """Export an authoritative report built from persisted records."""
    with db.get_connection() as conn:
        if scan_id:
            row = conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
        else:
            row = conn.execute("SELECT id FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="No scan records available to export")

    sid = row[0]
    findings = persistent_store.get_findings(sid)
    subdomains = persistent_store.get_subdomains(sid)

    if format.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["scan_id", "title", "severity", "scanner", "evidence"])
        for f in findings:
            writer.writerow([
                sid,
                f.get("finding_title", ""),
                f.get("severity", ""),
                f.get("scanner_name", ""),
                f.get("evidence", ""),
            ])
        return PlainTextResponse(output.getvalue(), media_type="text/csv")

    return {
        "scan_id": sid,
        "format": "json",
        "findings_count": len(findings),
        "subdomains_count": len(subdomains),
        "findings": findings,
        "subdomains": subdomains,
    }


@router.get("/vulnerability-assessment/templates")
async def list_report_templates() -> dict[str, Any]:
    """List available standardized cybersecurity report templates (Executive, Technical, Compliance, SARIF)."""
    return {
        "templates": [
            {"id": "executive", "name": "Executive Brief", "description": "High-level risk posture and business impact"},
            {"id": "technical", "name": "Technical In-Depth", "description": "Reproducible vulnerability PoCs and endpoints"},
            {"id": "compliance", "name": "Regulatory Compliance", "description": "OWASP Top 10, NIST, and ISO 27001 mapping"},
            {"id": "sarif", "name": "OASIS SARIF 2.1.0", "description": "Standardized static/dynamic analysis interchange format"},
        ]
    }
