"""
SNMK — Independent PCAP Analyzer & Network Forensics Microservice (Phase 9)
Standalone Service Entrypoint running on port 8002 (or mounted within gateway).
Provides offline packet capture inspection, protocol decoding, flow reconstruction, and anomaly detection.
"""

from __future__ import annotations

import datetime
import os
import shutil
import sys
import tempfile
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, FastAPI, File, HTTPException, Query, Response, UploadFile
from pydantic import BaseModel

# Ensure project root in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from core.alert_manager import alert_manager
from core.database import db
from core.mysql_database import mysql_manager
from services.pcap_service.engine import PcapAnalysisResult, pcap_analyzer

app = FastAPI(
    title="SNMK PCAP Forensics Service",
    description="Independent Deep Packet Inspection & Network Forensics Backend Microservice",
    version="1.0.0"
)

router = APIRouter(prefix="/api/v1/pcap", tags=["PCAP Forensics"])

UPLOAD_STORAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "pcap_uploads"))
os.makedirs(UPLOAD_STORAGE_DIR, exist_ok=True)

# In-memory session cache for fast UI queries
ACTIVE_ANALYSES: Dict[str, PcapAnalysisResult] = {}


# --- Health & Readiness ---

@app.get("/health")
@router.get("/health")
async def pcap_health_check():
    """Independent service health and readiness endpoint."""
    return {
        "service": "snmk-pcap-analyzer",
        "status": "HEALTHY",
        "version": "1.0.0",
        "protocols": ["Ethernet", "IPv4", "IPv6", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"],
        "max_upload_bytes": 50 * 1024 * 1024,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


# --- Endpoints ---

@router.post("/upload")
async def upload_pcap_endpoint(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Uploads and triggers an asynchronous deep packet inspection job on a .pcap or .pcapng file."""
    filename = file.filename or "capture.pcap"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(status_code=400, detail="Invalid file format. Only .pcap, .pcapng, and .cap captures are supported.")

    analysis_id = str(uuid.uuid4())
    job_dir = os.path.join(UPLOAD_STORAGE_DIR, analysis_id)
    os.makedirs(job_dir, exist_ok=True)
    save_path = os.path.join(job_dir, filename)

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Capture file exceeds 50 MB threshold.")

    with open(save_path, "wb") as f:
        f.write(content)

    # Execute in background task
    def _run_analysis():
        try:
            res = pcap_analyzer.analyze_file(save_path)
            res.id = analysis_id
            ACTIVE_ANALYSES[analysis_id] = res

            # Trigger Central Alerts for CRITICAL and HIGH severity findings
            for finding in res.findings:
                if finding.severity in ("CRITICAL", "HIGH"):
                    alert_manager.create_alert(
                        severity=finding.severity,
                        category="SECURITY",
                        title=f"[{finding.severity}] PCAP Forensics: {finding.title}",
                        description=f"{finding.description} Evidence: {finding.evidence}",
                        affected_asset=f"{filename} ({finding.src_endpoint})",
                        correlation_id=analysis_id,
                        remediation=finding.remediation,
                        source="pcap_forensics_service"
                    )
        except Exception as e:
            err_res = PcapAnalysisResult(id=analysis_id, filename=filename, status="FAILED")
            ACTIVE_ANALYSES[analysis_id] = err_res

    background_tasks.add_task(_run_analysis)

    return {
        "success": True,
        "analysis_id": analysis_id,
        "filename": filename,
        "size_bytes": len(content),
        "status": "PROCESSING",
        "message": f"Packet capture '{filename}' submitted for deep packet inspection."
    }


@router.get("/jobs/{job_id}")
async def get_pcap_job_endpoint(job_id: str):
    """Retrieves high-level summary, protocol distribution, and top talkers for an analysis."""
    res = ACTIVE_ANALYSES.get(job_id)
    if not res:
        raise HTTPException(status_code=404, detail="PCAP analysis job not found")
    return res.to_dict(include_packets=False)


@router.get("/jobs/{job_id}/packets")
async def get_pcap_packets_endpoint(
    job_id: str,
    protocol: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Retrieves paginated packet records with optional protocol filter."""
    res = ACTIVE_ANALYSES.get(job_id)
    if not res:
        raise HTTPException(status_code=404, detail="PCAP analysis job not found")

    packets = res.packets
    if protocol:
        packets = [p for p in packets if p.protocol.upper() == protocol.upper()]

    total = len(packets)
    slice_packets = packets[offset : offset + limit]

    return {
        "job_id": job_id,
        "total_packets": total,
        "limit": limit,
        "offset": offset,
        "packets": [p.to_dict() for p in slice_packets]
    }


@router.get("/jobs/{job_id}/flows")
async def get_pcap_flows_endpoint(job_id: str, limit: int = 50):
    """Retrieves bidirectional communication flow records."""
    res = ACTIVE_ANALYSES.get(job_id)
    if not res:
        raise HTTPException(status_code=404, detail="PCAP analysis job not found")
    return {
        "job_id": job_id,
        "total_flows": len(res.flows),
        "flows": [f.to_dict() for f in res.flows[:limit]]
    }


@router.get("/jobs/{job_id}/findings")
async def get_pcap_findings_endpoint(job_id: str):
    """Retrieves all anomaly and threat detection findings."""
    res = ACTIVE_ANALYSES.get(job_id)
    if not res:
        raise HTTPException(status_code=404, detail="PCAP analysis job not found")
    return {
        "job_id": job_id,
        "total_findings": len(res.findings),
        "findings": [f.to_dict() for f in res.findings]
    }


@router.get("/jobs/{job_id}/report")
async def download_pcap_report_endpoint(job_id: str, format: str = Query("html")):
    """Generates and downloads an executive network forensics report in HTML or JSON."""
    res = ACTIVE_ANALYSES.get(job_id)
    if not res:
        raise HTTPException(status_code=404, detail="PCAP analysis job not found")

    if format.lower() == "json":
        import json
        content = json.dumps(res.to_dict(include_packets=True), indent=2)
        return Response(content=content, media_type="application/json", headers={"Content-Disposition": f"attachment; filename=pcap_report_{job_id[:8]}.json"})

    # HTML Report
    findings_html = ""
    for f in res.findings:
        sev_color = "#ef4444" if f.severity in ("CRITICAL", "HIGH") else "#eab308"
        findings_html += f"""
        <div style="border-left: 4px solid {sev_color}; background: #0f172a; padding: 12px; margin-bottom: 10px; border-radius: 6px;">
            <div style="display:flex; justify-content:space-between;">
                <strong><span style="color:{sev_color}">[{f.severity}]</span> {f.title}</strong>
                <span style="font-family:monospace; color:#38bdf8;">{f.protocol}</span>
            </div>
            <p style="color:#cbd5e1; font-size:13px; margin: 6px 0;">{f.description}</p>
            <div style="font-family:monospace; font-size:12px; color:#94a3b8; background:#020617; padding:6px; border-radius:4px;">{f.evidence}</div>
        </div>
        """

    html = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>SNMK PCAP Forensics Report - {res.filename}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; padding: 24px; }}
            .card {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }}
            h1, h2 {{ color: #38bdf8; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>SNMK PCAP Forensics Report</h1>
            <p><strong>Capture:</strong> {res.filename} | <strong>Packets:</strong> {res.total_packets} | <strong>Duration:</strong> {round(res.duration_seconds, 2)}s</p>
            <p><strong>Protocols:</strong> {res.protocol_distribution}</p>
        </div>
        <div class="card">
            <h2>Threat & Anomaly Detections ({len(res.findings)})</h2>
            {findings_html or '<p style="color:#10b981;">No anomalous or malicious traffic patterns detected.</p>'}
        </div>
    </body>
    </html>
    """
    return Response(content=html, media_type="text/html", headers={"Content-Disposition": f"attachment; filename=pcap_report_{job_id[:8]}.html"})


app.include_router(router)
