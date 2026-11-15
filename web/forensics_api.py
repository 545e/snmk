"""
SNMK Digital Forensics & Data Recovery REST API
Enterprise endpoints for Physical Media, PhotoRec File Carving Station,
Autopsy Case Management, ExifTool GPS Geolocation, and Chain-of-Custody Ledger.

STRICT ENFORCEMENT: Cloudinary is completely forbidden and not integrated.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from core.digital_forensics import (
    storage_inspector,
    photorec_carver,
    autopsy_manager,
    exif_engine,
    custody_ledger,
)

forensics_router = APIRouter(prefix="/api/forensics", tags=["Digital Forensics & Data Recovery"])


# =====================================================================
# REQUEST & RESPONSE SCHEMAS
# =====================================================================

class CarvingStartRequest(BaseModel):
    source_target: str
    partition_mode: str = "WHOLE"  # "WHOLE", "UNALLOCATED"
    file_types: List[str] = Field(default_factory=lambda: ["jpg", "png", "pdf", "docx", "zip", "sqlite"])
    destination_dir: str = "forensics/recovered"


class AutopsyCreateCaseRequest(BaseModel):
    case_name: str
    case_number: str
    examiner_name: str
    description: str = ""


class AutopsyAddDataSourceRequest(BaseModel):
    name: str
    source_type: str = "DISK_IMAGE"  # "E01_IMAGE", "RAW_IMAGE", "MOBILE_BACKUP"
    path: str


class AutopsyIngestRequest(BaseModel):
    modules: List[str] = Field(default_factory=lambda: ["mod_hash_lookup", "mod_file_id", "mod_keyword", "mod_exif"])


class ExifExtractRequest(BaseModel):
    file_path: Optional[str] = None
    file_base64: Optional[str] = None
    filename: Optional[str] = "evidence_image.jpg"


class CustodyAddRequest(BaseModel):
    case_id: str
    item_name: str
    item_type: str
    source_device: str
    examiner_name: str
    storage_path: str
    notes: Optional[str] = ""


class CustodyVerifyRequest(BaseModel):
    examiner_name: str = "Forensic Examiner"


# =====================================================================
# STORAGE MEDIA & DISK IMAGES
# =====================================================================

@forensics_router.get("/storage/devices")
async def list_storage_devices():
    """Enumerate physical hard drives, SSDs, USB media, and registered forensic images."""
    devices = storage_inspector.list_devices()
    return {"status": "SUCCESS", "count": len(devices), "devices": [d.__dict__ for d in devices]}


@forensics_router.post("/storage/hash")
async def hash_evidence_file(file_path: str = Query(...)):
    """Compute forensic SHA-256 and SHA-512 hashes for an evidence file."""
    try:
        res = storage_inspector.hash_evidence_file(file_path)
        return {"status": "SUCCESS", "hashes": res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =====================================================================
# PHOTOREC CARVING STATION (WITH MANDATORY 'LEFT ⬅ BACK' NAVIGATION)
# =====================================================================

@forensics_router.get("/photorec/signatures")
async def get_photorec_signatures():
    """List available file families and signature filters for carving."""
    return {"status": "SUCCESS", "families": photorec_carver.FILE_SIGNATURE_FAMILIES}


@forensics_router.get("/photorec/browse")
async def browse_directory(path: Optional[str] = Query(None)):
    """
    Navigate directory structure for source or destination folders.
    Always includes 'parent_path' and 'has_parent' for 'Left ⬅ Back' navigation.
    """
    res = photorec_carver.browse_directory(path)
    return {"status": "SUCCESS", "browse": res}


@forensics_router.post("/photorec/start")
async def start_photorec_carving(req: CarvingStartRequest):
    """Start background file carving job with live telemetry."""
    job = photorec_carver.start_carving_job(
        source_target=req.source_target,
        partition_mode=req.partition_mode,
        file_types=req.file_types,
        destination_dir=req.destination_dir
    )
    return {"status": "SUCCESS", "job": job.__dict__}


@forensics_router.get("/photorec/status/{job_id}")
async def get_carving_job_status(job_id: str):
    """Get real-time sector scan progress, recovered files breakdown, and logs."""
    job = photorec_carver.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"status": "SUCCESS", "job": job.__dict__}


@forensics_router.post("/photorec/cancel/{job_id}")
async def cancel_carving_job(job_id: str):
    """Safely halt an active carving operation."""
    success = photorec_carver.cancel_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found or already terminated")
    return {"status": "SUCCESS", "message": f"Carving job {job_id} stopped."}


# =====================================================================
# AUTOPSY CASE WORKFLOW & INGEST
# =====================================================================

@forensics_router.get("/autopsy/modules")
async def get_autopsy_modules():
    """Catalog of available Autopsy ingest pipeline modules."""
    return {"status": "SUCCESS", "modules": autopsy_manager.INGEST_MODULES_CATALOG}


@forensics_router.get("/autopsy/cases")
async def list_autopsy_cases():
    """List all registered forensic cases and data sources."""
    cases = autopsy_manager.list_cases()
    return {"status": "SUCCESS", "count": len(cases), "cases": [c.__dict__ for c in cases]}


@forensics_router.post("/autopsy/cases")
async def create_autopsy_case(req: AutopsyCreateCaseRequest):
    """Initialize a new digital forensic case with examiner metadata."""
    case = autopsy_manager.create_case(
        case_name=req.case_name,
        case_number=req.case_number,
        examiner_name=req.examiner_name,
        description=req.description
    )
    return {"status": "SUCCESS", "case": case.__dict__}


@forensics_router.post("/autopsy/cases/{case_id}/datasources")
async def add_autopsy_data_source(case_id: str, req: AutopsyAddDataSourceRequest):
    """Attach a forensic image or disk dump to an existing case."""
    ok = autopsy_manager.add_data_source(case_id, req.name, req.source_type, req.path)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"status": "SUCCESS", "message": f"Data source {req.name} attached to case {case_id}."}


@forensics_router.post("/autopsy/cases/{case_id}/ingest")
async def trigger_autopsy_ingest(case_id: str, req: AutopsyIngestRequest):
    """Run automated artifact extraction and indexing pipeline."""
    ok = autopsy_manager.trigger_ingest(case_id, req.modules)
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"status": "SUCCESS", "message": f"Ingest pipeline triggered for case {case_id}."}


# =====================================================================
# EXIFTOOL & GPS EXTRACTION (ZERO CLOUDINARY)
# =====================================================================

@forensics_router.post("/exif/extract")
async def extract_exif_metadata(req: ExifExtractRequest):
    """
    Extract EXIF tags and GPS coordinates.
    Generates OpenStreetMap/Google Maps links and external Jimpl verification links.
    CLOUDINARY IS PROHIBITED AND NEVER USED.
    """
    try:
        if req.file_base64:
            raw_bytes = base64.b64decode(req.file_base64)
            report = exif_engine.extract_from_bytes(raw_bytes, req.filename or "evidence.jpg")
        elif req.file_path:
            report = exif_engine.extract_from_file(req.file_path)
        else:
            # Provide standard baseline forensic test sample
            sample_bytes = b"\xff\xd8\xff\xe1\x00\x22Exif\x00\x00II*\x00Apple\x00iPhone 15 Pro\x00GPS\x00"
            report = exif_engine.extract_from_bytes(sample_bytes, "forensic_gps_sample.jpg")

        return {"status": "SUCCESS", "report": report.__dict__}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# =====================================================================
# CHAIN OF CUSTODY IMMUTABLE LEDGER
# =====================================================================

@forensics_router.get("/custody/records")
async def list_custody_records(case_id: Optional[str] = Query(None)):
    """List cryptographically sealed chain-of-custody evidence records."""
    records = custody_ledger.list_evidence(case_id)
    return {"status": "SUCCESS", "count": len(records), "records": [r.__dict__ for r in records]}


@forensics_router.post("/custody/records")
async def add_custody_record(req: CustodyAddRequest):
    """Add new evidence item to the immutable forensic ledger with SHA-256 and SHA-512 seal."""
    rec = custody_ledger.add_evidence(
        case_id=req.case_id,
        item_name=req.item_name,
        item_type=req.item_type,
        source_device=req.source_device,
        examiner_name=req.examiner_name,
        storage_path=req.storage_path,
        notes=req.notes or ""
    )
    return {"status": "SUCCESS", "record": rec.__dict__}


@forensics_router.post("/custody/verify/{record_id}")
async def verify_custody_integrity(record_id: str, req: CustodyVerifyRequest):
    """Perform on-demand cryptographic hash reverification against evidence."""
    res = custody_ledger.verify_integrity(record_id, req.examiner_name)
    if res.get("status") == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=res["message"])
    return {"status": "SUCCESS", "verification": res}
