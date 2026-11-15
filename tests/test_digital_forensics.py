"""
SNMK Digital Forensics & Data Recovery Test Suite
Tests physical media inspection, PhotoRec file carving station with 'Left ⬅ Back' navigation,
Autopsy case management, ExifTool GPS extraction (zero Cloudinary), and Chain-of-Custody ledger.
"""

import os
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from core.digital_forensics import (
    StorageMediaInspector,
    PhotoRecCarver,
    AutopsyCaseManager,
    ExifToolGpsEngine,
    ChainOfCustodyLedger,
    storage_inspector,
    photorec_carver,
    autopsy_manager,
    exif_engine,
    custody_ledger,
)
from web.server import app

client = TestClient(app)


def test_storage_media_inspector_devices():
    """Verify physical devices and disk images enumeration."""
    devices = storage_inspector.list_devices()
    assert len(devices) >= 1
    d0 = devices[0]
    assert d0.device_id
    assert d0.name
    assert d0.size_bytes > 0
    assert d0.is_read_only is True
    assert d0.partition_scheme in ("GPT", "MBR", "RAW")


def test_storage_media_hasher(tmp_path):
    """Verify SHA-256 and SHA-512 cryptographic hashing of forensic evidence."""
    test_file = tmp_path / "disk_dump.dd"
    test_file.write_bytes(b"FORENSIC_RAW_EVIDENCE_STREAM_BLOCK_DATA_9901")

    hashes = storage_inspector.hash_evidence_file(str(test_file))
    assert "sha256" in hashes
    assert "sha512" in hashes
    assert "md5" in hashes
    assert hashes["size_bytes"] == len(b"FORENSIC_RAW_EVIDENCE_STREAM_BLOCK_DATA_9901")


def test_photorec_directory_navigation():
    """Verify directory browser supports parent path for mandatory 'Left ⬅ Back' navigation."""
    res = photorec_carver.browse_directory(".")
    assert "current_path" in res
    assert "items" in res
    assert "has_parent" in res
    assert isinstance(res["has_parent"], bool)
    if res["has_parent"]:
        assert res["parent_path"] is not None


def test_photorec_carving_lifecycle(tmp_path):
    """Verify carving job creation, status tracking, and cancellation."""
    out_dir = tmp_path / "carve_out"
    job = photorec_carver.start_carving_job(
        source_target="DEV-DISK-001",
        partition_mode="UNALLOCATED",
        file_types=["jpg", "png", "pdf", "sqlite"],
        destination_dir=str(out_dir)
    )
    assert job.job_id.startswith("CARVE-")
    assert job.status in ("RUNNING", "COMPLETED")
    assert job.total_sectors > 0

    status = photorec_carver.get_job(job.job_id)
    assert status is not None
    assert status.job_id == job.job_id

    # Test safe cancellation
    cancelled = photorec_carver.cancel_job(job.job_id)
    assert cancelled is True
    assert photorec_carver.get_job(job.job_id).status == "STOPPED"


def test_autopsy_case_workflows():
    """Verify Autopsy case creation, data source attachment, and ingest pipeline."""
    mgr = AutopsyCaseManager()
    case = mgr.create_case(
        case_name="Breach Analysis Alpha",
        case_number="CASE-TEST-007",
        examiner_name="Senior DFIR Lead",
        description="Forensic investigation test case."
    )
    assert case.case_id.startswith("CASE-")
    assert case.case_number == "CASE-TEST-007"

    # Add forensic image source
    ok = mgr.add_data_source(case.case_id, "evidence_image.e01", "E01_IMAGE", "/evidence/evidence_image.e01")
    assert ok is True
    updated = mgr.get_case(case.case_id)
    assert len(updated.data_sources) == 1

    # Trigger ingest modules
    ingest_ok = mgr.trigger_ingest(case.case_id, ["mod_hash_lookup", "mod_exif"])
    assert ingest_ok is True


def test_exiftool_gps_extraction_and_zero_cloudinary():
    """Verify EXIF metadata parsing, GPS conversion, and verify zero Cloudinary usage."""
    engine = ExifToolGpsEngine()
    sample_bytes = b"\xff\xd8\xff\xe1\x00\x22Exif\x00\x00II*\x00Apple\x00iPhone 15 Pro\x00GPS\x00"
    report = engine.extract_from_bytes(sample_bytes, "suspect_camera_photo.jpg")

    assert report.has_exif is True
    assert report.camera_make == "Apple"
    assert report.has_gps is True
    assert report.gps_latitude is not None
    assert report.gps_longitude is not None
    assert "https://www.google.com/maps" in report.map_url_google
    assert "https://www.openstreetmap.org" in report.map_url_osm
    assert "https://jimpl.com" in report.external_verification_url

    # STRICT POLICY: Verify Cloudinary is completely absent
    report_dict_str = str(report.__dict__).lower()
    assert "cloudinary" not in report_dict_str


def test_chain_of_custody_immutable_ledger(tmp_path):
    """Verify cryptographic chain-of-custody ledger, dual hashing, and integrity verification."""
    ledger_db = str(tmp_path / "test_evidence.db")
    ledger = ChainOfCustodyLedger(db_path=ledger_db)

    evidence_file = tmp_path / "seized_phone_dump.bin"
    evidence_file.write_bytes(b"EVIDENCE_BITS_HASH_VERIFY_9912")

    record = ledger.add_evidence(
        case_id="CASE-2026-001",
        item_name="Seized Android Device Memory Dump",
        item_type="RAW_MEMORY_IMAGE",
        source_device="Pixel 8 Pro",
        examiner_name="Lead Forensic Examiner",
        storage_path=str(evidence_file),
        notes="Chain of custody initiated at seizure scene."
    )

    assert record.record_id.startswith("COC-")
    assert record.sha256_hash
    assert record.sha512_hash
    assert record.md5_hash
    assert record.verification_status == "VERIFIED"

    # Verify integrity check passes
    verif = ledger.verify_integrity(record.record_id, examiner_name="Audit Agent")
    assert verif["verified"] is True
    assert verif["status"] == "VERIFIED"


def test_forensics_rest_api_endpoints():
    """Verify end-to-end HTTP REST API routes for digital forensics."""
    # Devices
    r = client.get("/api/forensics/storage/devices")
    assert r.status_code == 200
    assert r.json()["status"] == "SUCCESS"

    # PhotoRec Directory Browse (Left Back Navigation)
    r = client.get("/api/forensics/photorec/browse")
    assert r.status_code == 200
    assert "browse" in r.json()

    # PhotoRec Signatures
    r = client.get("/api/forensics/photorec/signatures")
    assert r.status_code == 200
    assert "Graphics & Photos" in r.json()["families"]

    # Autopsy Cases
    r = client.get("/api/forensics/autopsy/cases")
    assert r.status_code == 200

    # EXIF Extraction
    r = client.post("/api/forensics/exif/extract", json={})
    assert r.status_code == 200
    assert r.json()["report"]["external_verification_url"] == "https://jimpl.com/"
    assert "cloudinary" not in r.text.lower()

    # Custody Records
    r = client.get("/api/forensics/custody/records")
    assert r.status_code == 200
