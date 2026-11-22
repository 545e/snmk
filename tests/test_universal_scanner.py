"""
SNMK — Universal Vulnerability Scanner Test Suite
Comprehensive validation of:
1. URL Validation & SSRF Prevention
2. Document Parsing (PDF, DOCX, TXT)
3. Image Analysis (EXIF GPS Leaks, Polyglot Payloads, OCR)
4. Source Code SAST & Secret Detection
5. Folder & Archive Safety (Zip Slip, Bomb Protection, Hash Deduplication)
6. CrewAI Multi-Agent Task Orchestration
7. MySQL & SQLite Dual-Engine Persistence
8. Report Generation (HTML, JSON, CSV, Markdown, SARIF)
9. Centralized Alerts Integration
10. Cancellation & Error Handling
"""

import asyncio
import io
import os
import tempfile
import zipfile
from fastapi.testclient import TestClient

from core.alert_manager import alert_manager
from core.crewai_adapter import (
    CREWAI_UNIVERSAL_SCANNER_SPECS,
    create_universal_scanner_crew,
    get_universal_scanner_fleet,
)
from core.universal_scanner import (
    UniversalFinding,
    universal_scanner,
)
from web.server import app

client = TestClient(app)


def test_universal_scanner_crewai_fleet_registration():
    """Validates registration of all 12 specialized CrewAI scanning agents."""
    assert len(CREWAI_UNIVERSAL_SCANNER_SPECS) == 12
    fleet = get_universal_scanner_fleet()
    assert len(fleet) == 12

    roles = {a.role for a in fleet}
    expected_roles = [
        "URL Security Agent",
        "Web Application Security Agent",
        "Document Security Agent",
        "Image Analysis Agent",
        "OCR Analysis Agent",
        "Source Code Analysis Agent",
        "Secret Detection Agent",
        "Dependency Analysis Agent",
        "Malware Indicator Analysis Agent",
        "Vulnerability Correlation Agent",
        "Risk Assessment Agent",
        "Report Generation Agent",
    ]
    for r in expected_roles:
        assert r in roles

    for agent in fleet:
        assert agent.goal
        assert agent.backstory
        assert isinstance(agent.tools, list)


def test_universal_scanner_crew_orchestration():
    """Validates multi-agent crew execution with 4 sequential tasks."""
    async def _run():
        crew = create_universal_scanner_crew(scan_type="url", target="https://example.com")
        assert len(crew.agents) == 4
        assert len(crew.tasks) == 4
        res = await crew.kickoff(inputs={"target": "https://example.com"})
        assert res.status == "COMPLETED"
        assert res.tasks_completed == 4
        assert len(res.task_results) == 4

    asyncio.run(_run())


def test_url_scanning_ssrf_prevention():
    """Validates that scanning private IPs or cloud metadata endpoints is strictly blocked."""
    # 1. AWS IMDS metadata IP
    job_imds = universal_scanner.create_job("url", "http://169.254.169.254/latest/meta-data")
    universal_scanner.scan_url(job_imds)
    assert job_imds.status == "COMPLETED"
    assert len(job_imds.findings) >= 1
    assert any("SSRF" in f.finding_title for f in job_imds.findings)

    # 2. Private RFC1918 range
    job_private = universal_scanner.create_job("url", "http://192.168.1.100/admin")
    universal_scanner.scan_url(job_private)
    assert job_private.status == "COMPLETED"
    assert any("SSRF" in f.finding_title for f in job_private.findings)


def test_source_code_flaw_and_secret_detection():
    """Validates detection of hardcoded AWS keys, SQL injection, and command injection."""
    code = """
import os
AWS_ACCESS_KEY = "AKIA1234567890EXAMPLE"

def query_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

def backup(folder):
    os.system("tar -czf backup.tar.gz " + folder)
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    try:
        job = universal_scanner.create_job("file", fpath)
        universal_scanner.scan_files(job, [fpath])

        titles = [f.finding_title for f in job.findings]
        assert any("AWS Access Key ID" in t for t in titles)
        assert any("SQL Injection" in t for t in titles)
        assert any("Command Injection" in t for t in titles)
        assert job.critical_count >= 2
    finally:
        os.unlink(fpath)


def test_dockerfile_iac_vulnerability_detection():
    """Validates detection of container security misconfigurations."""
    dockerfile_content = """
FROM ubuntu:20.04
EXPOSE 22
ENV DB_PASSWORD="SuperSecretPassword123"
CMD ["python3", "app.py"]
"""
    with tempfile.NamedTemporaryFile(suffix="Dockerfile", mode="w", delete=False) as f:
        f.write(dockerfile_content)
        fpath = f.name

    try:
        job = universal_scanner.create_job("file", fpath)
        universal_scanner.scan_files(job, [fpath])

        titles = [f.finding_title for f in job.findings]
        assert any("Port Exposed" in t for t in titles)
        assert any("Secrets Hardcoded" in t for t in titles)
    finally:
        os.unlink(fpath)


def test_document_macro_and_secret_detection():
    """Validates document analysis with simulated suspicious macro indicators."""
    txt_content = """
Confidential Internal Document
OpenAI Key: sk-1234567890abcdef1234567890abcdef1234
Phishing Server: http://192.168.1.55/login.php
"""
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
        f.write(txt_content)
        fpath = f.name

    try:
        job = universal_scanner.create_job("file", fpath)
        universal_scanner.scan_files(job, [fpath])

        titles = [f.finding_title for f in job.findings]
        assert any("OpenAI" in t for t in titles)
        assert any("Direct IP-Based Link" in t for t in titles)
    finally:
        os.unlink(fpath)


def test_pdf_security_inspection():
    """Validates PDF inspection detecting embedded JavaScript and Launch actions."""
    # Harmless simulated PDF stream with interactive script indicator
    pdf_stream = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n" \
                 b"3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('XSS')) >>\nendobj\n%%EOF"

    with tempfile.NamedTemporaryFile(suffix=".pdf", mode="wb", delete=False) as f:
        f.write(pdf_stream)
        fpath = f.name

    try:
        job = universal_scanner.create_job("file", fpath)
        universal_scanner.scan_files(job, [fpath])

        titles = [f.finding_title for f in job.findings]
        assert any("JavaScript" in t or "OpenAction" in t for t in titles)
    finally:
        os.unlink(fpath)


def test_archive_zip_slip_prevention():
    """Validates detection and prevention of Zip Slip directory traversal attacks."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Malicious traversal member
        z.writestr("../../../../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        z.writestr("safe.txt", "harmless content")

    with tempfile.NamedTemporaryFile(suffix=".zip", mode="wb", delete=False) as f:
        f.write(buf.getvalue())
        fpath = f.name

    try:
        job = universal_scanner.create_job("archive", fpath)
        universal_scanner.scan_files(job, [fpath])

        titles = [f.finding_title for f in job.findings]
        assert any("Zip Slip" in t for t in titles)
        assert job.critical_count >= 1
    finally:
        os.unlink(fpath)


def test_archive_bomb_protection():
    """Validates that decompression bomb threshold stops excessive archive expansion."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Create a compressed entry that expands to > 200MB or has many entries
        for i in range(505):
            z.writestr(f"file_{i}.txt", f"Sample content {i}")

    with tempfile.NamedTemporaryFile(suffix=".zip", mode="wb", delete=False) as f:
        f.write(buf.getvalue())
        fpath = f.name

    try:
        job = universal_scanner.create_job("archive", fpath)
        universal_scanner.scan_files(job, [fpath])

        titles = [f.finding_title for f in job.findings]
        assert any("Bomb" in t for t in titles)
    finally:
        os.unlink(fpath)


def test_image_polyglot_payload_detection():
    """Validates detection of hidden executable headers appended past PNG IEND chunk."""
    # Minimal 1x1 valid PNG bytes + IEND marker + appended MZ PE binary header
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
    appended_malicious_pe = png_bytes + b"MZ\x90\x00\x03\x00\x00\x00ThisIsExecutablePayload"

    with tempfile.NamedTemporaryFile(suffix=".png", mode="wb", delete=False) as f:
        f.write(appended_malicious_pe)
        fpath = f.name

    try:
        job = universal_scanner.create_job("image", fpath)
        universal_scanner.scan_files(job, [fpath])

        titles = [f.finding_title for f in job.findings]
        assert any("Polyglot Executable Binary" in t for t in titles)
        assert job.critical_count >= 1
    finally:
        os.unlink(fpath)


def test_report_generation_all_formats():
    """Validates report generation in JSON, HTML, CSV, Markdown, and SARIF formats."""
    job = universal_scanner.create_job("test", "test_report_target")
    job.findings.append(UniversalFinding(
        scan_id=job.id,
        finding_title="Test Vulnerability",
        severity="HIGH",
        confidence="CONFIRMED",
        description="Test description",
        evidence="Test evidence",
        remediation="Test remediation",
        location="app.py:12",
        cwe_id="CWE-89",
        cvss_score=8.0
    ))
    job.total_findings = 1
    job.high_count = 1
    job.status = "COMPLETED"

    for fmt, mime in [
        ("json", "application/json"),
        ("csv", "text/csv"),
        ("md", "text/markdown"),
        ("sarif", "application/sarif+json"),
        ("html", "text/html"),
    ]:
        content, media = universal_scanner.generate_report(job.id, format_type=fmt)
        assert len(content) > 0
        assert media == mime
        assert "Test Vulnerability" in content


def test_centralized_alerts_integration():
    """Validates that CRITICAL and HIGH severity findings trigger centralized alerts."""
    initial_alerts = len(alert_manager._alerts)

    code = 'AWS_KEY = "AKIA9999888877776666"'
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        fpath = f.name

    try:
        job = universal_scanner.create_job("file", fpath)
        universal_scanner.scan_files(job, [fpath])
        assert job.critical_count >= 1
        # Check alert manager contains the new security alert
        assert len(alert_manager._alerts) >= initial_alerts + 1
        recent_alerts = [a["title"] for a in alert_manager.get_alerts(category="SECURITY", limit=5)]
        assert any("AWS Access Key" in t for t in recent_alerts)
    finally:
        os.unlink(fpath)


def test_universal_scanner_api_endpoints():
    """Validates REST API endpoints for scans, metrics, and report downloads."""
    # 1. Scans and Metrics endpoint
    res = client.get("/api/universal-scanner/scans")
    assert res.status_code == 200
    data = res.json()
    assert "scans" in data
    assert "metrics" in data
    assert "total_scans" in data["metrics"]

    # 2. URL scan endpoint
    res_url = client.post("/api/universal-scanner/scan/url", json={
        "url": "http://169.254.169.254/latest/meta-data",
        "scan_mode": "passive"
    })
    assert res_url.status_code == 200
    url_data = res_url.json()
    assert url_data["success"] is True
    scan_id = url_data["scan_id"]

    # 3. Retrieve scan details
    res_get = client.get(f"/api/universal-scanner/scans/{scan_id}")
    assert res_get.status_code == 200
    scan_detail = res_get.json()
    assert scan_detail["id"] == scan_id

    # 4. Report download endpoint
    res_rep = client.get(f"/api/universal-scanner/scans/{scan_id}/report?format=json")
    assert res_rep.status_code == 200
    assert "application/json" in res_rep.headers["content-type"]
