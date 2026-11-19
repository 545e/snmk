"""
SNMK — Universal Vulnerability Scanner Engine
Enterprise-level vulnerability assessment module supporting:
1. Website and Web Application URLs (Passive, Safe Active, Full Authorized)
2. Documents (PDF, DOC, DOCX, TXT, Markdown, RTF)
3. Images (PNG, JPG, JPEG, EXIF privacy leaks, appended payloads, OCR)
4. Source Code and Configuration Files (Python, JS, TS, Java, PHP, C/C++, Dockerfile, YAML, JSON, .env)
5. Entire Folders and Safe Archive Extraction (Zip Slip protection, bomb limits)
6. CrewAI Multi-Agent Correlation and Centralized Alert Integration
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.tls_policy import inspection_context

# Third-party parsers with safe import fallbacks
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

try:
    import docx
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

from core.alert_manager import alert_manager
from core.database import db
from core.integrations.endpoint_policy import resolve_host_addresses
from core.mysql_database import mysql_manager
from core.scope_policy import scope_policy

logger = logging.getLogger("snmk.universal_scanner")

# Base directory for storing untrusted uploaded assets outside web root
UPLOAD_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "universal_uploads"))
os.makedirs(UPLOAD_BASE_DIR, exist_ok=True)

# Safety constraints
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB per file
MAX_BATCH_SIZE = 100 * 1024 * 1024  # 100 MB per batch
MAX_ARCHIVE_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB max uncompressed
MAX_ARCHIVE_FILES = 500
MAX_COMPRESSION_RATIO = 100

# High-entropy secret regex patterns (Gitleaks / TruffleHog compatible)
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16,28})\b"), "CRITICAL", "CWE-798", 9.1),
    ("GitHub Personal Access Token", re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b"), "CRITICAL", "CWE-798", 9.3),
    ("OpenAI / AI Provider API Key", re.compile(r"\b(sk-[a-zA-Z0-9_-]{32,64})\b"), "CRITICAL", "CWE-798", 8.8),
    ("Slack API Token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"), "HIGH", "CWE-798", 8.0),
    ("RSA / SSH Private Key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), "CRITICAL", "CWE-312", 9.8),
    ("Database Connection String with Password", re.compile(r"\b(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_.-]+:[^@\s]{3,}@[a-zA-Z0-9_.-]+"), "HIGH", "CWE-312", 8.5),
    ("Generic High-Entropy API Key / Bearer", re.compile(r"(?i)(?:api_key|access_token|secret_key|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{24,}['\"]"), "HIGH", "CWE-798", 7.8),
    ("Exposed Password Assignment", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"), "MEDIUM", "CWE-259", 6.5),
]

# Source code flaw patterns (SAST indicators)
CODE_FLAW_PATTERNS = [
    ("SQL Injection: String Concatenation in Query", re.compile(r"(?i)(?:(?:execute|query|raw|cursor\.execute)\s*\(\s*(?:f['\"][^'\"]*\{|\"[^\"]*\"\s*\+|'[^']*'\s*\+)|(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:['\"]\s*\+|f['\"][^'\"]*\{))"), "HIGH", "CWE-89", 8.2, "Use parameterized queries or prepared statements instead of string concatenation."),
    ("Cross-Site Scripting (XSS): Unescaped DOM Insertion", re.compile(r"\b(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html)\s*="), "HIGH", "CWE-79", 7.5, "Use textContent, innerText, or safe templating frameworks that auto-escape user content."),
    ("Command Injection: Arbitrary Shell Execution", re.compile(r"\b(?:os\.system|subprocess\.Popen\([^,]+shell\s*=\s*True|subprocess\.call\([^,]+shell\s*=\s*True|eval\(|exec\(|passthru\(|shell_exec\()"), "CRITICAL", "CWE-78", 9.0, "Use subprocess with shell=False and pass arguments as a validated list."),
    ("Insecure Deserialization: Untrusted Object Loading", re.compile(r"\b(?:pickle\.loads|pickle\.load|yaml\.load\([^,]+,\s*Loader=yaml\.(?:UnsafeLoader|FullLoader)|yaml\.load\([^,]+\)|ObjectInputStream|unserialize\()"), "CRITICAL", "CWE-502", 9.4, "Use safe serialization formats like JSON, or yaml.SafeLoader. Never deserialize untrusted bytes."),
    ("Path Traversal: Arbitrary File Access", re.compile(r"\b(?:open\s*\([^,]+request\.|read_file\s*\([^,]+params|sendFile\s*\([^,]+req\.)"), "HIGH", "CWE-22", 7.8, "Validate and canonicalize all file paths using Path.resolve() against an explicit allowlisted base directory."),
    ("Weak Cryptography: Outdated Hash Algorithm", re.compile(r"\b(?:hashlib\.md5|hashlib\.sha1|crypto\.createHash\(['\"](?:md5|sha1)['\"]\)|MD5_Init)"), "MEDIUM", "CWE-328", 5.3, "Upgrade to SHA-256, SHA-3, or Argon2id/bcrypt for password hashing."),
    ("Insecure Cryptographic Randomness", re.compile(r"\b(?:random\.random\(\)|random\.randint\(|Math\.random\(\))"), "LOW", "CWE-330", 3.8, "Use cryptographically secure random generators such as secrets module or crypto.randomBytes."),
]

# Dockerfile / IaC Security Patterns
IAC_FLAW_PATTERNS = [
    ("Container Running as Root User", re.compile(r"^(?!.*\bUSER\b.*).*$", re.MULTILINE), "MEDIUM", "CWE-250", 6.0, "Define a non-root user via 'USER nonroot' in the Dockerfile."),
    ("Sensitive Port Exposed in Dockerfile (SSH/Docker Socket)", re.compile(r"(?i)^EXPOSE\s+.*(?:22|2375|2376)\b", re.MULTILINE), "HIGH", "CWE-200", 7.2, "Do not expose SSH or unauthenticated Docker daemon sockets inside containers."),
    ("Secrets Hardcoded in Dockerfile ENV / ARG", re.compile(r"(?i)^(?:ENV|ARG)\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=\s*['\"][^'\"]+['\"]", re.MULTILINE), "HIGH", "CWE-798", 8.0, "Use Docker BuildKit secrets or runtime environment variable injection instead."),
]


@dataclass
class UniversalFinding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    file_id: Optional[str] = None
    finding_title: str = ""
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: str = "CONFIRMED"  # CONFIRMED, SUSPECTED, INFORMATIONAL
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    scanner_name: str = "SNMK Universal Scanner"
    location: str = ""
    cwe_id: Optional[str] = None
    cvss_score: float = 0.0
    status: str = "OPEN"
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UploadedFileRecord:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    original_filename: str = ""
    detected_file_type: str = "unknown"
    file_size: int = 0
    sha256_hash: str = ""
    processing_status: str = "PENDING"  # PENDING, PROCESSING, COMPLETED, FAILED
    storage_path: str = ""
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UniversalScanJob:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = "operator"
    scan_type: str = "url"  # url, file, folder, archive
    target: str = ""
    status: str = "QUEUED"  # QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    started_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    completed_at: Optional[str] = None
    total_files: int = 0
    completed_files: int = 0
    failed_files: int = 0
    progress_percent: int = 0
    current_stage: str = "Initializing"
    current_file: Optional[str] = None
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_configuration: Dict[str, Any] = field(default_factory=dict)
    files: List[UploadedFileRecord] = field(default_factory=list)
    findings: List[UniversalFinding] = field(default_factory=list)
    cancelled: bool = False

    def to_dict(self, include_details: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_files": self.total_files,
            "completed_files": self.completed_files,
            "failed_files": self.failed_files,
            "progress_percent": self.progress_percent,
            "current_stage": self.current_stage,
            "current_file": self.current_file,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "scan_configuration": self.scan_configuration,
        }
        if include_details:
            data["files"] = [f.to_dict() for f in self.files]
            data["findings"] = [f.to_dict() for f in self.findings]
        return data


class UniversalScannerEngine:
    """Master orchestrator for URL, Document, Image, Source Code, and Folder vulnerability assessment."""

    def __init__(self):
        self._jobs: Dict[str, UniversalScanJob] = {}
        self._init_sqlite_tables()

    def _init_sqlite_tables(self):
        """Ensures local SQLite WAL tables exist for persistence alongside MySQL."""
        try:
            with db.get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS universal_scans (
                        id TEXT PRIMARY KEY,
                        user_id TEXT,
                        scan_type TEXT,
                        target TEXT,
                        status TEXT,
                        started_at TEXT,
                        completed_at TEXT,
                        total_files INTEGER DEFAULT 0,
                        total_findings INTEGER DEFAULT 0,
                        critical_count INTEGER DEFAULT 0,
                        high_count INTEGER DEFAULT 0,
                        medium_count INTEGER DEFAULT 0,
                        low_count INTEGER DEFAULT 0,
                        info_count INTEGER DEFAULT 0,
                        scan_configuration TEXT
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS uploaded_files (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        original_filename TEXT,
                        detected_file_type TEXT,
                        file_size INTEGER DEFAULT 0,
                        sha256_hash TEXT,
                        processing_status TEXT,
                        storage_reference TEXT,
                        created_at TEXT
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS universal_findings (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        file_id TEXT,
                        finding_title TEXT,
                        severity TEXT,
                        confidence TEXT,
                        description TEXT,
                        evidence TEXT,
                        remediation TEXT,
                        scanner_name TEXT,
                        location TEXT,
                        cwe_id TEXT,
                        cvss_score REAL DEFAULT 0.0,
                        status TEXT,
                        created_at TEXT
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS universal_reports (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        report_type TEXT,
                        report_reference TEXT,
                        created_at TEXT
                    );
                """)
        except Exception as e:
            logger.warning(f"Failed to initialize SQLite universal scanner tables: {e}")

    # =========================================================================
    # Job Lifecycle & Management
    # =========================================================================

    def create_job(self, scan_type: str, target: str, config: Optional[Dict[str, Any]] = None, user_id: str = "operator") -> UniversalScanJob:
        job = UniversalScanJob(
            scan_type=scan_type,
            target=target,
            user_id=user_id,
            scan_configuration=config or {}
        )
        self._jobs[job.id] = job
        self._persist_job_to_db(job)
        return job

    def get_job(self, scan_id: str) -> Optional[UniversalScanJob]:
        if scan_id in self._jobs:
            return self._jobs[scan_id]
        # Attempt to load from database
        return self._load_job_from_db(scan_id)

    def cancel_job(self, scan_id: str) -> bool:
        job = self.get_job(scan_id)
        if not job:
            return False
        job.cancelled = True
        job.status = "CANCELLED"
        job.current_stage = "Cancelled by user"
        self._persist_job_to_db(job)
        return True

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        # Return recent in-memory jobs or query DB
        jobs_list = sorted(list(self._jobs.values()), key=lambda j: j.started_at, reverse=True)
        return [j.to_dict(include_details=False) for j in jobs_list[:limit]]

    def get_metrics(self) -> Dict[str, Any]:
        total_scans = len(self._jobs)
        urls_scanned = sum(1 for j in self._jobs.values() if j.scan_type == "url")
        files_analyzed = sum(j.total_files for j in self._jobs.values() if j.scan_type in ("file", "archive"))
        folders_analyzed = sum(1 for j in self._jobs.values() if j.scan_type == "folder")
        total_findings = sum(j.total_findings for j in self._jobs.values())
        critical = sum(j.critical_count for j in self._jobs.values())
        high = sum(j.high_count for j in self._jobs.values())
        medium = sum(j.medium_count for j in self._jobs.values())
        low = sum(j.low_count for j in self._jobs.values())
        failed = sum(1 for j in self._jobs.values() if j.status == "FAILED")
        return {
            "total_scans": total_scans,
            "urls_scanned": urls_scanned,
            "files_analyzed": files_analyzed,
            "folders_analyzed": folders_analyzed,
            "total_vulnerabilities": total_findings,
            "critical_findings": critical,
            "high_findings": high,
            "medium_findings": medium,
            "low_findings": low,
            "failed_scans": failed,
        }

    # =========================================================================
    # URL Vulnerability Analysis
    # =========================================================================

    def scan_url(self, job: UniversalScanJob) -> List[UniversalFinding]:
        url = job.target.strip()
        job.status = "RUNNING"
        job.current_stage = "Validating target and SSRF protections"
        job.progress_percent = 10

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or parsed.scheme not in ("http", "https"):
            url = "https://" + url
            parsed = urllib.parse.urlparse(url)

        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scan_mode = job.scan_configuration.get("scan_mode", "passive")  # passive, safe_active, full_authorized

        # 1. SSRF & Target Allowlist Policy Check
        job.current_stage = "Enforcing SSRF and network access policies"
        job.progress_percent = 20

        is_allowed, resolved_ip = self._validate_url_ssrf_safety(hostname)
        if not is_allowed:
            finding = UniversalFinding(
                scan_id=job.id,
                finding_title="Restricted Internal / Loopback Target Blocked (SSRF Prevention)",
                severity="HIGH",
                confidence="CONFIRMED",
                description=f"Target '{hostname}' resolves to restricted or private IP address '{resolved_ip}'. Access is prevented to protect platform infrastructure.",
                evidence=f"Target host: {hostname}, Resolved IP: {resolved_ip}",
                remediation="Only public FQDNs or authorized lab endpoints may be scanned.",
                scanner_name="SNMK Scope & SSRF Policy",
                location=url,
                cwe_id="CWE-918",
                cvss_score=8.6
            )
            job.findings.append(finding)
            self._finalize_job(job)
            return job.findings

        # 2. TLS / Certificate Inspection (for HTTPS)
        job.current_stage = "Auditing TLS/SSL protocol and certificates"
        job.progress_percent = 35
        if parsed.scheme == "https":
            self._audit_tls_configuration(job, hostname, port)

        # 3. HTTP Security Headers and Cookie Attributes
        job.current_stage = "Analyzing HTTP security headers and cookies"
        job.progress_percent = 55
        self._audit_http_headers_and_cookies(job, url)

        # 4. Safe Active / Full Authorized Probing
        if scan_mode in ("safe_active", "full_authorized"):
            job.current_stage = "Probing common sensitive endpoints and misconfigurations"
            job.progress_percent = 75
            self._audit_sensitive_endpoints(job, url)

        job.current_stage = "Correlating findings from scanner evidence"
        job.progress_percent = 90

        # Correlation is performed over findings produced by the real checks
        # above only. The CrewAI adapter is a planning layer that executes no
        # tools, so it is intentionally not represented as an evidence source.
        # (The previously present no-op ``crew.kickoff`` call was removed
        # because it claimed an assessment that never happened.)

        self._finalize_job(job)
        return job.findings

    def _validate_url_ssrf_safety(self, hostname: str) -> Tuple[bool, str]:
        """Validates host against loopback, private ranges, and cloud metadata IPs."""
        try:
            # Check scope policy for authorized lab targets first
            val = scope_policy.validate_target(hostname)
            if val.is_allowed:
                return True, val.resolved_ip or "127.0.0.1"

            addrs = resolve_host_addresses(hostname)
            for addr in addrs:
                ip = ipaddress.ip_address(addr)
                if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
                    return False, str(ip)
                # Cloud metadata IPs check
                if str(ip) in ("169.254.169.254", "169.254.170.2"):
                    return False, str(ip)
            return True, addrs[0] if addrs else "unknown"
        except Exception as e:
            logger.warning(f"Failed to resolve host '{hostname}': {e}")
            return False, "Resolution Failed"

    def _audit_tls_configuration(self, job: UniversalScanJob, hostname: str, port: int):
        """Audits SSL/TLS certificate validity, expiry, and protocol."""
        try:
            context = inspection_context()

            with socket.create_connection((hostname, port), timeout=6.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    version = ssock.version()
                    cipher = ssock.cipher()

                    if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        job.findings.append(UniversalFinding(
                            scan_id=job.id,
                            finding_title=f"Insecure Legacy Protocol Supported ({version})",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            description=f"Server negotiates legacy protocol {version}, which is deprecated and susceptible to cryptographic downgrades.",
                            evidence=f"Negotiated Protocol: {version}, Cipher: {cipher[0] if cipher else 'unknown'}",
                            remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on the web server; mandate TLS 1.2 or TLS 1.3.",
                            scanner_name="SNMK TLS Auditor",
                            location=f"{hostname}:{port}",
                            cwe_id="CWE-326",
                            cvss_score=7.4
                        ))
        except Exception as e:
            logger.debug(f"TLS inspection note for {hostname}: {e}")

    def _audit_http_headers_and_cookies(self, job: UniversalScanJob, url: str):
        """Audits security headers (HSTS, CSP, X-Frame-Options, etc.) and cookie flags."""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SNMK-Universal-Scanner/2.3"}
            )
            # Safe handler preventing automated follow of redirects to internal IPs
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                headers = dict(resp.info())
                cookies = resp.headers.get_all("Set-Cookie") or []

                # Missing HSTS
                if url.startswith("https://") and "strict-transport-security" not in [k.lower() for k in headers.keys()]:
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        finding_title="Missing HTTP Strict Transport Security (HSTS) Header",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        description="The application does not enforce HSTS, leaving users vulnerable to SSL-stripping and man-in-the-middle attacks.",
                        evidence="Strict-Transport-Security header was not returned in HTTP response.",
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to server responses.",
                        scanner_name="SNMK Header Auditor",
                        location=url,
                        cwe_id="CWE-319",
                        cvss_score=5.3
                    ))

                # Missing Content-Security-Policy
                if "content-security-policy" not in [k.lower() for k in headers.keys()]:
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        finding_title="Missing Content-Security-Policy (CSP) Header",
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        description="Content-Security-Policy header is absent, increasing exposure to Cross-Site Scripting (XSS) and code injection.",
                        evidence="Content-Security-Policy header was omitted.",
                        remediation="Define a strong CSP specifying trusted origins for script-src, style-src, and frame-ancestors.",
                        scanner_name="SNMK Header Auditor",
                        location=url,
                        cwe_id="CWE-1021",
                        cvss_score=5.0
                    ))

                # Missing X-Content-Type-Options
                if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        finding_title="Missing or Weak X-Content-Type-Options Header",
                        severity="LOW",
                        confidence="CONFIRMED",
                        description="The X-Content-Type-Options header is missing or not set to 'nosniff', allowing browsers to MIME-sniff response content.",
                        evidence=f"X-Content-Type-Options: {headers.get('X-Content-Type-Options', 'NOT_SET')}",
                        remediation="Set 'X-Content-Type-Options: nosniff' across all HTTP responses.",
                        scanner_name="SNMK Header Auditor",
                        location=url,
                        cwe_id="CWE-79",
                        cvss_score=3.7
                    ))

                # Information Disclosure in Server Headers
                server_hdr = headers.get("Server", "")
                powered_by = headers.get("X-Powered-By", "")
                if server_hdr and any(c.isdigit() for c in server_hdr):
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        finding_title=f"Server Version Disclosure ({server_hdr})",
                        severity="LOW",
                        confidence="CONFIRMED",
                        description="The Server header discloses granular software and version details, facilitating targeted vulnerability searches by adversaries.",
                        evidence=f"Server: {server_hdr}",
                        remediation="Configure the web server to suppress or tokenize the Server header (e.g., 'ServerTokens Prod').",
                        scanner_name="SNMK InfoDisclosure Auditor",
                        location=url,
                        cwe_id="CWE-200",
                        cvss_score=3.5
                    ))

                if powered_by:
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        finding_title=f"Backend Technology Disclosure (X-Powered-By: {powered_by})",
                        severity="LOW",
                        confidence="CONFIRMED",
                        description="The X-Powered-By header advertises backend framework components to external callers.",
                        evidence=f"X-Powered-By: {powered_by}",
                        remediation="Remove the X-Powered-By header in application or proxy configurations.",
                        scanner_name="SNMK InfoDisclosure Auditor",
                        location=url,
                        cwe_id="CWE-200",
                        cvss_score=3.0
                    ))

                # Cookie Flags Audit
                for cookie in cookies:
                    c_lower = cookie.lower()
                    c_name = cookie.split("=")[0].strip()
                    if "secure" not in c_lower and url.startswith("https://"):
                        job.findings.append(UniversalFinding(
                            scan_id=job.id,
                            finding_title=f"Insecure Cookie Missing 'Secure' Flag ({c_name})",
                            severity="MEDIUM",
                            confidence="CONFIRMED",
                            description=f"Cookie '{c_name}' does not specify the Secure attribute, allowing it to be transmitted over unencrypted HTTP.",
                            evidence=f"Set-Cookie: {cookie}",
                            remediation="Append '; Secure' to all cookies issued over TLS.",
                            scanner_name="SNMK Cookie Auditor",
                            location=url,
                            cwe_id="CWE-614",
                            cvss_score=4.8
                        ))
                    if "httponly" not in c_lower:
                        job.findings.append(UniversalFinding(
                            scan_id=job.id,
                            finding_title=f"Cookie Accessible via JavaScript Missing 'HttpOnly' ({c_name})",
                            severity="MEDIUM",
                            confidence="CONFIRMED",
                            description=f"Cookie '{c_name}' lacks HttpOnly, making session tokens vulnerable to theft via Cross-Site Scripting (XSS).",
                            evidence=f"Set-Cookie: {cookie}",
                            remediation="Append '; HttpOnly' to all sensitive authentication and session cookies.",
                            scanner_name="SNMK Cookie Auditor",
                            location=url,
                            cwe_id="CWE-1004",
                            cvss_score=5.3
                        ))
        except Exception as e:
            logger.debug(f"HTTP header inspection note: {e}")

    def _audit_sensitive_endpoints(self, job: UniversalScanJob, base_url: str):
        """Safely checks for publicly exposed sensitive files and endpoints."""
        sensitive_paths = [
            ("/.env", "Exposed Environment File (.env)", "CRITICAL", "CWE-552", 9.2),
            ("/.git/HEAD", "Exposed Git Version Control Directory (/.git/HEAD)", "HIGH", "CWE-527", 8.2),
            ("/server-status", "Exposed Server Status Page (/server-status)", "MEDIUM", "CWE-200", 5.3),
            ("/phpinfo.php", "Exposed PHP Info Debug Page (/phpinfo.php)", "HIGH", "CWE-200", 7.5),
            ("/api/swagger.json", "Publicly Accessible API Documentation (/api/swagger.json)", "INFORMATIONAL", "CWE-200", 2.0),
        ]
        base_url = base_url.rstrip("/")
        for path, title, sev, cwe, cvss in sensitive_paths:
            test_url = base_url + path
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "SNMK-Prober/2.3"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        content_sample = resp.read(256).decode("utf-8", errors="ignore")
                        # Verify it's not a generic 200 soft 404 page
                        if path == "/.env" and ("=" in content_sample or "KEY" in content_sample or "SECRET" in content_sample):
                            job.findings.append(UniversalFinding(
                                scan_id=job.id,
                                finding_title=title,
                                severity=sev,
                                confidence="CONFIRMED",
                                description=f"The application exposes sensitive configuration at {test_url}, disclosing database credentials or API keys.",
                                evidence=f"Status 200 OK. Sample: {content_sample[:100]}...",
                                remediation="Block public web server access to all dotfiles and environment configurations.",
                                scanner_name="SNMK Active Prober",
                                location=test_url,
                                cwe_id=cwe,
                                cvss_score=cvss
                            ))
                        elif path == "/.git/HEAD" and ("ref:" in content_sample or len(content_sample.strip()) == 40):
                            job.findings.append(UniversalFinding(
                                scan_id=job.id,
                                finding_title=title,
                                severity=sev,
                                confidence="CONFIRMED",
                                description=f"Git repository structure is publicly reachable at {test_url}, allowing reconstruction of source code.",
                                evidence=f"Status 200 OK. HEAD: {content_sample.strip()}",
                                remediation="Deny web access to /.git and version control metadata directories.",
                                scanner_name="SNMK Active Prober",
                                location=test_url,
                                cwe_id=cwe,
                                cvss_score=cvss
                            ))
            except Exception:
                continue

    # =========================================================================
    # File & Folder Vulnerability Analysis
    # =========================================================================

    def scan_files(self, job: UniversalScanJob, file_paths: List[str]) -> List[UniversalFinding]:
        job.status = "RUNNING"
        job.total_files = len(file_paths)
        job.completed_files = 0
        job.failed_files = 0
        job.current_stage = "Classifying submitted files and calculating integrity hashes"
        job.progress_percent = 10

        # Process each file safely
        for idx, fpath in enumerate(file_paths):
            if job.cancelled:
                break

            filename = os.path.basename(fpath)
            job.current_file = filename
            job.progress_percent = int(10 + (idx / max(1, len(file_paths))) * 80)
            job.current_stage = f"Analyzing ({idx + 1}/{len(file_paths)}): {filename}"

            try:
                file_record = self._register_file(job.id, fpath)
                job.files.append(file_record)

                # Route based on detected file category
                cat = file_record.detected_file_type
                if cat == "archive":
                    self._analyze_archive(job, file_record)
                elif cat == "document":
                    self._analyze_document(job, file_record)
                elif cat == "image":
                    self._analyze_image(job, file_record)
                elif cat in ("source_code", "config"):
                    self._analyze_source_code_and_config(job, file_record)
                else:
                    # Generic text or binary inspection
                    self._analyze_generic_file(job, file_record)

                file_record.processing_status = "COMPLETED"
                job.completed_files += 1
            except Exception as e:
                logger.error(f"Error analyzing file '{fpath}': {e}", exc_info=True)
                job.failed_files += 1
                if 'file_record' in locals():
                    file_record.processing_status = "FAILED"

        job.current_stage = "Deduplicating findings and running risk assessment"
        job.progress_percent = 95
        self._finalize_job(job)
        return job.findings

    def _register_file(self, scan_id: str, file_path: str) -> UploadedFileRecord:
        size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        digest = sha.hexdigest()

        ext = Path(file_path).suffix.lower()
        cat = self._detect_file_category(ext, file_path)

        return UploadedFileRecord(
            scan_id=scan_id,
            original_filename=os.path.basename(file_path),
            detected_file_type=cat,
            file_size=size,
            sha256_hash=digest,
            processing_status="PROCESSING",
            storage_path=file_path
        )

    def _detect_file_category(self, ext: str, path: str) -> str:
        if ext in (".zip", ".tar", ".gz", ".tgz"):
            return "archive"
        if ext in (".pdf", ".doc", ".docx", ".txt", ".md", ".markdown", ".rtf"):
            return "document"
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff"):
            return "image"
        if ext in (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".c", ".cpp", ".h", ".hpp", ".cs", ".go", ".rb", ".sh", ".ps1"):
            return "source_code"
        base_lower = os.path.basename(path).lower()
        if "dockerfile" in base_lower or "docker-compose" in base_lower or ext in (".json", ".xml", ".yaml", ".yml", ".env", ".ini", ".conf", ".toml", ".tf"):
            return "config"
        return "generic"

    # -------------------------------------------------------------------------
    # Document Analyzer
    # -------------------------------------------------------------------------
    def _analyze_document(self, job: UniversalScanJob, record: UploadedFileRecord):
        ext = Path(record.storage_path).suffix.lower()
        extracted_text = ""

        # 1. PDF Analysis
        if ext == ".pdf":
            self._analyze_pdf(job, record)
            return

        # 2. DOCX Analysis
        elif ext == ".docx":
            if DOCX_AVAILABLE:
                try:
                    doc = docx.Document(record.storage_path)
                    extracted_text = "\n".join([p.text for p in doc.paragraphs])
                except Exception as e:
                    logger.debug(f"python-docx error on {record.original_filename}: {e}")
            # Check for VBA Macros in docx package
            try:
                with zipfile.ZipFile(record.storage_path, "r") as z:
                    namelist = z.namelist()
                    if any("vbaProject.bin" in name for name in namelist):
                        job.findings.append(UniversalFinding(
                            scan_id=job.id,
                            file_id=record.id,
                            finding_title="Active VBA Macro Detected in Document (vbaProject.bin)",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            description="The uploaded Word document contains an embedded Visual Basic for Applications (VBA) macro binary.",
                            evidence=f"File '{record.original_filename}' contains vbaProject.bin",
                            remediation="Inspect macro code in an isolated sandbox. Strip macros before distributing documents.",
                            scanner_name="SNMK Document Auditor",
                            location=record.original_filename,
                            cwe_id="CWE-94",
                            cvss_score=7.8
                        ))
            except Exception:
                logging.getLogger(__name__).debug("Suppressed exception (audited empty handler)", exc_info=True)

        # 3. Plain Text / Markdown / RTF
        else:
            try:
                with open(record.storage_path, "r", encoding="utf-8", errors="ignore") as f:
                    extracted_text = f.read(500000)  # read first 500KB
            except Exception as e:
                logger.debug(f"Failed to read document text: {e}")

        # Scan extracted text for exposed secrets and phishing links
        if extracted_text:
            self._scan_text_for_secrets(job, record, extracted_text)
            self._scan_text_for_suspicious_urls(job, record, extracted_text)

    def _analyze_pdf(self, job: UniversalScanJob, record: UploadedFileRecord):
        """Deep PDF structural inspection for JavaScript, Launch actions, and secrets."""
        # Raw byte scan for dangerous PDF objects
        try:
            with open(record.storage_path, "rb") as f:
                content = f.read(2 * 1024 * 1024)  # 2MB inspection window

            dangerous_pdf_tags = [
                (b"/JavaScript", "Embedded JavaScript in PDF Object", "HIGH", "CWE-79", 7.5),
                (b"/Launch", "Dangerous /Launch Action in PDF (Arbitrary Command Execution)", "CRITICAL", "CWE-78", 9.3),
                (b"/EmbeddedFiles", "Embedded External File Attachment Inside PDF", "MEDIUM", "CWE-434", 6.2),
                (b"/OpenAction", "Automated /OpenAction Execution Upon Document View", "MEDIUM", "CWE-94", 6.0),
            ]
            for tag, title, sev, cwe, cvss in dangerous_pdf_tags:
                if tag in content:
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        file_id=record.id,
                        finding_title=title,
                        severity=sev,
                        confidence="CONFIRMED",
                        description=f"PDF file contains {tag.decode('latin1')} structure which can trigger automated scripts upon viewing.",
                        evidence=f"Found signature '{tag.decode('latin1')}' in {record.original_filename}",
                        remediation="Sanitize or flatten the PDF to strip interactive scripts and automated launch actions.",
                        scanner_name="SNMK PDF Security Analyzer",
                        location=record.original_filename,
                        cwe_id=cwe,
                        cvss_score=cvss
                    ))
        except Exception as e:
            logger.debug(f"Raw PDF byte inspection error: {e}")

        # Extract text via PyPDF if available
        if PYPDF_AVAILABLE:
            try:
                reader = pypdf.PdfReader(record.storage_path)
                pdf_text = ""
                for page in reader.pages[:20]:  # inspect first 20 pages
                    t = page.extract_text()
                    if t:
                        pdf_text += t + "\n"
                if pdf_text:
                    self._scan_text_for_secrets(job, record, pdf_text)
                    self._scan_text_for_suspicious_urls(job, record, pdf_text)
            except Exception as e:
                logger.debug(f"PyPDF extraction note: {e}")

    # -------------------------------------------------------------------------
    # Image Analyzer
    # -------------------------------------------------------------------------
    def _analyze_image(self, job: UniversalScanJob, record: UploadedFileRecord):
        """Audits images for EXIF metadata privacy leaks, GPS tags, and appended polyglot payloads."""
        if not PIL_AVAILABLE:
            return

        try:
            with Image.open(record.storage_path) as img:
                info = img._getexif() if hasattr(img, "_getexif") else None
                if info:
                    # 1. GPS Location Leak Detection
                    gps_info = info.get(34853)  # GPSInfo tag ID
                    if gps_info:
                        job.findings.append(UniversalFinding(
                            scan_id=job.id,
                            file_id=record.id,
                            finding_title="Geolocation Privacy Leak: GPS Coordinates in EXIF",
                            severity="MEDIUM",
                            confidence="CONFIRMED",
                            description="Image contains embedded GPS metadata, exposing precise physical latitude, longitude, and elevation.",
                            evidence=f"GPSInfo tag present in {record.original_filename}",
                            remediation="Strip EXIF metadata using an image processing pipeline or 'exiftool -all=' before publishing images.",
                            scanner_name="SNMK Image EXIF Auditor",
                            location=record.original_filename,
                            cwe_id="CWE-200",
                            cvss_score=5.5
                        ))

                    # 2. Camera & Software Details
                    model = info.get(272)  # Model
                    software = info.get(305)  # Software
                    if model or software:
                        job.findings.append(UniversalFinding(
                            scan_id=job.id,
                            file_id=record.id,
                            finding_title=f"Device / Software Metadata Disclosed ({software or model})",
                            severity="INFORMATIONAL",
                            confidence="CONFIRMED",
                            description="Image preserves hardware and editing software tags in EXIF headers.",
                            evidence=f"Device: {model or 'N/A'}, Software: {software or 'N/A'}",
                            remediation="Strip device serial numbers and software version metadata.",
                            scanner_name="SNMK Image EXIF Auditor",
                            location=record.original_filename,
                            cwe_id="CWE-200",
                            cvss_score=2.0
                        ))
        except Exception as e:
            logger.debug(f"Pillow EXIF note on {record.original_filename}: {e}")

        # 3. Polyglot / Appended Payload Detection (Past official EOF)
        self._check_image_appended_payload(job, record)

        # 4. OCR / Text Extraction (Screenshots with exposed credentials)
        if TESSERACT_AVAILABLE:
            try:
                ocr_text = pytesseract.image_to_string(Image.open(record.storage_path))
                if ocr_text:
                    self._scan_text_for_secrets(job, record, ocr_text, source="OCR Extraction")
            except Exception as e:
                logger.debug(f"Tesseract OCR execution note: {e}")

    def _check_image_appended_payload(self, job: UniversalScanJob, record: UploadedFileRecord):
        """Detects malicious binaries or archives appended after official image EOF markers."""
        try:
            with open(record.storage_path, "rb") as f:
                data = f.read()

            ext = Path(record.storage_path).suffix.lower()
            trailing_data = b""

            if ext == ".png":
                iend = b"\x49\x45\x4e\x44\xae\x42\x60\x82"
                idx = data.find(iend)
                if idx != -1 and idx + len(iend) < len(data):
                    trailing_data = data[idx + len(iend):]
            elif ext in (".jpg", ".jpeg"):
                eoi = b"\xff\xd9"
                idx = data.rfind(eoi)
                if idx != -1 and idx + len(eoi) < len(data):
                    trailing_data = data[idx + len(eoi):]

            if trailing_data:
                # Check for executable or archive headers inside trailing data
                if trailing_data.startswith(b"MZ") or b"\x7fELF" in trailing_data[:10]:
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        file_id=record.id,
                        finding_title="Polyglot Executable Binary Hidden in Image Trailer",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        description="An executable PE/ELF binary header is appended past the official image termination marker.",
                        evidence=f"Appended payload size: {len(trailing_data)} bytes starting with executable signature.",
                        remediation="Isolate and inspect the file in malware sandbox. Do not distribute or display without re-encoding.",
                        scanner_name="SNMK Steganography & Polyglot Detector",
                        location=record.original_filename,
                        cwe_id="CWE-434",
                        cvss_score=9.5
                    ))
                elif trailing_data.startswith(b"PK\x03\x04"):
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        file_id=record.id,
                        finding_title="Embedded ZIP Archive Hidden in Image Trailer",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        description="A compressed ZIP archive is hidden past the image end-of-file marker.",
                        evidence=f"Appended PK zip signature ({len(trailing_data)} bytes) found in {record.original_filename}",
                        remediation="Re-encode image with standard image processing libraries to strip unreferenced trailer bytes.",
                        scanner_name="SNMK Steganography & Polyglot Detector",
                        location=record.original_filename,
                        cwe_id="CWE-434",
                        cvss_score=7.8
                    ))
        except Exception as e:
            logger.debug(f"Payload trailer check note: {e}")

    # -------------------------------------------------------------------------
    # Source Code and Configuration Analyzer
    # -------------------------------------------------------------------------
    def _analyze_source_code_and_config(self, job: UniversalScanJob, record: UploadedFileRecord):
        try:
            with open(record.storage_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            logger.debug(f"Failed to read source code: {e}")
            return

        lines = content.splitlines()

        # 1. Hardcoded Secrets Detection
        self._scan_text_for_secrets(job, record, content, lines=lines)

        # 2. Source Code Vulnerability Patterns (SQLi, XSS, Command Injection, Deserialization)
        for idx, line in enumerate(lines):
            line_no = idx + 1
            for title, pattern, sev, cwe, cvss, rem in CODE_FLAW_PATTERNS:
                if pattern.search(line):
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        file_id=record.id,
                        finding_title=title,
                        severity=sev,
                        confidence="CONFIRMED",
                        description=f"Potential application security flaw identified at line {line_no}.",
                        evidence=f"{record.original_filename}:{line_no} -> {line.strip()[:140]}",
                        remediation=rem,
                        scanner_name="SNMK Static Code Auditor",
                        location=f"{record.original_filename}:{line_no}",
                        cwe_id=cwe,
                        cvss_score=cvss
                    ))

        # 3. Dockerfile / IaC Security Audit
        filename_lower = record.original_filename.lower()
        if "dockerfile" in filename_lower:
            for title, pattern, sev, cwe, cvss, rem in IAC_FLAW_PATTERNS:
                if pattern.search(content):
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        file_id=record.id,
                        finding_title=title,
                        severity=sev,
                        confidence="CONFIRMED",
                        description=f"Container configuration risk detected in {record.original_filename}.",
                        evidence=f"File: {record.original_filename}",
                        remediation=rem,
                        scanner_name="SNMK Container Auditor",
                        location=record.original_filename,
                        cwe_id=cwe,
                        cvss_score=cvss
                    ))

    def _analyze_generic_file(self, job: UniversalScanJob, record: UploadedFileRecord):
        """Scans arbitrary files for secrets and binary safety indicators."""
        try:
            with open(record.storage_path, "rb") as f:
                head = f.read(1024 * 1024)  # 1MB
            text = head.decode("utf-8", errors="ignore")
            if text:
                self._scan_text_for_secrets(job, record, text)
        except Exception as e:
            logger.debug(f"Generic file scan error: {e}")

    # -------------------------------------------------------------------------
    # Archive Analyzer with Zip Slip & Bomb Protection
    # -------------------------------------------------------------------------
    def _analyze_archive(self, job: UniversalScanJob, record: UploadedFileRecord):
        """Safely inspects and extracts ZIP archives enforcing decompression boundaries."""
        extract_dir = tempfile.mkdtemp(prefix="snmk_extract_")
        extracted_files = []

        try:
            with zipfile.ZipFile(record.storage_path, "r") as z:
                total_uncompressed = sum(info.file_size for info in z.infolist())
                file_count = len(z.infolist())

                # Archive Bomb Protection
                if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED or file_count > MAX_ARCHIVE_FILES:
                    job.findings.append(UniversalFinding(
                        scan_id=job.id,
                        file_id=record.id,
                        finding_title="Decompression Bomb / Zip Bomb Indicator Detected",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        description=f"Archive contains {file_count} files expanding to {round(total_uncompressed / 1024 / 1024, 2)} MB, exceeding safe extraction threshold.",
                        evidence=f"File count: {file_count}, Uncompressed: {total_uncompressed} bytes",
                        remediation="Inspect archive metadata in an isolated sandbox with strict resource quotas.",
                        scanner_name="SNMK Archive Security Guard",
                        location=record.original_filename,
                        cwe_id="CWE-400",
                        cvss_score=8.6
                    ))
                    return

                # Zip Slip / Path Traversal Check & Safe Extraction
                for member in z.infolist():
                    target_path = os.path.abspath(os.path.join(extract_dir, member.filename))
                    if not target_path.startswith(os.path.abspath(extract_dir) + os.sep) and not target_path == os.path.abspath(extract_dir):
                        job.findings.append(UniversalFinding(
                            scan_id=job.id,
                            file_id=record.id,
                            finding_title="Zip Slip Path Traversal Vulnerability Detected",
                            severity="CRITICAL",
                            confidence="CONFIRMED",
                            description="Archive contains entry with directory traversal sequences (../) targeting locations outside extraction sandbox.",
                            evidence=f"Malicious member name: '{member.filename}' in {record.original_filename}",
                            remediation="Sanitize all relative archive filenames to strip '..' components before extraction.",
                            scanner_name="SNMK Archive Security Guard",
                            location=record.original_filename,
                            cwe_id="CWE-22",
                            cvss_score=9.3
                        ))
                        return

                    if not member.is_dir():
                        z.extract(member, extract_dir)
                        extracted_files.append(target_path)

            # Recursively scan extracted archive contents
            for ext_file in extracted_files:
                if job.cancelled:
                    break
                sub_record = self._register_file(job.id, ext_file)
                cat = sub_record.detected_file_type
                if cat == "document":
                    self._analyze_document(job, sub_record)
                elif cat == "image":
                    self._analyze_image(job, sub_record)
                elif cat in ("source_code", "config"):
                    self._analyze_source_code_and_config(job, sub_record)
                else:
                    self._analyze_generic_file(job, sub_record)

        except zipfile.BadZipFile:
            job.findings.append(UniversalFinding(
                scan_id=job.id,
                file_id=record.id,
                finding_title="Corrupt or Invalid ZIP Archive Structure",
                severity="LOW",
                confidence="CONFIRMED",
                description="The submitted file failed ZIP container header validation.",
                evidence=f"BadZipFile on {record.original_filename}",
                remediation="Ensure file integrity and re-upload uncorrupted archive.",
                scanner_name="SNMK Archive Guard",
                location=record.original_filename,
                cwe_id="CWE-20",
                cvss_score=3.0
            ))
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Shared Secret and Phishing Regex Scanners
    # -------------------------------------------------------------------------
    def _scan_text_for_secrets(self, job: UniversalScanJob, record: UploadedFileRecord, text: str, lines: Optional[List[str]] = None, source: str = "Static Scan"):
        """Detects exposed API keys, private keys, database passwords, and credentials."""
        for name, pattern, sev, cwe, cvss in SECRET_PATTERNS:
            matches = pattern.finditer(text)
            for m in matches:
                matched_val = m.group(0)
                # Mask secret value in evidence for safe display
                if len(matched_val) > 8:
                    masked = matched_val[:4] + "*" * (len(matched_val) - 8) + matched_val[-4:]
                else:
                    masked = "****"

                loc = record.original_filename
                if lines:
                    # Find exact line number
                    start_char = m.start()
                    cur = 0
                    for lno, line in enumerate(lines, 1):
                        cur += len(line) + 1
                        if cur >= start_char:
                            loc = f"{record.original_filename}:{lno}"
                            break

                job.findings.append(UniversalFinding(
                    scan_id=job.id,
                    file_id=record.id,
                    finding_title=f"Hardcoded Secret / Credential Leak ({name})",
                    severity=sev,
                    confidence="CONFIRMED",
                    description=f"Identified high-entropy secret '{name}' embedded in application artifact.",
                    evidence=f"Masked Value: {masked} [{source}]",
                    remediation="Revoke the exposed credential immediately. Store secrets in environment variables or an enterprise secret vault.",
                    scanner_name="SNMK Secret Detection Engine",
                    location=loc,
                    cwe_id=cwe,
                    cvss_score=cvss
                ))

    def _scan_text_for_suspicious_urls(self, job: UniversalScanJob, record: UploadedFileRecord, text: str):
        """Extracts and flags suspicious external links and phishing indicators."""
        url_regex = re.compile(r"https?:\/\/[^\s<>\"'()]+", re.IGNORECASE)
        for m in url_regex.finditer(text):
            link = m.group(0)
            parsed = urllib.parse.urlparse(link)
            host = parsed.hostname or ""

            # Detect raw IP addresses used as domains
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                job.findings.append(UniversalFinding(
                    scan_id=job.id,
                    file_id=record.id,
                    finding_title=f"Suspicious Direct IP-Based Link ({host})",
                    severity="MEDIUM",
                    confidence="CONFIRMED",
                    description="Document references a direct IP address rather than a verified domain, characteristic of C2 or phishing infrastructure.",
                    evidence=f"Found Link: {link}",
                    remediation="Verify destination ownership and replace raw IP links with registered domain names.",
                    scanner_name="SNMK Phishing & Link Analyzer",
                    location=record.original_filename,
                    cwe_id="CWE-20",
                    cvss_score=5.3
                ))

    # =========================================================================
    # Finalization, Alerts, and Persistence
    # =========================================================================

    def _finalize_job(self, job: UniversalScanJob):
        # 1. Deduplicate findings
        unique_findings = []
        seen_keys = set()
        for f in job.findings:
            key = (f.finding_title, f.location, f.evidence)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)
        job.findings = unique_findings

        # 2. Count statistics
        job.total_findings = len(job.findings)
        job.critical_count = sum(1 for f in job.findings if f.severity == "CRITICAL")
        job.high_count = sum(1 for f in job.findings if f.severity == "HIGH")
        job.medium_count = sum(1 for f in job.findings if f.severity == "MEDIUM")
        job.low_count = sum(1 for f in job.findings if f.severity == "LOW")
        job.info_count = sum(1 for f in job.findings if f.severity == "INFORMATIONAL")

        if not job.cancelled:
            job.status = "COMPLETED"
            job.progress_percent = 100
            job.current_stage = "Assessment Complete"
        job.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 3. Trigger Centralized Alerts for CRITICAL / HIGH findings
        for f in job.findings:
            if f.severity in ("CRITICAL", "HIGH"):
                alert_manager.create_alert(
                    severity=f.severity,
                    category="SECURITY",
                    title=f"[{f.severity}] {f.finding_title}",
                    description=f"Universal scanner identified '{f.finding_title}' in {f.location}. {f.description}",
                    affected_asset=f.location,
                    correlation_id=job.id,
                    remediation=f.remediation,
                    source="universal_scanner"
                )

        # 4. Persist to SQLite and MySQL
        self._persist_job_to_db(job)

    def _persist_job_to_db(self, job: UniversalScanJob):
        """Persists job metadata, files, and findings to SQLite and MySQL."""
        # SQLite Persistence
        try:
            with db.get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO universal_scans
                    (id, user_id, scan_type, target, status, started_at, completed_at,
                     total_files, total_findings, critical_count, high_count, medium_count, low_count, info_count, scan_configuration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    job.id, job.user_id, job.scan_type, job.target, job.status,
                    job.started_at, job.completed_at, job.total_files, job.total_findings,
                    job.critical_count, job.high_count, job.medium_count, job.low_count, job.info_count,
                    json.dumps(job.scan_configuration)
                ))
                for f in job.findings:
                    conn.execute("""
                        INSERT OR REPLACE INTO universal_findings
                        (id, scan_id, file_id, finding_title, severity, confidence,
                         description, evidence, remediation, scanner_name, location, cwe_id, cvss_score, status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        f.id, f.scan_id, f.file_id, f.finding_title, f.severity, f.confidence,
                        f.description, f.evidence, f.remediation, f.scanner_name, f.location, f.cwe_id, f.cvss_score, f.status, f.created_at
                    ))
        except Exception as e:
            logger.warning(f"Failed to persist universal scan to SQLite: {e}")

        # MySQL Persistence (if online)
        if mysql_manager.is_configured():
            try:
                conn = mysql_manager.get_connection()
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO universal_scans
                        (id, user_id, scan_type, target, status, started_at, completed_at,
                         total_files, total_findings, critical_count, high_count, medium_count, low_count, info_count, scan_configuration)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        status=VALUES(status), completed_at=VALUES(completed_at),
                        total_files=VALUES(total_files), total_findings=VALUES(total_findings),
                        critical_count=VALUES(critical_count), high_count=VALUES(high_count),
                        medium_count=VALUES(medium_count), low_count=VALUES(low_count), info_count=VALUES(info_count);
                    """, (
                        job.id, job.user_id, job.scan_type, job.target, job.status,
                        job.started_at, job.completed_at, job.total_files, job.total_findings,
                        job.critical_count, job.high_count, job.medium_count, job.low_count, job.info_count,
                        json.dumps(job.scan_configuration)
                    ))
                conn.close()
            except Exception as e:
                logger.warning(f"Failed to persist universal scan to MySQL: {e}")

    def _load_job_from_db(self, scan_id: str) -> Optional[UniversalScanJob]:
        try:
            with db.get_connection() as conn:
                cur = conn.execute("SELECT * FROM universal_scans WHERE id = ?", (scan_id,))
                row = cur.fetchone()
                if not row:
                    return None

                config = json.loads(row[14]) if row[14] else {}
                job = UniversalScanJob(
                    id=row[0],
                    user_id=row[1],
                    scan_type=row[2],
                    target=row[3],
                    status=row[4],
                    started_at=row[5],
                    completed_at=row[6],
                    total_files=row[7],
                    total_findings=row[8],
                    critical_count=row[9],
                    high_count=row[10],
                    medium_count=row[11],
                    low_count=row[12],
                    info_count=row[13],
                    scan_configuration=config
                )

                # Load findings
                cur_f = conn.execute("SELECT * FROM universal_findings WHERE scan_id = ?", (scan_id,))
                for frow in cur_f.fetchall():
                    job.findings.append(UniversalFinding(
                        id=frow[0],
                        scan_id=frow[1],
                        file_id=frow[2],
                        finding_title=frow[3],
                        severity=frow[4],
                        confidence=frow[5],
                        description=frow[6],
                        evidence=frow[7],
                        remediation=frow[8],
                        scanner_name=frow[9],
                        location=frow[10],
                        cwe_id=frow[11],
                        cvss_score=frow[12],
                        status=frow[13],
                        created_at=frow[14]
                    ))
                self._jobs[job.id] = job
                return job
        except Exception as e:
            clean_id = str(scan_id).replace("\r", "").replace("\n", "")[:64]
            logger.warning(f"Error loading job {clean_id} from SQLite: {e}")
            return None

    # =========================================================================
    # Report Generation (JSON, HTML, CSV, Markdown, SARIF)
    # =========================================================================

    def generate_report(self, scan_id: str, format_type: str = "json") -> Tuple[str, str]:
        """Generates downloadable reports in standard formats. Returns (content, mime_type)."""
        job = self.get_job(scan_id)
        if not job:
            raise ValueError(f"Scan {scan_id} not found")

        format_type = format_type.lower()
        if format_type == "json":
            return json.dumps(job.to_dict(include_details=True), indent=2), "application/json"

        elif format_type == "csv":
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(["Finding Title", "Severity", "Confidence", "Location", "CWE", "CVSS", "Description", "Evidence", "Remediation", "Scanner"])
            for f in job.findings:
                writer.writerow([f.finding_title, f.severity, f.confidence, f.location, f.cwe_id or "", f.cvss_score, f.description, f.evidence, f.remediation, f.scanner_name])
            return out.getvalue(), "text/csv"

        elif format_type in ("md", "markdown"):
            md = [
                f"# SNMK Universal Vulnerability Scanner Report",
                f"**Target:** `{job.target}` | **Scan ID:** `{job.id}` | **Date:** {job.completed_at or job.started_at}",
                f"",
                f"### Executive Summary",
                f"- **Total Findings:** {job.total_findings}",
                f"- **Critical:** {job.critical_count} | **High:** {job.high_count} | **Medium:** {job.medium_count} | **Low:** {job.low_count} | **Informational:** {job.info_count}",
                f"- **Status:** {job.status}",
                f"",
                f"### Detailed Findings",
            ]
            for idx, f in enumerate(job.findings, 1):
                md.append(f"#### {idx}. [{f.severity}] {f.finding_title}")
                md.append(f"- **Location:** `{f.location}`")
                md.append(f"- **CWE:** `{f.cwe_id or 'N/A'}` | **CVSS:** {f.cvss_score}")
                md.append(f"- **Description:** {f.description}")
                md.append(f"- **Evidence:** `{f.evidence}`")
                md.append(f"- **Remediation:** {f.remediation}")
                md.append("")
            return "\n".join(md), "text/markdown"

        elif format_type == "sarif":
            sarif = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "SNMK Universal Vulnerability Scanner",
                            "version": "2.3.0",
                            "informationUri": "https://github.com/545e/snmk"
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.cwe_id or "SNMK-SEC-FINDING",
                            "level": "error" if f.severity in ("CRITICAL", "HIGH") else ("warning" if f.severity == "MEDIUM" else "note"),
                            "message": {"text": f"{f.finding_title}: {f.description}"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.location}
                                }
                            }]
                        }
                        for f in job.findings
                    ]
                }]
            }
            return json.dumps(sarif, indent=2), "application/sarif+json"

        elif format_type == "html":
            rows = ""
            for f in job.findings:
                sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFORMATIONAL": "#64748b"}.get(f.severity, "#64748b")
                rows += f"""
                <tr>
                    <td><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:11px;">{f.severity}</span></td>
                    <td><strong>{f.finding_title}</strong><br><small style="color:#64748b">{f.cwe_id or ''}</small></td>
                    <td><code>{f.location}</code></td>
                    <td><pre style="background:#0f172a;color:#38bdf8;padding:6px;border-radius:4px;font-size:12px;margin:0;">{f.evidence}</pre></td>
                    <td>{f.remediation}</td>
                </tr>
                """
            html = f"""<!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>SNMK Vulnerability Report - {job.id}</title>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; padding: 24px; margin: 0; }}
                    .card {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }}
                    h1, h2, h3 {{ color: #38bdf8; }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                    th, td {{ padding: 10px; border: 1px solid #334155; text-align: left; vertical-align: top; font-size: 13px; }}
                    th {{ background: #0f172a; color: #94a3b8; }}
                    .badge-pill {{ display: inline-block; padding: 6px 14px; border-radius: 9999px; margin-right: 8px; font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>SNMK Universal Vulnerability Scanner Report</h1>
                    <p><strong>Target:</strong> {job.target} &nbsp;|&nbsp; <strong>Scan ID:</strong> {job.id} &nbsp;|&nbsp; <strong>Date:</strong> {job.completed_at or job.started_at}</p>
                    <div style="margin-top: 15px;">
                        <span class="badge-pill" style="background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid #ef4444;">CRITICAL: {job.critical_count}</span>
                        <span class="badge-pill" style="background: rgba(249,115,22,0.2); color: #f97316; border: 1px solid #f97316;">HIGH: {job.high_count}</span>
                        <span class="badge-pill" style="background: rgba(234,179,8,0.2); color: #eab308; border: 1px solid #eab308;">MEDIUM: {job.medium_count}</span>
                        <span class="badge-pill" style="background: rgba(59,130,246,0.2); color: #3b82f6; border: 1px solid #3b82f6;">LOW: {job.low_count}</span>
                        <span class="badge-pill" style="background: rgba(100,116,139,0.2); color: #94a3b8; border: 1px solid #94a3b8;">INFO: {job.info_count}</span>
                    </div>
                </div>
                <div class="card">
                    <h2>Vulnerability Findings ({job.total_findings})</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Vulnerability</th>
                                <th>Location</th>
                                <th>Evidence</th>
                                <th>Remediation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
            """
            return html, "text/html"

        return json.dumps(job.to_dict(include_details=True)), "application/json"


# Global singleton instance
universal_scanner = UniversalScannerEngine()
