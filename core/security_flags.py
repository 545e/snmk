"""
SNMK — Intelligent Security Flag Identification Engine (Phase 7)
Centralized indicator & flag identification engine classifying security indicators
across tools, source code, documents, images, URLs, and network forensics.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from core.alert_manager import alert_manager
from core.database import db
from core.mysql_database import mysql_manager

logger = logging.getLogger("snmk.security_flags")


class FlagCategory(str, Enum):
    CREDENTIALS_AND_SECRETS = "CREDENTIALS_AND_SECRETS"
    WEB_APPLICATION_SECURITY = "WEB_APPLICATION_SECURITY"
    MALWARE_AND_SUSPICIOUS = "MALWARE_AND_SUSPICIOUS"
    INFRASTRUCTURE_SECURITY = "INFRASTRUCTURE_SECURITY"
    DOCUMENT_AND_IMAGE = "DOCUMENT_AND_IMAGE"
    PCAP_AND_NETWORK = "PCAP_AND_NETWORK"


class FlagSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    POTENTIAL = "POTENTIAL"
    NOT_VERIFIED = "NOT_VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


# Canonical Flag Catalog with default Category, Severity, and Guidance
FLAG_CATALOG: Dict[str, Dict[str, Any]] = {
    # A. Credentials and Secret Flags
    "API_KEY": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.HIGH, "impact": "Exposed API key allows unauthorized API usage.", "rem": "Rotate API key and migrate to environment secret manager."},
    "SECRET_KEY": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.CRITICAL, "impact": "Root or service secret key exposure grants unauthorized elevation.", "rem": "Immediately revoke and regenerate key."},
    "ACCESS_TOKEN": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.HIGH, "impact": "Allows session hijacking and unauthorized API access.", "rem": "Invalidate token and shorten token lifespans."},
    "REFRESH_TOKEN": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.HIGH, "impact": "Enables long-term persistence without re-authentication.", "rem": "Revoke refresh token and mandate re-login."},
    "JWT_TOKEN": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.MEDIUM, "impact": "Token claims or keys exposed in artifacts.", "rem": "Use secure server-side session stores or short-lived signed JWTs."},
    "PASSWORD_EXPOSED": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.HIGH, "impact": "Plaintext credentials allow direct account compromise.", "rem": "Change password immediately and hash credentials with Argon2id."},
    "DATABASE_CREDENTIALS": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.CRITICAL, "impact": "Database connection string grants unauthorized database access.", "rem": "Rotate DB credentials and bind to internal VPC network only."},
    "PRIVATE_KEY": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.CRITICAL, "impact": "Asymmetric private key disclosure compromises TLS or server SSH authentication.", "rem": "Generate new keypair and revoke compromised certificate."},
    "AWS_ACCESS_KEY": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.CRITICAL, "impact": "AWS credentials expose cloud infrastructure, storage, and IAM roles.", "rem": "Disable IAM access key in AWS Console and audit CloudTrail."},
    "GITHUB_TOKEN": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.CRITICAL, "impact": "Enables unauthorized git repository read, write, and CI/CD takeover.", "rem": "Revoke PAT in GitHub Developer Settings."},
    "SSH_KEY": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.CRITICAL, "impact": "Direct shell access to production hosts.", "rem": "Remove public key from authorized_keys and generate new ED25519 key."},
    "HARD_CODED_SECRET": {"category": FlagCategory.CREDENTIALS_AND_SECRETS, "severity": FlagSeverity.HIGH, "impact": "Hardcoded token in repository commits.", "rem": "Extract secret into environment variables."},

    # B. Web Application Security Flags
    "SQL_INJECTION": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.HIGH, "impact": "Arbitrary SQL execution, data exfiltration, or database destruction.", "rem": "Use parameterized queries or ORM prepared statements."},
    "XSS": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.HIGH, "impact": "Cross-Site Scripting allows session cookie theft and client-side malware execution.", "rem": "Encode user inputs and implement a strict Content-Security-Policy."},
    "CSRF": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Forces authenticated users into executing unintended actions.", "rem": "Implement anti-CSRF tokens and SameSite cookie attributes."},
    "SSRF": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.CRITICAL, "impact": "Server-Side Request Forgery allows querying internal cloud metadata and private networks.", "rem": "Enforce strict IP/DNS destination validation and block loopback/metadata ranges."},
    "IDOR": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.HIGH, "impact": "Insecure Direct Object Reference allows viewing other tenant records.", "rem": "Enforce object-level authorization checks per request session."},
    "PATH_TRAVERSAL": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.HIGH, "impact": "Directory traversal allows reading arbitrary host filesystem files.", "rem": "Canonicalize paths and restrict reads to an explicit allowlisted directory."},
    "COMMAND_INJECTION": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.CRITICAL, "impact": "Remote code execution on host operating system.", "rem": "Avoid shell execution; pass arguments as validated parameter lists."},
    "OPEN_REDIRECT": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Abused in phishing campaigns to mislead victims.", "rem": "Validate redirect URLs against trusted internal domain allowlists."},
    "DIRECTORY_LISTING": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.LOW, "impact": "Discloses internal file names and backup archives.", "rem": "Disable directory browsing in web server configuration."},
    "INSECURE_COOKIE": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Session token vulnerable to network interception or XSS extraction.", "rem": "Set 'Secure; HttpOnly; SameSite=Lax' on all session cookies."},
    "MISSING_SECURITY_HEADERS": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.LOW, "impact": "Browser defenses (MIME-sniffing, framing) are not enforced.", "rem": "Configure HSTS, CSP, X-Content-Type-Options, and X-Frame-Options."},
    "CORS_MISCONFIGURATION": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Wildcard origin with credentials allows cross-origin data theft.", "rem": "Specify explicit origins instead of wildcard '*' with Access-Control-Allow-Credentials."},
    "TLS_MISCONFIGURATION": {"category": FlagCategory.WEB_APPLICATION_SECURITY, "severity": FlagSeverity.HIGH, "impact": "Deprecated protocol or weak cipher enables traffic decryption.", "rem": "Mandate TLS 1.2 or TLS 1.3 with forward-secret ciphers."},

    # C. Malware and Suspicious Activity Flags
    "MALICIOUS_URL_INDICATOR": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.HIGH, "impact": "Directs traffic to known malware or phishing host.", "rem": "Block URL at perimeter firewall and DNS sinkhole."},
    "PHISHING_INDICATOR": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.HIGH, "impact": "Credential harvesting lure.", "rem": "Quarantine message or document and notify recipients."},
    "RANSOMWARE_INDICATOR": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.CRITICAL, "impact": "Known ransomware extension or shadow-copy deletion command.", "rem": "Isolate host from network immediately and initiate incident response."},
    "TROJAN_INDICATOR": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.CRITICAL, "impact": "Backdoor or trojanized payload executable found.", "rem": "Quarantine binary and run dynamic sandbox analysis."},
    "SPYWARE_INDICATOR": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.HIGH, "impact": "Unauthorized keylogger or surveillance telemetry module.", "rem": "Terminate process and inspect scheduled tasks."},
    "SUSPICIOUS_SCRIPT": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.MEDIUM, "impact": "Embedded script attempting unauthorized system queries.", "rem": "Analyze script AST in isolated container."},
    "OBFUSCATED_CODE": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.MEDIUM, "impact": "High entropy, base64 eval, or packed code concealing intent.", "rem": "De-obfuscate payload and perform static code review."},
    "SUSPICIOUS_EXECUTABLE": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.HIGH, "impact": "Unsigned binary in temporary or non-standard directory.", "rem": "Verify code signature and SHA-256 hash against threat feeds."},
    "PERSISTENCE_INDICATOR": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.HIGH, "impact": "Modifications to autorun registry keys, cron jobs, or startup services.", "rem": "Audit autorun entries and revert unapproved system changes."},
    "UNUSUAL_NETWORK_ENDPOINT": {"category": FlagCategory.MALWARE_AND_SUSPICIOUS, "severity": FlagSeverity.MEDIUM, "impact": "Connection to dynamic DNS or suspicious high-port socket.", "rem": "Inspect connection PID and apply host firewall drop."},

    # D. Infrastructure Security Flags
    "EXPOSED_PORT": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Publicly accessible service port expands attack surface.", "rem": "Restrict port ingress via security groups or VPN gateway."},
    "INSECURE_DOCKER_CONFIG": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Container running as root or with host socket mounted.", "rem": "Specify non-root USER and avoid mounting /var/run/docker.sock."},
    "KUBERNETES_MISCONFIGURATION": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.HIGH, "impact": "Privileged pod or overly broad RBAC ClusterRole.", "rem": "Apply Pod Security Standards and principle of least privilege."},
    "PUBLIC_STORAGE_ACCESS": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.HIGH, "impact": "S3 bucket or blob storage configured with public read/write.", "rem": "Enable Block Public Access on cloud storage buckets."},
    "WEAK_FILE_PERMISSIONS": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "World-writable configuration or executable files.", "rem": "Chmod files to 0600 or 0640 with appropriate service ownership."},
    "DEBUG_MODE_ENABLED": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Discloses stack traces, environment variables, or interactive console.", "rem": "Set DEBUG=False in production settings."},
    "EXPOSED_ADMIN_ENDPOINT": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Management panel (/admin, /actuator) reachable from public internet.", "rem": "Place admin endpoints behind SSO/VPN and enforce IP allowlisting."},
    "INSECURE_DATABASE_CONFIGURATION": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.HIGH, "impact": "Default credentials, empty passwords, or remote root login enabled.", "rem": "Harden database installation and bind to 127.0.0.1 or VPC network."},
    "WEAK_TLS_CONFIGURATION": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Support for legacy ciphers (RC4, 3DES, CBC mode).", "rem": "Update TLS policy to modern cipher suites."},
    "OUTDATED_DEPENDENCY": {"category": FlagCategory.INFRASTRUCTURE_SECURITY, "severity": FlagSeverity.MEDIUM, "impact": "Component contains published known CVEs.", "rem": "Upgrade dependency to latest patched version."},

    # E. Document and Image Security Flags
    "SUSPICIOUS_EMBEDDED_URL": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.MEDIUM, "impact": "Document contains phishing links or direct IP addresses.", "rem": "Inspect hyperlinks and sanitize document prior to forwarding."},
    "MACRO_PRESENT": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.HIGH, "impact": "Active VBA or script macro embedded in office document.", "rem": "Block inbound macro-enabled files (.docm, .xlsm) at mail gateway."},
    "EMBEDDED_OBJECT_PRESENT": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.MEDIUM, "impact": "OLE or embedded binary attachment inside document.", "rem": "Extract and inspect embedded attachments in sandbox."},
    "EXIF_GPS_EXPOSURE": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.MEDIUM, "impact": "Physical location latitude/longitude coordinates disclosed in image headers.", "rem": "Strip EXIF metadata before publishing media."},
    "SENSITIVE_TEXT_VISIBLE": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.MEDIUM, "impact": "Credentials or confidential data visible in screenshot text.", "rem": "Redact sensitive graphical elements before sharing images."},
    "QR_CODE_URL_DETECTED": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.LOW, "impact": "Embedded QR code redirects to external web destination.", "rem": "Verify decoded destination domain against safe URL policy."},
    "CREDENTIAL_IN_SCREENSHOT": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.HIGH, "impact": "API keys or passwords visible in screenshot image.", "rem": "Rotate exposed credential and crop sensitive graphic."},
    "SUSPICIOUS_FILE_SIGNATURE": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.HIGH, "impact": "File extension does not match true magic byte header.", "rem": "Enforce strict MIME/magic signature validation."},
    "POSSIBLE_POLYGLOT_FILE": {"category": FlagCategory.DOCUMENT_AND_IMAGE, "severity": FlagSeverity.CRITICAL, "impact": "Executable or archive payload hidden past image end-of-file marker.", "rem": "Quarantine polyglot file and re-encode image assets."},

    # F. PCAP and Network Forensics Flags
    "SUSPICIOUS_SOURCE_IP": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "Traffic originating from known bulletproof host or threat actor ASN.", "rem": "Block source IP at perimeter firewall."},
    "SUSPICIOUS_DESTINATION_IP": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "Outbound connection to known C2 server or botnet controller.", "rem": "Isolate sending internal host and inspect egress traffic."},
    "PORT_SCAN_INDICATOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.MEDIUM, "impact": "Sequential probe across multiple destination ports.", "rem": "Enable automated rate limiting and port-scan drop rules."},
    "SYN_FLOOD_INDICATOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "Denial of service via incomplete TCP half-open connections.", "rem": "Enable SYN cookies on host or firewall."},
    "DNS_TUNNELING_INDICATOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "High-entropy or oversized TXT queries used for covert data exfiltration.", "rem": "Implement DNS inspection and filter high-entropy subdomains."},
    "C2_COMMUNICATION_INDICATOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.CRITICAL, "impact": "Command and control beaconing or interactive protocol shell.", "rem": "Block C2 domain/IP and initiate host endpoint isolation."},
    "DATA_EXFILTRATION_INDICATOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.CRITICAL, "impact": "Anomalous high-volume outbound transfer to external host.", "rem": "Terminate network connection and inspect DLP telemetry."},
    "CLEAR_TEXT_CREDENTIAL_EXPOSURE": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "HTTP Basic auth, FTP, or Telnet passwords transmitted in cleartext.", "rem": "Enforce TLS encryption across all authentication protocols."},
    "MALICIOUS_DOMAIN_INDICATOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "DNS query to newly registered or categorized malicious domain.", "rem": "Apply DNS filtering and inspect host processes."},
    "SUSPICIOUS_HTTP_REQUEST": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.MEDIUM, "impact": "HTTP request contains SQL injection, XSS, or path traversal in URI.", "rem": "Deploy WAF rule to inspect and block malicious parameters."},
    "UNUSUAL_TLS_HANDSHAKE": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.MEDIUM, "impact": "Self-signed certificate, SNI mismatch, or suspicious JA3 fingerprint.", "rem": "Inspect certificate authority chain and TLS fingerprint."},
    "ARP_SPOOFING_INDICATOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "Conflicting ARP replies attempting man-in-the-middle positioning.", "rem": "Enable Dynamic ARP Inspection (DAI) on network switches."},
    "UNUSUAL_NETWORK_BEHAVIOR": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.MEDIUM, "impact": "Traffic volume or protocol anomaly deviating from baseline.", "rem": "Analyze network flow logs and correlate with host activity."},
    "SUSPICIOUS_PROTOCOL": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.MEDIUM, "impact": "Encrypted or unexpected protocol on non-standard port.", "rem": "Enforce application-layer protocol inspection."},
    "POSSIBLE_BEACONING": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.HIGH, "impact": "Regular outbound heartbeat connections with consistent jitter.", "rem": "Inspect endpoint process initiating periodic connections."},
    "UNEXPECTED_EXTERNAL_CONNECTION": {"category": FlagCategory.PCAP_AND_NETWORK, "severity": FlagSeverity.MEDIUM, "impact": "Internal database or server initiating spontaneous internet connection.", "rem": "Audit server outbound rules and deny default egress."},
}


@dataclass
class SecurityFlag:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    flag_name: str = ""
    category: str = FlagCategory.CREDENTIALS_AND_SECRETS.value
    severity: str = FlagSeverity.MEDIUM.value
    confidence_score: float = 0.8
    verification_status: str = VerificationStatus.NOT_VERIFIED.value
    detection_source: str = "SNMK Flag Engine"
    target_ref: str = ""
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    affected_component: str = ""
    technical_explanation: str = ""
    business_impact: str = ""
    recommended_remediation: str = ""
    related_flags: List[str] = field(default_factory=list)
    detector_agent_or_tool: str = "Rule Engine"
    reviewer_notes: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecurityFlagEngine:
    """Centralized Flag Identification, Categorization, and Verification Service."""

    def __init__(self):
        self._flags: Dict[str, SecurityFlag] = {}
        self._init_tables()

    def _init_tables(self):
        """Initializes SQLite tables for local persistence."""
        try:
            with db.get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS security_flags (
                        id TEXT PRIMARY KEY,
                        flag_name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence_score REAL DEFAULT 0.8,
                        verification_status TEXT DEFAULT 'NOT_VERIFIED',
                        detection_source TEXT,
                        target_ref TEXT,
                        evidence TEXT,
                        timestamp TEXT,
                        affected_component TEXT,
                        technical_explanation TEXT,
                        business_impact TEXT,
                        recommended_remediation TEXT,
                        related_flags TEXT,
                        detector_agent_or_tool TEXT,
                        reviewer_notes TEXT,
                        reviewed_by TEXT,
                        reviewed_at TEXT
                    );
                """)
        except Exception as e:
            logger.warning(f"Error creating security_flags table: {e}")

    def raise_flag(
        self,
        flag_name: str,
        target_ref: str,
        evidence: str,
        confidence_score: float = 0.85,
        detection_source: str = "SNMK Engine",
        detector: str = "Rule Engine",
        verification_status: str = VerificationStatus.SUSPECTED.value,
        custom_explanation: Optional[str] = None,
        custom_impact: Optional[str] = None,
        custom_remediation: Optional[str] = None,
    ) -> SecurityFlag:
        """Creates and registers a security flag indicator, triggering alerts for critical findings."""
        meta = FLAG_CATALOG.get(flag_name, {
            "category": FlagCategory.WEB_APPLICATION_SECURITY,
            "severity": FlagSeverity.MEDIUM,
            "impact": "Security anomaly detected.",
            "rem": "Inspect finding evidence and remediate according to security guidelines."
        })

        flag = SecurityFlag(
            flag_name=flag_name,
            category=meta["category"].value if hasattr(meta["category"], "value") else str(meta["category"]),
            severity=meta["severity"].value if hasattr(meta["severity"], "value") else str(meta["severity"]),
            confidence_score=confidence_score,
            verification_status=verification_status,
            detection_source=detection_source,
            target_ref=target_ref,
            evidence=evidence,
            affected_component=target_ref.split("/")[-1] if "/" in target_ref else target_ref,
            technical_explanation=custom_explanation or f"Detected indicator {flag_name} in {target_ref}.",
            business_impact=custom_impact or meta.get("impact", ""),
            recommended_remediation=custom_remediation or meta.get("rem", ""),
            detector_agent_or_tool=detector,
        )

        self._flags[flag.id] = flag
        self._persist_flag(flag)

        # Trigger Central Alert for CRITICAL and HIGH severity flags
        if flag.severity in (FlagSeverity.CRITICAL.value, FlagSeverity.HIGH.value):
            alert_manager.create_alert(
                severity=flag.severity,
                category="SECURITY",
                title=f"[{flag.severity}] Security Flag Raised: {flag.flag_name}",
                description=f"Security flag {flag.flag_name} identified at {flag.target_ref}. {flag.business_impact}",
                affected_asset=flag.target_ref,
                correlation_id=flag.id,
                remediation=flag.recommended_remediation,
                source="security_flag_engine"
            )

        return flag

    def update_verification_status(
        self,
        flag_id: str,
        status: str,
        reviewer: str = "auditor",
        notes: Optional[str] = None
    ) -> bool:
        """Allows authorized reviewers to update verification status (CONFIRMED, FALSE_POSITIVE, RESOLVED, etc.)."""
        flag = self.get_flag(flag_id)
        if not flag:
            return False

        flag.verification_status = status
        flag.reviewed_by = reviewer
        flag.reviewer_notes = notes
        flag.reviewed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._persist_flag(flag)
        return True

    def get_flag(self, flag_id: str) -> Optional[SecurityFlag]:
        if flag_id in self._flags:
            return self._flags[flag_id]
        # Query SQLite
        try:
            with db.get_connection() as conn:
                cur = conn.execute("SELECT * FROM security_flags WHERE id = ?", (flag_id,))
                row = cur.fetchone()
                if row:
                    flag = SecurityFlag(
                        id=row[0], flag_name=row[1], category=row[2], severity=row[3],
                        confidence_score=row[4], verification_status=row[5], detection_source=row[6],
                        target_ref=row[7], evidence=row[8], timestamp=row[9], affected_component=row[10],
                        technical_explanation=row[11], business_impact=row[12], recommended_remediation=row[13],
                        related_flags=json.loads(row[14]) if row[14] else [], detector_agent_or_tool=row[15],
                        reviewer_notes=row[16], reviewed_by=row[17], reviewed_at=row[18]
                    )
                    self._flags[flag.id] = flag
                    return flag
        except Exception as e:
            clean_id = str(flag_id).replace("\r", "").replace("\n", "")[:64]
            logger.warning(f"Error fetching flag {clean_id}: {e}")
        return None

    def list_flags(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Lists flags with optional filtering."""
        flags = list(self._flags.values())
        if category:
            flags = [f for f in flags if f.category == category]
        if severity:
            flags = [f for f in flags if f.severity == severity]
        if status:
            flags = [f for f in flags if f.verification_status == status]

        flags.sort(key=lambda x: x.timestamp, reverse=True)
        return [f.to_dict() for f in flags[:limit]]

    def get_summary(self) -> Dict[str, Any]:
        """Provides high-level dashboard metrics for the Flag Identification system."""
        total = len(self._flags)
        crit = sum(1 for f in self._flags.values() if f.severity == "CRITICAL")
        high = sum(1 for f in self._flags.values() if f.severity == "HIGH")
        med = sum(1 for f in self._flags.values() if f.severity == "MEDIUM")
        low = sum(1 for f in self._flags.values() if f.severity == "LOW")

        by_cat = {}
        for c in FlagCategory.__members__.values():
            by_cat[c.value] = sum(1 for f in self._flags.values() if f.category == c.value)

        by_status = {}
        for s in VerificationStatus.__members__.values():
            by_status[s.value] = sum(1 for f in self._flags.values() if f.verification_status == s.value)

        return {
            "total_flags": total,
            "critical_count": crit,
            "high_count": high,
            "medium_count": med,
            "low_count": low,
            "by_severity": {
                "CRITICAL": crit,
                "HIGH": high,
                "MEDIUM": med,
                "LOW": low,
            },
            "by_category": by_cat,
            "by_status": by_status,
            "catalog_count": len(FLAG_CATALOG)
        }

    def get_metrics(self) -> Dict[str, Any]:
        return self.get_summary()

    def get_catalog(self, category: Optional[str] = None) -> Dict[str, Any]:
        if not category:
            return FLAG_CATALOG
        return {
            k: v for k, v in FLAG_CATALOG.items()
            if (v.get("category").value if hasattr(v.get("category"), "value") else str(v.get("category"))).lower() == category.lower()
        }

    def record_flag(
        self,
        flag_code: str,
        affected_asset: str = "Target Infrastructure",
        source_module: str = "api",
        evidence: str = "",
        confidence: float = 0.85,
    ) -> SecurityFlag:
        return self.raise_flag(
            flag_name=flag_code,
            target_ref=affected_asset,
            evidence=evidence,
            confidence_score=confidence,
            detection_source=source_module,
        )

    def review_flag(self, flag_id: str, new_status: str, reviewer: str = "auditor", notes: Optional[str] = None) -> bool:
        return self.update_verification_status(flag_id=flag_id, status=new_status, reviewer=reviewer, notes=notes)

    def _persist_flag(self, flag: SecurityFlag):
        try:
            with db.get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO security_flags
                    (id, flag_name, category, severity, confidence_score, verification_status,
                     detection_source, target_ref, evidence, timestamp, affected_component,
                     technical_explanation, business_impact, recommended_remediation, related_flags,
                     detector_agent_or_tool, reviewer_notes, reviewed_by, reviewed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flag.id, flag.flag_name, flag.category, flag.severity, flag.confidence_score, flag.verification_status,
                    flag.detection_source, flag.target_ref, flag.evidence, flag.timestamp, flag.affected_component,
                    flag.technical_explanation, flag.business_impact, flag.recommended_remediation, json.dumps(flag.related_flags),
                    flag.detector_agent_or_tool, flag.reviewer_notes, flag.reviewed_by, flag.reviewed_at
                ))
        except Exception as e:
            logger.warning(f"Error persisting flag to SQLite: {e}")

        if mysql_manager.is_configured():
            try:
                conn = mysql_manager.get_connection()
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO security_flags
                        (id, flag_name, category, severity, confidence_score, verification_status,
                         detection_source, target_ref, evidence, timestamp, affected_component,
                         technical_explanation, business_impact, recommended_remediation, related_flags,
                         detector_agent_or_tool, reviewer_notes, reviewed_by, reviewed_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        verification_status=VALUES(verification_status),
                        reviewer_notes=VALUES(reviewer_notes),
                        reviewed_by=VALUES(reviewed_by),
                        reviewed_at=VALUES(reviewed_at);
                    """, (
                        flag.id, flag.flag_name, flag.category, flag.severity, flag.confidence_score, flag.verification_status,
                        flag.detection_source, flag.target_ref, flag.evidence, flag.timestamp, flag.affected_component,
                        flag.technical_explanation, flag.business_impact, flag.recommended_remediation, json.dumps(flag.related_flags),
                        flag.detector_agent_or_tool, flag.reviewer_notes, flag.reviewed_by, flag.reviewed_at
                    ))
                conn.close()
            except Exception as e:
                logger.warning(f"Error persisting flag to MySQL: {e}")


# Singleton instance
security_flag_engine = SecurityFlagEngine()
security_flags_engine = security_flag_engine
