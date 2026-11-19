"""
SNMK Enterprise Cybersecurity Platform — Cross-Module Security Correlation Engine
Correlates findings across Universal Scanner, Security Flags, Cryptography Workbench,
PCAP Analyzer, and SAST to identify multi-stage attack chains, linked indicators, and compound risks.
"""

from __future__ import annotations

import datetime
import enum
import json
import logging
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("snmk.correlation_engine")

DB_PATH = Path("data/snmk_database.sqlite3")


class AttackStage(str, enum.Enum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class IncidentStatus(str, enum.Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class CorrelatedIncident:
    """Represents a unified security incident constructed from multiple correlated findings."""

    def __init__(
        self,
        incident_id: str,
        title: str,
        severity: IncidentSeverity,
        confidence_score: float,
        attack_stages: List[AttackStage],
        description: str,
        affected_assets: List[str],
        events: List[Dict[str, Any]],
        mitre_tactics: List[str],
        recommended_actions: List[str],
        status: IncidentStatus = IncidentStatus.NEW,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.incident_id = incident_id
        self.title = title
        self.severity = severity
        self.confidence_score = round(confidence_score, 2)
        self.attack_stages = attack_stages
        self.description = description
        self.affected_assets = affected_assets
        self.events = events
        self.mitre_tactics = mitre_tactics
        self.recommended_actions = recommended_actions
        self.status = status
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.created_at = created_at or now_iso
        self.updated_at = updated_at or now_iso

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence_score": self.confidence_score,
            "attack_stages": [s.value for s in self.attack_stages],
            "description": self.description,
            "affected_assets": self.affected_assets,
            "event_count": len(self.events),
            "events": self.events,
            "mitre_tactics": self.mitre_tactics,
            "recommended_actions": self.recommended_actions,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class CorrelationEngine:
    """
    Evaluates cross-module indicators from Universal Scanner, Security Flags,
    PCAP Network Flow Analysis, and Crypto Workbench to detect cohesive attacks.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._incidents: Dict[str, CorrelatedIncident] = {}
        self._init_db()
        self._load_from_db()

    def _init_db(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS correlated_incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        attack_stages TEXT NOT NULL,
                        description TEXT NOT NULL,
                        affected_assets TEXT NOT NULL,
                        events_json TEXT NOT NULL,
                        mitre_tactics TEXT NOT NULL,
                        recommended_actions TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_corr_severity ON correlated_incidents(severity)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_corr_status ON correlated_incidents(status)")
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to initialize correlated_incidents table: {e}")

    def _load_from_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT * FROM correlated_incidents ORDER BY created_at DESC LIMIT 500")
                for row in cur.fetchall():
                    inc = CorrelatedIncident(
                        incident_id=row["incident_id"],
                        title=row["title"],
                        severity=IncidentSeverity(row["severity"]),
                        confidence_score=row["confidence_score"],
                        attack_stages=[AttackStage(s) for s in json.loads(row["attack_stages"])],
                        description=row["description"],
                        affected_assets=json.loads(row["affected_assets"]),
                        events=json.loads(row["events_json"]),
                        mitre_tactics=json.loads(row["mitre_tactics"]),
                        recommended_actions=json.loads(row["recommended_actions"]),
                        status=IncidentStatus(row["status"]),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                    )
                    self._incidents[inc.incident_id] = inc
        except Exception as e:
            logger.warning(f"Error loading correlated incidents from DB: {e}")

    def _save_incident(self, inc: CorrelatedIncident):
        with self._lock:
            self._incidents[inc.incident_id] = inc
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO correlated_incidents
                    (incident_id, title, severity, confidence_score, attack_stages, description,
                     affected_assets, events_json, mitre_tactics, recommended_actions, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        title = excluded.title,
                        severity = excluded.severity,
                        confidence_score = excluded.confidence_score,
                        attack_stages = excluded.attack_stages,
                        description = excluded.description,
                        affected_assets = excluded.affected_assets,
                        events_json = excluded.events_json,
                        mitre_tactics = excluded.mitre_tactics,
                        recommended_actions = excluded.recommended_actions,
                        status = excluded.status,
                        updated_at = excluded.updated_at
                """, (
                    inc.incident_id,
                    inc.title,
                    inc.severity.value,
                    inc.confidence_score,
                    json.dumps([s.value for s in inc.attack_stages]),
                    inc.description,
                    json.dumps(inc.affected_assets),
                    json.dumps(inc.events),
                    json.dumps(inc.mitre_tactics),
                    json.dumps(inc.recommended_actions),
                    inc.status.value,
                    inc.created_at,
                    inc.updated_at,
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to persist correlated incident {inc.incident_id}: {e}")

    def correlate(
        self,
        scanner_findings: Optional[List[Dict[str, Any]]] = None,
        security_flags: Optional[List[Dict[str, Any]]] = None,
        pcap_anomalies: Optional[List[Dict[str, Any]]] = None,
        crypto_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CorrelatedIncident]:
        """
        Runs multi-heuristic correlation rules across findings from all modules.
        Returns newly generated or updated CorrelatedIncident records.
        """
        scanner_findings = scanner_findings or []
        security_flags = security_flags or []
        pcap_anomalies = pcap_anomalies or []
        crypto_findings = crypto_findings or []

        generated_incidents: List[CorrelatedIncident] = []

        # --- Rule 1: Credential Exposure to Network Auth Leakage ---
        # Discovered password/API secret in file/code + Cleartext credential in PCAP or Web traffic
        cred_flags = [
            f for f in security_flags
            if f.get("category") == "Credentials" or "CRED_" in f.get("flag_code", "")
        ]
        pcap_cred_anomalies = [
            a for a in pcap_anomalies
            if a.get("anomaly_type") == "CLEARTEXT_CREDENTIALS" or "credential" in a.get("title", "").lower()
        ]
        if cred_flags and pcap_cred_anomalies:
            assets = list({f.get("affected_asset", "") for f in cred_flags} | {a.get("dst_ip", "") for a in pcap_cred_anomalies} - {""})
            matched_events = [
                {"source": "security_flags", "data": cred_flags[0]},
                {"source": "pcap_analyzer", "data": pcap_cred_anomalies[0]},
            ]
            inc = CorrelatedIncident(
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                title="Compound Credential Compromise: Code Exposure & Cleartext Network Transmission",
                severity=IncidentSeverity.CRITICAL,
                confidence_score=0.95,
                attack_stages=[AttackStage.CREDENTIAL_ACCESS, AttackStage.LATERAL_MOVEMENT],
                description="Secrets discovered in source files or environment variables correlate with unencrypted authentication credentials transmitted over network protocols.",
                affected_assets=assets or ["Application Codebase", "Internal Gateway"],
                events=matched_events,
                mitre_tactics=["T1552 - Unsecured Credentials", "T1040 - Network Sniffing", "T1078 - Valid Accounts"],
                recommended_actions=[
                    "Immediately revoke and rotate all exposed API tokens and database passwords",
                    "Enforce strict TLS 1.3 encryption across all communication paths",
                    "Add automated pre-commit secret scanning hooks",
                ],
            )
            self._save_incident(inc)
            generated_incidents.append(inc)

        # --- Rule 2: Reconnaissance to Weaponized Delivery / C2 ---
        # Port scan in PCAP + Suspicious File/Doc in Scanner + DNS Tunneling in PCAP
        port_scans = [a for a in pcap_anomalies if a.get("anomaly_type") == "PORT_SCAN"]
        dns_tunnels = [a for a in pcap_anomalies if a.get("anomaly_type") == "DNS_TUNNELING"]
        suspicious_files = [
            f for f in scanner_findings
            if f.get("severity") in ("CRITICAL", "HIGH") and any(k in f.get("category", "").lower() for k in ("malware", "macro", "polyglot", "executable"))
        ]

        if port_scans and (dns_tunnels or suspicious_files):
            stages = [AttackStage.RECONNAISSANCE]
            tactics = ["T1046 - Network Service Discovery"]
            events: List[Dict[str, Any]] = [{"source": "pcap_analyzer", "data": port_scans[0]}]

            if suspicious_files:
                stages.append(AttackStage.EXECUTION)
                tactics.append("T1204 - User Execution")
                events.append({"source": "universal_scanner", "data": suspicious_files[0]})

            if dns_tunnels:
                stages.append(AttackStage.COMMAND_AND_CONTROL)
                tactics.append("T1071.004 - DNS Command and Control")
                events.append({"source": "pcap_analyzer", "data": dns_tunnels[0]})

            assets = list({port_scans[0].get("dst_ip", ""), port_scans[0].get("src_ip", "")} - {""})
            inc = CorrelatedIncident(
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                title="Multi-Stage Intrusion Chain: Reconnaissance, Payload Staging & Covert C2",
                severity=IncidentSeverity.CRITICAL,
                confidence_score=0.92,
                attack_stages=stages,
                description="Observed active port scanning followed by weaponized payload discovery and high-entropy DNS tunneling beacons indicative of command-and-control communication.",
                affected_assets=assets or ["Target Perimeter", "DNS Resolver"],
                events=events,
                mitre_tactics=tactics,
                recommended_actions=[
                    "Isolate host IP executing DNS tunneling beacons from network segment",
                    "Block scanning source IP at edge firewall / perimeter WAF",
                    "Quarantine and perform sandbox dynamic analysis on flagged artifact",
                ],
            )
            self._save_incident(inc)
            generated_incidents.append(inc)

        # --- Rule 3: Web Application Vulnerability Linked to Insecure Crypto ---
        # Web flaw (e.g. SQLi / Broken Auth) + Deprecated/Weak Crypto Algorithm
        web_vulns = [
            f for f in scanner_findings
            if any(term in f.get("title", "").lower() for term in ("injection", "auth", "bypass", "jwt", "cross-site"))
        ]
        weak_crypto = [
            c for c in crypto_findings
            if any(term in str(c).lower() for term in ("md5", "sha1", "des", "rc4", "ecb", "insecure", "deprecated"))
        ]
        if web_vulns and weak_crypto:
            inc = CorrelatedIncident(
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                title="Cryptographic Degradation in Vulnerable Web Application Flow",
                severity=IncidentSeverity.HIGH,
                confidence_score=0.88,
                attack_stages=[AttackStage.INITIAL_ACCESS, AttackStage.DEFENSE_EVASION],
                description="Web application entry points exhibiting input sanitization flaws utilize obsolete cryptographic primitives, enabling token forging and integrity bypass.",
                affected_assets=[f.get("file_path") or f.get("title") for f in web_vulns[:2]],
                events=[
                    {"source": "universal_scanner", "data": web_vulns[0]},
                    {"source": "crypto_workbench", "data": weak_crypto[0]},
                ],
                mitre_tactics=["T1190 - Exploit Public-Facing Application", "T1588.006 - Security Tools Cryptographic Flaws"],
                recommended_actions=[
                    "Upgrade all legacy hashing algorithms to SHA-256 or Argon2id",
                    "Enforce authenticated encryption using AES-256-GCM or ChaCha20-Poly1305",
                    "Sanitize web application parameters using parameterized queries and strict input schemas",
                ],
            )
            self._save_incident(inc)
            generated_incidents.append(inc)

        # --- Rule 4: Generic Compound Risk Rule ---
        # If there are multiple critical findings across 2 or more distinct sources, cluster them
        distinct_sources = set()
        all_crit: List[Dict[str, Any]] = []
        for f in scanner_findings:
            if f.get("severity") == "CRITICAL":
                distinct_sources.add("universal_scanner")
                all_crit.append({"source": "universal_scanner", "data": f})
        for f in security_flags:
            if f.get("severity") == "CRITICAL":
                distinct_sources.add("security_flags")
                all_crit.append({"source": "security_flags", "data": f})
        for a in pcap_anomalies:
            if a.get("severity") == "CRITICAL":
                distinct_sources.add("pcap_analyzer")
                all_crit.append({"source": "pcap_analyzer", "data": a})

        if len(distinct_sources) >= 2 and len(all_crit) >= 2 and not generated_incidents:
            inc = CorrelatedIncident(
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                title="High-Priority Cross-Domain Security Event Cluster",
                severity=IncidentSeverity.CRITICAL,
                confidence_score=0.85,
                attack_stages=[AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION],
                description=f"Multiple concurrent critical security indicators observed across {len(distinct_sources)} independent monitoring surfaces.",
                affected_assets=["SNMK Monitored Infrastructure"],
                events=all_crit[:5],
                mitre_tactics=["T1190 - Initial Compromise", "T1059 - Command and Scripting Interpreter"],
                recommended_actions=[
                    "Triage critical alerts in the Security Flag and Network Analyzer views",
                    "Audit affected services and apply patching or network segmentation",
                ],
            )
            self._save_incident(inc)
            generated_incidents.append(inc)

        return generated_incidents

    def list_incidents(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            incidents = list(self._incidents.values())

        if severity:
            incidents = [i for i in incidents if i.severity.value == severity.upper()]
        if status:
            incidents = [i for i in incidents if i.status.value == status.upper()]

        incidents.sort(key=lambda x: x.created_at, reverse=True)
        return [i.to_dict() for i in incidents[:limit]]

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            inc = self._incidents.get(incident_id)
            return inc.to_dict() if inc else None

    def update_incident_status(
        self,
        incident_id: str,
        new_status: str,
        notes: Optional[str] = None,
    ) -> bool:
        try:
            st = IncidentStatus(new_status.upper())
        except ValueError:
            return False

        with self._lock:
            inc = self._incidents.get(incident_id)
            if not inc:
                return False
            inc.status = st
            inc.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if notes:
                inc.events.append({
                    "source": "triage_note",
                    "timestamp": inc.updated_at,
                    "note": notes,
                })
            self._save_incident(inc)
            return True

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            incidents = list(self._incidents.values())

        by_severity = {s.value: 0 for s in IncidentSeverity}
        by_status = {st.value: 0 for st in IncidentStatus}
        by_stage: Dict[str, int] = {}

        for inc in incidents:
            by_severity[inc.severity.value] = by_severity.get(inc.severity.value, 0) + 1
            by_status[inc.status.value] = by_status.get(inc.status.value, 0) + 1
            for stage in inc.attack_stages:
                by_stage[stage.value] = by_stage.get(stage.value, 0) + 1

        return {
            "total_incidents": len(incidents),
            "open_incidents": sum(1 for i in incidents if i.status not in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE)),
            "by_severity": by_severity,
            "by_status": by_status,
            "by_stage": by_stage,
            "last_evaluated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }


# Global singleton instance
correlation_engine = CorrelationEngine()
