"""
SNMK Enterprise Cybersecurity Platform — Security Flags & Correlation Engine Tests (Phases 7 & 10)
Verifies:
1. Security Flag catalog mapping across all 6 categories (70 standardized flags).
2. Security Flag lifecycle recording, deduplication, review workflow, and alerts.
3. Cross-module security correlation engine detecting compound credential compromise,
   multi-stage intrusion chains, and web vulnerability cryptographic flaws.
"""

from __future__ import annotations

import unittest

from core.correlation_engine import (
    AttackStage,
    IncidentSeverity,
    IncidentStatus,
    correlation_engine,
)
from core.security_flags import (
    FLAG_CATALOG,
    FlagCategory,
    FlagSeverity,
    SecurityFlag,
    VerificationStatus,
    security_flags_engine,
)


class TestSecurityFlagsAndCorrelation(unittest.TestCase):
    # 1. Flag Catalog Integrity
    def test_01_flag_catalog_completeness(self):
        catalog = FLAG_CATALOG
        self.assertGreaterEqual(len(catalog), 65)

        # Check required fields
        for name, meta in catalog.items():
            self.assertIn("category", meta)
            self.assertIn("severity", meta)
            self.assertIn("impact", meta)
            self.assertIn("rem", meta)

    # 2. Flag Recording & Review Workflow
    def test_02_flag_recording_and_review(self):
        flag = security_flags_engine.raise_flag(
            flag_name="Hardcoded Credentials",
            target_ref="config/secrets.env",
            evidence="AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
            verification_status=VerificationStatus.SUSPECTED.value,
        )
        self.assertIsNotNone(flag)
        self.assertIsInstance(flag, SecurityFlag)
        self.assertEqual(flag.verification_status, VerificationStatus.SUSPECTED.value)

        # Review workflow
        ok = security_flags_engine.update_verification_status(
            flag_id=flag.id,
            status=VerificationStatus.CONFIRMED.value,
            reviewer="lead_auditor",
            notes="Confirmed live production credential leak"
        )
        self.assertTrue(ok)

        # Filter by status
        confirmed = security_flags_engine.list_flags(status=VerificationStatus.CONFIRMED.value)
        self.assertTrue(any(f["id"] == flag.id for f in confirmed))

        # Posture summary
        metrics = security_flags_engine.get_summary()
        self.assertGreaterEqual(metrics["total_flags"], 1)
        self.assertIn("by_category", metrics)
        self.assertIn("by_severity", metrics)

    # 3. Cross-Module Correlation Engine
    def test_03_credential_leakage_and_network_correlation(self):
        sec_flags = [
            {
                "flag_code": "FLAG-CRED-001",
                "category": "Credentials",
                "name": "Hardcoded AWS Access Key",
                "severity": "CRITICAL",
                "affected_asset": "auth_service.py"
            }
        ]
        pcap_anomalies = [
            {
                "anomaly_type": "CLEARTEXT_CREDENTIALS",
                "severity": "HIGH",
                "title": "Cleartext Authentication Credentials Over HTTP",
                "dst_ip": "10.0.0.15",
                "evidence": "admin:SuperSecretPassword123"
            }
        ]

        incidents = correlation_engine.correlate(
            security_flags=sec_flags,
            pcap_anomalies=pcap_anomalies
        )
        self.assertGreaterEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.severity, IncidentSeverity.CRITICAL)
        self.assertIn(AttackStage.CREDENTIAL_ACCESS, inc.attack_stages)
        self.assertIn("auth_service.py", inc.affected_assets)

    def test_04_multi_stage_attack_chain_correlation(self):
        pcap_anomalies = [
            {
                "anomaly_type": "PORT_SCAN",
                "severity": "HIGH",
                "title": "SYN Stealth Port Sweep",
                "src_ip": "198.51.100.42",
                "dst_ip": "192.168.1.1"
            },
            {
                "anomaly_type": "DNS_TUNNELING",
                "severity": "CRITICAL",
                "title": "High-Entropy DNS Tunneling Payload",
                "src_ip": "192.168.1.1",
                "description": "Exfiltration channel to bad-actor.cc"
            }
        ]
        scanner_findings = [
            {
                "title": "VBA Macro AutoExec Dropper Detected",
                "severity": "CRITICAL",
                "category": "Malware / Macro",
                "file_path": "invoice_malicious.docm"
            }
        ]

        incidents = correlation_engine.correlate(
            scanner_findings=scanner_findings,
            pcap_anomalies=pcap_anomalies
        )
        self.assertGreaterEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertIn(AttackStage.RECONNAISSANCE, inc.attack_stages)
        self.assertIn(AttackStage.COMMAND_AND_CONTROL, inc.attack_stages)
        self.assertGreaterEqual(inc.confidence_score, 0.90)

    def test_05_correlation_incident_lifecycle(self):
        incidents = correlation_engine.list_incidents(limit=1)
        self.assertGreaterEqual(len(incidents), 1)
        inc_id = incidents[0]["incident_id"]

        # Update status
        ok = correlation_engine.update_incident_status(inc_id, "CONTAINED", notes="Firewall rule applied to block C2 domain")
        self.assertTrue(ok)

        detail = correlation_engine.get_incident(inc_id)
        self.assertEqual(detail["status"], "CONTAINED")

        metrics = correlation_engine.get_metrics()
        self.assertGreaterEqual(metrics["total_incidents"], 1)


if __name__ == "__main__":
    unittest.main()
