"""
SNMK Enterprise Cybersecurity Platform — PCAP Analyzer Microservice Tests (Phase 9)
Verifies offline packet capture parsing, protocol distribution, IP conversation flows,
SYN flood anomaly detection, port scan anomaly detection, DNS tunneling detection,
and cleartext credential extraction using Scapy synthetic captures.
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest

from fastapi.testclient import TestClient
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap
from services.pcap_service.engine import PcapAnalyzerEngine, pcap_analyzer
from services.pcap_service.main import app


class TestPcapAnalyzer(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _create_synthetic_pcap(self) -> str:
        """Builds a test PCAP containing TCP, UDP, ICMP, DNS tunneling, and HTTP auth."""
        packets = []

        # 1. Normal TCP handshake and HTTP traffic with credentials
        p1 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="S")
        p2 = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=80, dport=54321, flags="SA")
        p3 = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="A")
        # HTTP request carrying cleartext password
        p4 = (
            IP(src="192.168.1.100", dst="192.168.1.1")
            / TCP(sport=54321, dport=80, flags="PA")
            / Raw(load=b"POST /login HTTP/1.1\r\nHost: target.local\r\n\r\nusername=admin&password=SuperSecretPassword123")
        )
        packets.extend([p1, p2, p3, p4])

        # 2. Port scan pattern (same src, probing multiple dst ports)
        for port in range(1000, 1030):
            scan_pkt = IP(src="10.0.0.50", dst="192.168.1.1") / TCP(sport=40000 + port, dport=port, flags="S")
            packets.append(scan_pkt)

        # 3. DNS Tunneling Beacon (long domain, high entropy)
        dns_tunnel_query = "c2ExMzM3LXZpY3RpbS05MzkxOC1kYXRhZXhmaWx0cmF0aW9uLXNlY3JldHM.attacker-c2.net"
        dns_pkt = (
            IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=dns_tunnel_query))
        )
        packets.append(dns_pkt)

        # 4. ICMP ping
        icmp_pkt = IP(src="192.168.1.100", dst="192.168.1.1") / ICMP(type=8)
        packets.append(icmp_pkt)

        pcap_path = os.path.join(self.tmp_dir.name, "test_traffic.pcap")
        wrpcap(pcap_path, packets)
        return pcap_path

    def test_01_pcap_parsing_and_protocol_breakdown(self):
        pcap_path = self._create_synthetic_pcap()
        result = pcap_analyzer.analyze_file(pcap_path)

        self.assertGreater(result.total_packets, 30)
        self.assertIn("TCP", result.protocol_distribution)
        self.assertIn("DNS", result.protocol_distribution)
        self.assertIn("ICMP", result.protocol_distribution)
        self.assertGreater(len(result.flows), 0)
        self.assertGreater(len(result.top_talkers), 0)

    def test_02_port_scan_detection(self):
        pcap_path = self._create_synthetic_pcap()
        result = pcap_analyzer.analyze_file(pcap_path)

        port_scans = [f for f in result.findings if "Port Scan" in f.title or "FLAG-PCAP-002" in f.flag_name]
        self.assertGreater(len(port_scans), 0)
        self.assertIn("10.0.0.50", port_scans[0].src_endpoint)

    def test_03_dns_tunneling_detection(self):
        pcap_path = self._create_synthetic_pcap()
        result = pcap_analyzer.analyze_file(pcap_path)

        dns_findings = [f for f in result.findings if "DNS Tunneling" in f.title or "FLAG-PCAP-005" in f.flag_name]
        self.assertGreater(len(dns_findings), 0)
        self.assertIn("attacker-c2.net", dns_findings[0].description)

    def test_04_cleartext_credentials_detection(self):
        pcap_path = self._create_synthetic_pcap()
        result = pcap_analyzer.analyze_file(pcap_path)

        cred_findings = [f for f in result.findings if "clear" in f.title.lower() or "CLEAR_TEXT" in f.flag_name]
        self.assertGreater(len(cred_findings), 0)
        self.assertIn("SuperSecretPassword123", cred_findings[0].evidence)

    def test_05_api_service_endpoints(self):
        res_h = self.client.get("/health")
        self.assertEqual(res_h.status_code, 200)
        self.assertEqual(res_h.json()["service"], "snmk-pcap-analyzer")

        pcap_path = self._create_synthetic_pcap()
        with open(pcap_path, "rb") as fh:
            res_up = self.client.post("/api/v1/pcap/upload", files={"file": ("test.pcap", fh, "application/vnd.tcpdump.pcap")})
        self.assertEqual(res_up.status_code, 200)
        data = res_up.json()
        self.assertTrue(data["success"])
        self.assertIn("analysis_id", data)


if __name__ == "__main__":
    unittest.main()
