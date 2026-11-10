"""
SNMK MAP ?" Enterprise Automated Test Suite
Comprehensive testing for network interfaces, Wireshark-style packet dissection,
PCAP/PCAPNG forensics, geolocation, DNS, routing, BGP, Wi-Fi, speed benchmarks,
AI investigation, reporting, and FastAPI REST endpoints.
"""

import os
import sys
import pytest
from starlette.testclient import TestClient

from core.network.models import (
    NetworkInterfaceInfo, LocalNetworkInfo, GeolocationInfo,
    PacketSummary, PacketDetail, FlowSummary, OriginInvestigation
)
from core.network.interfaces import get_local_network_info, get_network_interfaces, check_capture_drivers
from core.network.geo_engine import decimal_to_dms, is_private_ip, geo_engine
from core.network.infrastructure import infra_engine
from core.network.dns_engine import dns_engine, calculate_shannon_entropy
from core.network.packet_engine import PacketDissector, format_hex_dump, parse_tcp_flags, live_capture
from core.network.pcap_forensics import validate_pcap_header, pcap_engine
from core.network.origin_engine import origin_engine
from core.network.discovery import lookup_mac_vendor, discovery_engine
from core.network.routing_engine import route_engine
from core.network.wifi_engine import wifi_engine
from core.network.performance_engine import perf_engine
from core.network.threat_engine import threat_engine
from core.network.ai_assistant import map_ai_assistant
from core.network.reporting import report_generator
from web.server import app

client = TestClient(app)


class TestMapSubsystem:
    """Enterprise verification tests for SNMK MAP subsystem."""

    # 1. Interface & Capture Driver Tests
    def test_01_interface_detection(self):
        interfaces = get_network_interfaces()
        assert isinstance(interfaces, list)
        assert len(interfaces) > 0
        primary = interfaces[0]
        assert hasattr(primary, "name")
        assert hasattr(primary, "is_up")
        assert hasattr(primary, "interface_type")

        driver_ok, driver_type = check_capture_drivers()
        assert isinstance(driver_ok, bool)
        assert isinstance(driver_type, str)

    def test_02_local_network_posture(self):
        posture = get_local_network_info()
        assert posture.hostname is not None
        assert posture.local_ipv4 is not None
        assert posture.primary_interface is not None
        assert isinstance(posture.dns_servers, list)

    # 2. Geolocation & Coordinates Tests
    def test_03_decimal_to_dms_conversion(self):
        lat_dms = decimal_to_dms(17.6868, True)
        lon_dms = decimal_to_dms(83.2185, False)
        assert "17°" in lat_dms and "N" in lat_dms
        assert "83°" in lon_dms and "E" in lon_dms

        # Negative coordinates
        south_dms = decimal_to_dms(-33.8688, True)
        assert "33°" in south_dms and "S" in south_dms

    def test_04_private_ip_rejection_for_coordinates(self):
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.5") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("8.8.8.8") is False

    @pytest.mark.anyio
    async def test_05_geolocation_private_ip_handling(self):
        geo = await geo_engine.lookup_ip_geolocation("192.168.0.1")
        assert geo.latitude is None
        assert geo.longitude is None
        assert "Private" in geo.confidence

    # 3. DNS Intelligence & Entropy
    def test_06_shannon_entropy_calculation(self):
        normal_entropy = calculate_shannon_entropy("google")
        assert normal_entropy < 3.0

        high_entropy_str = "a8f3b9c2d1e7f4a5b6c8d9e0f1a2b3c4"
        high_entropy = calculate_shannon_entropy(high_entropy_str)
        assert high_entropy > 3.0

    @pytest.mark.anyio
    async def test_07_dns_resolution(self):
        res = await dns_engine.resolve_all("127.0.0.1")
        assert res["target"] == "127.0.0.1"
        assert res["is_reverse"] is True

    # 4. Wireshark-Style Packet Dissector
    def test_08_packet_dissector_and_hex_dump(self):
        from scapy.all import Ether, IP, TCP, UDP
        dissector = PacketDissector()

        # TCP packet
        raw_tcp = Ether()/IP(src="192.168.1.50", dst="1.1.1.1")/TCP(sport=54321, dport=443, flags="S", seq=1000)
        summary, detail = dissector.dissect(raw_tcp, 1, "Wi-Fi", 0.0)

        assert summary.no == 1
        assert summary.source_ip == "192.168.1.50"
        assert summary.destination_ip == "1.1.1.1"
        assert summary.protocol == "TLS"  # 443 heuristic
        assert "SYN" in summary.tcp_flags
        assert len(detail.layers) >= 3
        assert len(detail.hex_dump) > 0
        assert len(detail.ascii_dump) > 0

        # Retransmission check
        summary2, detail2 = dissector.dissect(raw_tcp, 2, "Wi-Fi", 0.0)
        assert summary2.no == 2

    # 5. PCAP Header Validation
    def test_09_pcap_header_validation(self):
        pcap_magic_le = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"
        is_val, desc = validate_pcap_header(pcap_magic_le)
        assert is_val is True
        assert "Standard PCAP" in desc

        pcapng_magic = b"\x0a\x0d\x0d\x0a\x00\x00\x00\x20"
        is_val2, desc2 = validate_pcap_header(pcapng_magic)
        assert is_val2 is True
        assert "PCAPNG" in desc2

        invalid_data = b"NOT_A_PCAP_FILE_AT_ALL"
        is_val3, _ = validate_pcap_header(invalid_data)
        assert is_val3 is False

    # 6. Network Origin Classification
    @pytest.mark.anyio
    async def test_10_origin_investigation(self):
        res = await origin_engine.investigate_origin("127.0.0.1")
        assert res.target == "127.0.0.1"
        assert "Local Host" in res.origin_classification
        assert len(res.limitations) > 0

    # 7. Device Discovery & MAC Vendor
    def test_11_mac_vendor_lookup(self):
        assert "Intel" in lookup_mac_vendor("14:4F:8A:2F:A4:95")
        assert "Raspberry Pi" in lookup_mac_vendor("B8:27:EB:12:34:56")
        assert lookup_mac_vendor(None) == "Unknown Vendor"

    def test_12_device_discovery(self):
        devs = discovery_engine.discover_local_devices()
        assert isinstance(devs, list)
        assert len(devs) > 0
        # Check local host device is present
        assert any(d.device_type.startswith("Workstation") for d in devs)

    # 8. Threat Intelligence Port Classification
    @pytest.mark.anyio
    async def test_13_threat_suspicious_ports(self):
        th = await threat_engine.evaluate_endpoint("192.168.1.100", 4444)
        assert th.is_malicious is True
        assert "Metasploit" in th.threat_category

        th_normal = await threat_engine.evaluate_endpoint("192.168.1.100", 80)
        assert th_normal.is_malicious is False

    # 9. AI Investigation Telemetry Grounding
    @pytest.mark.anyio
    async def test_14_ai_assistant_grounding(self):
        ans = await map_ai_assistant.answer_query("Identify the origin of this connection.")
        assert "response" in ans
        assert len(ans["response"]) > 20
        assert len(ans["evidence_citations"]) > 0

    # 10. Multi-format Report Generation
    def test_15_report_generation(self):
        local_info = get_local_network_info().dict()
        rep_data = report_generator.compile_report_data(
            assessment_id="TEST-MAP-01",
            target="192.168.0.10",
            local_info=local_info,
            public_ip_info={"ip": "49.204.237.171"},
            isp_asn_info={"isp": "ACT Broadband", "asn": "AS24309", "asn_org": "Atria"},
            geo_info={"city": "Rasapudipalem", "country": "IN", "latitude": 17.7331, "longitude": 83.3162, "lat_dms": "17°43'59\"N", "lon_dms": "83°18'58\"E"},
            packet_stats={"total_packets": 50, "protocol_hierarchy": {"TCP": 30, "UDP": 20}},
            flows=[],
            devices=[],
            dns_data={"target": "127.0.0.1", "records": []},
            route_data={"hops": []},
            wifi_data=None,
            perf_data=None,
            ai_summary=None
        )

        md = report_generator.to_markdown(rep_data)
        assert "# SNMK MAP" in md
        assert "AS24309" in md

        html = report_generator.to_html(rep_data)
        assert "<!DOCTYPE html>" in html
        assert "ACT Broadband" in html

        pdf = report_generator.to_pdf(rep_data)
        assert isinstance(pdf, bytes)
        assert len(pdf) > 500

    # 11. FastAPI REST Endpoints Verification
    def test_16_fastapi_endpoints(self):
        # GET /api/network/interfaces
        r1 = client.get("/api/network/interfaces")
        assert r1.status_code == 200
        assert r1.json()["success"] is True
        assert len(r1.json()["interfaces"]) > 0

        # GET /api/network/local-info
        r2 = client.get("/api/network/local-info")
        assert r2.status_code == 200
        assert r2.json()["posture"]["hostname"] is not None

        # GET /api/network/capture/status
        r3 = client.get("/api/network/capture/status")
        assert r3.status_code == 200
        assert "is_running" in r3.json()

        # GET /api/network/capture/packets
        r4 = client.get("/api/network/capture/packets")
        assert r4.status_code == 200
        assert "packets" in r4.json()

        # GET /api/network/devices
        r5 = client.get("/api/network/devices")
        assert r5.status_code == 200
        assert r5.json()["success"] is True

        # POST /api/network/origin/investigate
        r6 = client.post("/api/network/origin/investigate", json={"target": "127.0.0.1", "authorized_confirmation": True})
        assert r6.status_code == 200
        assert "Local Host" in r6.json()["origin"]["origin_classification"]
