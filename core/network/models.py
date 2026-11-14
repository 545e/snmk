"""
SNMK MAP ?" Network Intelligence & Forensics Pydantic Data Models
Enterprise-grade data schemas for network interfaces, packet forensics,
traffic flows, geolocation, routing, DNS, BGP, Wi-Fi, performance, and reporting.
"""

from __future__ import annotations

import datetime
from typing import Any

from pydantic import BaseModel, Field


class NetworkInterfaceInfo(BaseModel):
    name: str
    description: str = ""
    interface_type: str = "Ethernet"  # Ethernet, Wi-Fi, Loopback, Virtual, Tunnel
    is_up: bool = False
    speed_mbps: int = 0
    mtu: int = 1500
    mac_address: str | None = None
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    netmask: str | None = None
    broadcast: str | None = None
    gateway: str | None = None
    capture_capable: bool = True
    required_permissions: str = "User / Packet Filter Driver"


class LocalNetworkInfo(BaseModel):
    hostname: str
    primary_interface: str
    local_ipv4: str
    local_ipv6: str | None = None
    mac_address: str | None = None
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    subnet_cidr: str | None = None
    interfaces: list[NetworkInterfaceInfo] = Field(default_factory=list)
    capture_driver_installed: bool = False
    capture_driver_type: str = "None"  # Npcap, libpcap, TShark, Socket-only


class GeolocationInfo(BaseModel):
    ip: str
    latitude: float | None = None
    longitude: float | None = None
    lat_dms: str | None = None  # Degrees, minutes, seconds e.g. 17°41'12.5"N
    lon_dms: str | None = None  # e.g. 83°13'06.6"E
    city: str | None = None
    region: str | None = None
    country: str | None = None
    country_code: str | None = None
    postal: str | None = None
    timezone: str | None = None
    accuracy_radius_km: int | None = None
    source_provider: str = "Direct IP Intelligence"
    confidence: str = "Approximate Network Location"  # Approximate, Verified Device, Network Infra
    physical_caveat: str = "IP geolocation represents network allocation routing points, not individual physical identity."
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class IspAsnInfo(BaseModel):
    ip: str
    asn: str | None = None
    asn_org: str | None = None
    isp: str | None = None
    organization: str | None = None
    rdap_registry: str | None = None
    network_prefix: str | None = None
    reverse_dns: str | None = None
    bgp_announced: bool = True
    country: str | None = None


class PacketSummary(BaseModel):
    no: int
    timestamp: float
    time_str: str
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str  # TCP, UDP, ICMP, DNS, TLS, HTTP, ARP, etc.
    length: int
    interface: str = "default"
    info: str
    tcp_flags: str | None = None  # SYN, ACK, FIN, RST, PSH, URG
    is_retransmission: bool = False
    is_suspicious: bool = False


class PacketDetail(BaseModel):
    summary: PacketSummary
    frame_info: dict[str, Any] = Field(default_factory=dict)
    layers: list[str] = Field(default_factory=list)
    layer_fields: dict[str, dict[str, Any]] = Field(default_factory=dict)
    hex_dump: str = ""
    ascii_dump: str = ""
    expert_info: list[str] = Field(default_factory=list)


class FlowSummary(BaseModel):
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_seconds: float = 0.0
    first_seen: str
    last_seen: str
    state: str = "ESTABLISHED"
    source_asn: str | None = None
    dest_asn: str | None = None
    dest_country: str | None = None
    is_suspicious: bool = False


class OriginInvestigation(BaseModel):
    target: str
    target_type: str  # IPv4, IPv6, Domain, CIDR
    source_ip: str | None = None
    source_port: int | None = None
    source_mac: str | None = None
    source_hostname: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    destination_hostname: str | None = None
    isp_info: IspAsnInfo | None = None
    geo_info: GeolocationInfo | None = None
    origin_classification: str = "Unknown"  # Local device, Gateway, Private network, Public internet endpoint, ISP infrastructure, Corporate, Cloud hosting, CDN, VPN/proxy, Unknown
    confidence: str = "Medium"
    classification_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    first_observed: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    last_observed: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class DiscoveredDevice(BaseModel):
    ip: str
    mac_address: str | None = None
    vendor: str | None = "Unknown Vendor"
    hostname: str | None = None
    device_type: str = "Endpoint"  # Gateway, Server, Workstation, IoT, Mobile, Endpoint
    is_gateway: bool = False
    is_reachable: bool = True
    response_time_ms: float | None = None
    open_ports: list[int] = Field(default_factory=list)
    first_seen: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    status: str = "ACTIVE"  # ACTIVE, REMOVED, NEW, CHANGED


class DnsRecord(BaseModel):
    domain: str
    record_type: str  # A, AAAA, MX, NS, TXT, CNAME, PTR, SOA, SRV
    value: str
    ttl: int = 300
    resolver: str = "System"
    response_time_ms: float = 0.0


class RouteHop(BaseModel):
    hop: int
    ip: str
    hostname: str | None = None
    rtt_ms: list[float] = Field(default_factory=list)
    avg_rtt_ms: float | None = None
    packet_loss_pct: float = 0.0
    asn: str | None = None
    isp: str | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    status: str = "SUCCESS"  # SUCCESS, TIMEOUT, FILTERED


class BgpPrefixInfo(BaseModel):
    prefix: str
    origin_asn: str
    asn_name: str
    as_path: list[str] = Field(default_factory=list)
    registry: str = "RIPE/ARIN"
    announcing_country: str = "Unknown"
    is_valid: bool = True


class SpeedTestResult(BaseModel):
    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    ping_ms: float = 0.0
    jitter_ms: float = 0.0
    packet_loss_pct: float = 0.0
    dns_time_ms: float = 0.0
    test_server: str = "Local Network Test Server"
    test_duration_seconds: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    status: str = "COMPLETED"


class WifiIntelligence(BaseModel):
    interface_name: str
    ssid: str | None = None
    bssid: str | None = None
    signal_pct: int = 0
    rssi_dbm: int | None = None
    channel: int | None = None
    band: str | None = None  # 2.4 GHz, 5 GHz, 6 GHz
    radio_type: str | None = None  # 802.11ax, 802.11ac, 802.11n
    auth_cipher: str | None = None  # WPA2-Personal, WPA3, etc.
    tx_rate_mbps: int | None = None
    rx_rate_mbps: int | None = None
    quality_assessment: str = "Good"
    security_warnings: list[str] = Field(default_factory=list)


class ThreatIntelligenceMatch(BaseModel):
    ip: str
    source_service: str  # VirusTotal, AbuseIPDB, AlienVault, Shodan
    reputation_score: int = 0  # 0 to 100
    is_malicious: bool = False
    threat_category: str | None = None
    total_reports: int = 0
    last_reported: str | None = None
    recommended_action: str = "Monitor"


class MapAssessmentSession(BaseModel):
    assessment_id: str
    status: str = "IDLE"  # IDLE, RUNNING, STOPPED, COMPLETED, ERROR
    mode: str = "on_demand"
    target: str = ""
    profile: str = "Complete Network Intelligence"
    interface: str = "default"
    start_time: str | None = None
    end_time: str | None = None
    packets_captured: int = 0
    flows_identified: int = 0
    devices_discovered: int = 0
    threats_flagged: int = 0


# Request Schemas
class CaptureStartRequest(BaseModel):
    interface: str = "default"
    packet_limit: int = 100
    duration_limit: int = 30
    bpf_filter: str = ""
    promiscuous: bool = False


class DiscoveryStartRequest(BaseModel):
    interface: str = "default"
    subnet_cidr: str | None = None
    authorized_confirmation: bool = True


class OriginInvestigationRequest(BaseModel):
    target: str
    authorized_confirmation: bool = True


class RouteAnalyzeRequest(BaseModel):
    target: str
    max_hops: int = 20
    timeout: float = 2.0


class SpeedTestRequest(BaseModel):
    include_upload: bool = True
    duration_seconds: int = 5


class AiQueryRequest(BaseModel):
    query: str
    context: dict[str, Any] | None = None
    model_override: str | None = None


class GeocodeRequest(BaseModel):
    query: str  # Address or coordinates "17.7331, 83.3162"
