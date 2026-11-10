"""
SNMK MAP ?" Network Intelligence & Forensics Pydantic Data Models
Enterprise-grade data schemas for network interfaces, packet forensics,
traffic flows, geolocation, routing, DNS, BGP, Wi-Fi, performance, and reporting.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NetworkInterfaceInfo(BaseModel):
    name: str
    description: str = ""
    interface_type: str = "Ethernet"  # Ethernet, Wi-Fi, Loopback, Virtual, Tunnel
    is_up: bool = False
    speed_mbps: int = 0
    mtu: int = 1500
    mac_address: Optional[str] = None
    ipv4_addresses: List[str] = Field(default_factory=list)
    ipv6_addresses: List[str] = Field(default_factory=list)
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    gateway: Optional[str] = None
    capture_capable: bool = True
    required_permissions: str = "User / Packet Filter Driver"


class LocalNetworkInfo(BaseModel):
    hostname: str
    primary_interface: str
    local_ipv4: str
    local_ipv6: Optional[str] = None
    mac_address: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    subnet_cidr: Optional[str] = None
    interfaces: List[NetworkInterfaceInfo] = Field(default_factory=list)
    capture_driver_installed: bool = False
    capture_driver_type: str = "None"  # Npcap, libpcap, TShark, Socket-only


class GeolocationInfo(BaseModel):
    ip: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    lat_dms: Optional[str] = None  # Degrees, minutes, seconds e.g. 17°41'12.5"N
    lon_dms: Optional[str] = None  # e.g. 83°13'06.6"E
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None
    accuracy_radius_km: Optional[int] = None
    source_provider: str = "Direct IP Intelligence"
    confidence: str = "Approximate Network Location"  # Approximate, Verified Device, Network Infra
    physical_caveat: str = "IP geolocation represents network allocation routing points, not individual physical identity."
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class IspAsnInfo(BaseModel):
    ip: str
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    rdap_registry: Optional[str] = None
    network_prefix: Optional[str] = None
    reverse_dns: Optional[str] = None
    bgp_announced: bool = True
    country: Optional[str] = None


class PacketSummary(BaseModel):
    no: int
    timestamp: float
    time_str: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str  # TCP, UDP, ICMP, DNS, TLS, HTTP, ARP, etc.
    length: int
    interface: str = "default"
    info: str
    tcp_flags: Optional[str] = None  # SYN, ACK, FIN, RST, PSH, URG
    is_retransmission: bool = False
    is_suspicious: bool = False


class PacketDetail(BaseModel):
    summary: PacketSummary
    frame_info: Dict[str, Any] = Field(default_factory=dict)
    layers: List[str] = Field(default_factory=list)
    layer_fields: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    hex_dump: str = ""
    ascii_dump: str = ""
    expert_info: List[str] = Field(default_factory=list)


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
    source_asn: Optional[str] = None
    dest_asn: Optional[str] = None
    dest_country: Optional[str] = None
    is_suspicious: bool = False


class OriginInvestigation(BaseModel):
    target: str
    target_type: str  # IPv4, IPv6, Domain, CIDR
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    source_mac: Optional[str] = None
    source_hostname: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    destination_hostname: Optional[str] = None
    isp_info: Optional[IspAsnInfo] = None
    geo_info: Optional[GeolocationInfo] = None
    origin_classification: str = "Unknown"  # Local device, Gateway, Private network, Public internet endpoint, ISP infrastructure, Corporate, Cloud hosting, CDN, VPN/proxy, Unknown
    confidence: str = "Medium"
    classification_evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    first_observed: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    last_observed: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DiscoveredDevice(BaseModel):
    ip: str
    mac_address: Optional[str] = None
    vendor: Optional[str] = "Unknown Vendor"
    hostname: Optional[str] = None
    device_type: str = "Endpoint"  # Gateway, Server, Workstation, IoT, Mobile, Endpoint
    is_gateway: bool = False
    is_reachable: bool = True
    response_time_ms: Optional[float] = None
    open_ports: List[int] = Field(default_factory=list)
    first_seen: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
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
    hostname: Optional[str] = None
    rtt_ms: List[float] = Field(default_factory=list)
    avg_rtt_ms: Optional[float] = None
    packet_loss_pct: float = 0.0
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    status: str = "SUCCESS"  # SUCCESS, TIMEOUT, FILTERED


class BgpPrefixInfo(BaseModel):
    prefix: str
    origin_asn: str
    asn_name: str
    as_path: List[str] = Field(default_factory=list)
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
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    status: str = "COMPLETED"


class WifiIntelligence(BaseModel):
    interface_name: str
    ssid: Optional[str] = None
    bssid: Optional[str] = None
    signal_pct: int = 0
    rssi_dbm: Optional[int] = None
    channel: Optional[int] = None
    band: Optional[str] = None  # 2.4 GHz, 5 GHz, 6 GHz
    radio_type: Optional[str] = None  # 802.11ax, 802.11ac, 802.11n
    auth_cipher: Optional[str] = None  # WPA2-Personal, WPA3, etc.
    tx_rate_mbps: Optional[int] = None
    rx_rate_mbps: Optional[int] = None
    quality_assessment: str = "Good"
    security_warnings: List[str] = Field(default_factory=list)


class ThreatIntelligenceMatch(BaseModel):
    ip: str
    source_service: str  # VirusTotal, AbuseIPDB, AlienVault, Shodan
    reputation_score: int = 0  # 0 to 100
    is_malicious: bool = False
    threat_category: Optional[str] = None
    total_reports: int = 0
    last_reported: Optional[str] = None
    recommended_action: str = "Monitor"


class MapAssessmentSession(BaseModel):
    assessment_id: str
    status: str = "IDLE"  # IDLE, RUNNING, STOPPED, COMPLETED, ERROR
    mode: str = "on_demand"
    target: str = ""
    profile: str = "Complete Network Intelligence"
    interface: str = "default"
    start_time: Optional[str] = None
    end_time: Optional[str] = None
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
    subnet_cidr: Optional[str] = None
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
    context: Optional[Dict[str, Any]] = None
    model_override: Optional[str] = None


class GeocodeRequest(BaseModel):
    query: str  # Address or coordinates "17.7331, 83.3162"
