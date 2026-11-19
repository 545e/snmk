"""
SNMK — PCAP Analyzer & Network Forensics Engine (Phase 9)
Offline packet capture analyzer supporting .pcap and .pcapng:
1. Protocol Analysis (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, TLS)
2. Network Flow Extraction & Conversation Reconstruction
3. Anomaly & Threat Detection (Port Scans, SYN Floods, DNS Tunneling, Cleartext Credentials)
4. Sanitization & Evidence Export
"""

from __future__ import annotations

import datetime
import math
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Scapy with safe fallbacks
try:
    from scapy.all import (
        ARP,
        DNS,
        DNSRR,
        ICMP,
        IP,
        IPv6,
        TCP,
        UDP,
        Ether,
        Raw,
        rdpcap,
    )
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


@dataclass
class PacketRecord:
    packet_number: int
    timestamp: float
    time_iso: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    length: int = 0
    info: str = ""
    tcp_flags: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    total_packets: int
    total_bytes: int
    duration_sec: float
    start_time: str
    end_time: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PcapFinding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    analysis_id: str = ""
    flag_name: str = ""
    severity: str = "MEDIUM"
    confidence: float = 0.85
    title: str = ""
    description: str = ""
    evidence: str = ""
    src_endpoint: str = ""
    dst_endpoint: str = ""
    protocol: str = ""
    packet_numbers: List[int] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PcapAnalysisResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    filename: str = ""
    file_size_bytes: int = 0
    total_packets: int = 0
    duration_seconds: float = 0.0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Dict[str, Any]] = field(default_factory=list)
    packets: List[PacketRecord] = field(default_factory=list)
    flows: List[FlowRecord] = field(default_factory=list)
    findings: List[PcapFinding] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    completed_at: Optional[str] = None
    status: str = "COMPLETED"

    def to_dict(self, include_packets: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "filename": self.filename,
            "file_size_bytes": self.file_size_bytes,
            "total_packets": self.total_packets,
            "duration_seconds": round(self.duration_seconds, 2),
            "protocol_distribution": self.protocol_distribution,
            "top_talkers": self.top_talkers,
            "flows_count": len(self.flows),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
        }
        if include_packets:
            data["packets"] = [p.to_dict() for p in self.packets[:1000]]  # cap preview
            data["flows"] = [fl.to_dict() for fl in self.flows[:100]]
        return data


class PcapAnalyzerEngine:
    """Offline Deep Packet Inspection and Forensics Analysis Engine."""

    MAX_ANALYSIS_PACKETS = 10000

    def analyze_file(self, pcap_path: str, max_packets: int = MAX_ANALYSIS_PACKETS) -> PcapAnalysisResult:
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        file_size = os.path.getsize(pcap_path)
        filename = os.path.basename(pcap_path)

        result = PcapAnalysisResult(
            filename=filename,
            file_size_bytes=file_size
        )

        if not SCAPY_AVAILABLE:
            result.status = "FAILED"
            result.findings.append(PcapFinding(
                analysis_id=result.id,
                flag_name="TOOL_UNAVAILABLE",
                severity="HIGH",
                title="Scapy Network Forensics Module Unavailable",
                description="The scapy packet inspection library is not accessible in this environment."
            ))
            return result

        try:
            packets = rdpcap(pcap_path, count=max_packets)
        except Exception as e:
            result.status = "FAILED"
            result.findings.append(PcapFinding(
                analysis_id=result.id,
                flag_name="SUSPICIOUS_FILE_SIGNATURE",
                severity="MEDIUM",
                title="Malformed or Unsupported PCAP File Structure",
                description=f"Could not parse packet capture: {str(e)}"
            ))
            return result

        result.total_packets = len(packets)
        if result.total_packets == 0:
            result.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            return result

        # First pass: parse packets and populate statistics
        first_ts = float(packets[0].time) if hasattr(packets[0], 'time') else 0.0
        last_ts = float(packets[-1].time) if hasattr(packets[-1], 'time') else 0.0
        result.duration_seconds = max(0.0, last_ts - first_ts)

        proto_counts: Dict[str, int] = {}
        ip_counts: Dict[str, int] = {}
        conversations: Dict[Tuple[str, str, str, Optional[int], Optional[int]], Dict[str, Any]] = {}

        # Threat tracking state
        syn_tracker: Dict[str, Set[int]] = {}  # src_ip -> set of dest ports
        syn_count: Dict[str, int] = {}
        ack_count: Dict[str, int] = {}
        dns_queries: List[Dict[str, Any]] = []
        cleartext_creds: List[Dict[str, Any]] = []

        for idx, pkt in enumerate(packets, 1):
            ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0
            time_iso = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat() if ts > 0 else "N/A"
            length = len(pkt)

            src_ip = "N/A"
            dst_ip = "N/A"
            src_port = None
            dst_port = None
            proto_name = "OTHER"
            info = ""
            tcp_flags = None

            # Ethernet / ARP
            if pkt.haslayer(ARP):
                proto_name = "ARP"
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                info = f"ARP Who has {dst_ip}? Tell {src_ip}"

            # IPv4 / IPv6
            elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
                ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # Track IP activity
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1

                # TCP
                if pkt.haslayer(TCP):
                    proto_name = "TCP"
                    tcp = pkt[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    tcp_flags = str(tcp.flags)
                    info = f"{src_port} -> {dst_port} [{tcp_flags}] Seq={tcp.seq}"

                    # Track SYN flood / port scanning
                    if "S" in tcp_flags and "A" not in tcp_flags:
                        syn_tracker.setdefault(src_ip, set()).add(dst_port)
                        syn_count[src_ip] = syn_count.get(src_ip, 0) + 1
                    if "A" in tcp_flags:
                        ack_count[src_ip] = ack_count.get(src_ip, 0) + 1

                    # Inspect HTTP / TLS payloads
                    if dst_port in (80, 8080, 8000) or src_port in (80, 8080, 8000):
                        proto_name = "HTTP"
                        if pkt.haslayer(Raw):
                            payload = pkt[Raw].load
                            info = self._inspect_http_payload(payload, idx, src_ip, dst_ip, cleartext_creds)

                    elif dst_port == 443 or src_port == 443:
                        proto_name = "TLS"
                        info = f"TLS Traffic ({src_port} -> {dst_port})"

                # UDP
                elif pkt.haslayer(UDP):
                    proto_name = "UDP"
                    udp = pkt[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    info = f"UDP {src_port} -> {dst_port} Len={udp.len}"

                    # DNS
                    if pkt.haslayer(DNS):
                        proto_name = "DNS"
                        dns = pkt[DNS]
                        if dns.qd:
                            qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                            qtype = dns.qd.qtype
                            info = f"Standard query 0x{dns.id:04x} {qname}"
                            dns_queries.append({"pkt": idx, "query": qname, "src": src_ip, "type": qtype})

                # ICMP
                elif pkt.haslayer(ICMP):
                    proto_name = "ICMP"
                    icmp = pkt[ICMP]
                    info = f"ICMP Type={icmp.type} Code={icmp.code}"

            proto_counts[proto_name] = proto_counts.get(proto_name, 0) + 1

            record = PacketRecord(
                packet_number=idx,
                timestamp=ts,
                time_iso=time_iso,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_name,
                length=length,
                info=info or f"{proto_name} Frame",
                tcp_flags=tcp_flags
            )
            result.packets.append(record)

            # Record Flow (Bidirectional session aggregation)
            if src_ip != "N/A" and dst_ip != "N/A":
                flow_key = tuple(sorted([src_ip, dst_ip])) + (proto_name, tuple(sorted([src_port or 0, dst_port or 0])))
                if flow_key not in conversations:
                    conversations[flow_key] = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": proto_name,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "packets": 0,
                        "bytes": 0,
                        "start_time": time_iso,
                        "end_time": time_iso,
                        "start_ts": ts,
                        "end_ts": ts,
                    }
                c = conversations[flow_key]
                c["packets"] += 1
                c["bytes"] += length
                c["end_time"] = time_iso
                c["end_ts"] = ts

        # Populate flows
        for idx, (fkey, c) in enumerate(conversations.items(), 1):
            dur = max(0.0, c["end_ts"] - c["start_ts"])
            result.flows.append(FlowRecord(
                flow_id=f"flow_{idx}",
                src_ip=c["src_ip"],
                dst_ip=c["dst_ip"],
                protocol=c["protocol"],
                src_port=c["src_port"],
                dst_port=c["dst_port"],
                total_packets=c["packets"],
                total_bytes=c["bytes"],
                duration_sec=round(dur, 3),
                start_time=c["start_time"],
                end_time=c["end_time"],
            ))

        result.protocol_distribution = proto_counts

        # Top talkers (top 5 active IP addresses)
        sorted_talkers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        result.top_talkers = [{"ip": ip, "packet_count": count} for ip, count in sorted_talkers]

        # ---------------------------------------------------------------------
        # Threat & Anomaly Evaluation
        # ---------------------------------------------------------------------
        self._evaluate_threats(result, syn_tracker, syn_count, ack_count, dns_queries, cleartext_creds)

        result.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return result

    def _inspect_http_payload(self, payload: bytes, pkt_no: int, src_ip: str, dst_ip: str, creds_list: List[Dict[str, Any]]) -> str:
        text = payload[:500].decode("latin1", errors="ignore")
        first_line = text.split("\r\n")[0] if "\r\n" in text else text[:50]

        # Cleartext Basic Auth
        if "Authorization: Basic " in text:
            creds_list.append({"pkt": pkt_no, "src": src_ip, "dst": dst_ip, "type": "HTTP Basic Auth", "snippet": "Authorization: Basic ..."})
        # Cleartext POST Credentials
        else:
            match = re.search(r"(?i)(?:password|passwd|pwd)=[^\s&]+", text)
            if match:
                creds_list.append({"pkt": pkt_no, "src": src_ip, "dst": dst_ip, "type": "HTTP POST Form Password", "snippet": match.group(0)})

        return first_line

    def _evaluate_threats(
        self,
        result: PcapAnalysisResult,
        syn_tracker: Dict[str, Set[int]],
        syn_count: Dict[str, int],
        ack_count: Dict[str, int],
        dns_queries: List[Dict[str, Any]],
        cleartext_creds: List[Dict[str, Any]]
    ):
        # 1. Port Scanning Indicator (Single IP probing > 15 unique destination ports)
        for src, ports in syn_tracker.items():
            if len(ports) >= 15:
                result.findings.append(PcapFinding(
                    analysis_id=result.id,
                    flag_name="PORT_SCAN_INDICATOR",
                    severity="HIGH",
                    confidence=0.92,
                    title=f"TCP Port Scanning Activity Detected from {src}",
                    description=f"Host {src} sent TCP SYN packets probing {len(ports)} unique destination ports in this capture.",
                    evidence=f"Targeted ports include: {sorted(list(ports))[:10]}... Total probed: {len(ports)}",
                    src_endpoint=src,
                    protocol="TCP",
                    remediation="Apply automated firewall drop rules for IP scanning bursts and inspect host for unauthorized recon tooling."
                ))

        # 2. SYN Flood Pattern (High SYN volume with near zero ACK)
        for src, count in syn_count.items():
            acks = ack_count.get(src, 0)
            if count > 50 and acks == 0:
                result.findings.append(PcapFinding(
                    analysis_id=result.id,
                    flag_name="SYN_FLOOD_INDICATOR",
                    severity="CRITICAL",
                    confidence=0.95,
                    title=f"Potential TCP SYN Flood DoS Pattern from {src}",
                    description=f"Observed {count} TCP SYN packets from {src} without a single corresponding ACK or established handshake.",
                    evidence=f"SYN count: {count}, ACK count: {acks}",
                    src_endpoint=src,
                    protocol="TCP",
                    remediation="Enable TCP SYN cookies on receiving endpoints and drop unauthenticated half-open streams at perimeter."
                ))

        # 3. DNS Tunneling & Exfiltration Indicators
        for q in dns_queries:
            query = q["query"]
            # Detect abnormally long subdomains (> 45 chars) or high entropy
            if len(query) > 45 or self._shannon_entropy(query) > 4.2:
                result.findings.append(PcapFinding(
                    analysis_id=result.id,
                    flag_name="DNS_TUNNELING_INDICATOR",
                    severity="HIGH",
                    confidence=0.88,
                    title="Suspected DNS Tunneling / Covert Exfiltration Channel",
                    description=f"Identified high-entropy or oversized DNS query '{query}' indicative of iodine, dnscat2, or Cobalt Strike DNS C2 beaconing.",
                    evidence=f"Query: {query} (Length: {len(query)} chars, Entropy: {round(self._shannon_entropy(query), 2)}) at packet #{q['pkt']}",
                    src_endpoint=q["src"],
                    protocol="DNS",
                    packet_numbers=[q["pkt"]],
                    remediation="Configure DNS query length limits, inspect host DNS cache, and enforce internal DNS forwarding policies."
                ))
                break  # flag once per capture

        # 4. Cleartext Credential Exposure
        for c in cleartext_creds:
            result.findings.append(PcapFinding(
                analysis_id=result.id,
                flag_name="CLEAR_TEXT_CREDENTIAL_EXPOSURE",
                severity="HIGH",
                confidence=0.98,
                title=f"Clear-Text Credentials Transmitted over Network ({c['type']})",
                description=f"Unencrypted authentication data was observed in packet #{c['pkt']} from {c['src']} to {c['dst']}.",
                evidence=f"Observed in packet #{c['pkt']} via unencrypted HTTP transport. Snippet: {c.get('snippet', '')}",
                src_endpoint=c["src"],
                dst_endpoint=c["dst"],
                protocol="HTTP",
                packet_numbers=[c["pkt"]],
                remediation="Mandate TLS 1.2+ for all web applications and reject unencrypted HTTP authentication endpoints."
            ))

    def _shannon_entropy(self, s: str) -> float:
        """Calculates Shannon entropy of a string."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum(p * math.log(p, 2) for p in prob)


pcap_analyzer = PcapAnalyzerEngine()
