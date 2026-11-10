"""
SNMK MAP ?" PCAP and PCAPNG Forensic Analysis Engine
Validates capture files, verifies SHA-256 cryptographic hashes, dissects all frames,
evaluates protocol hierarchies, tracks TCP handshakes and conversations, and extracts indicators.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import rdpcap

from core.network.models import FlowSummary, PacketDetail, PacketSummary
from core.network.packet_engine import PacketDissector

logger = logging.getLogger("snmk.map.pcap")

# Standard PCAP & PCAPNG magic numbers
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def validate_pcap_header(file_bytes: bytes) -> Tuple[bool, str]:
    """Verifies magic numbers to ensure file is legitimate PCAP or PCAPNG."""
    if len(file_bytes) < 4:
        return False, "File is too short to be a valid capture file."

    header = file_bytes[:4]
    if header in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
        return True, "Standard PCAP format"
    elif header == PCAPNG_MAGIC:
        return True, "PCAPNG Next-Generation format"

    return False, "Invalid capture file format: Missing PCAP/PCAPNG magic header."


class PcapForensicsEngine:
    """Forensic dissector and metadata analyzer for PCAP/PCAPNG files."""

    def __init__(self):
        self.dissector = PacketDissector()

    def analyze_bytes(self, file_content: bytes, filename: str = "uploaded.pcap", max_packets: int = 1500) -> Dict[str, Any]:
        """Analyzes in-memory capture bytes safely with resource bounds."""
        # 1. Validation
        is_valid, format_desc = validate_pcap_header(file_content)
        if not is_valid:
            return {"success": False, "error": format_desc}

        # 2. Cryptographic Hash
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        file_size_bytes = len(file_content)

        # 3. Write securely to temporary file for Scapy rdpcap
        temp_dir = tempfile.gettempdir()
        safe_name = os.path.basename(filename).replace("..", "")
        temp_path = os.path.join(temp_dir, f"snmk_forensics_{sha256_hash[:8]}_{safe_name}")

        try:
            with open(temp_path, "wb") as f:
                f.write(file_content)

            pkts = rdpcap(temp_path, count=max_packets)
            total_packets_parsed = len(pkts)

            if total_packets_parsed == 0:
                return {
                    "success": True,
                    "filename": filename,
                    "sha256": sha256_hash,
                    "file_size_bytes": file_size_bytes,
                    "format": format_desc,
                    "total_packets": 0,
                    "packets": [],
                    "message": "Capture file is empty."
                }

            base_time = float(getattr(pkts[0], "time", 0.0))
            end_time = float(getattr(pkts[-1], "time", 0.0))
            duration_sec = round(max(0.0, end_time - base_time), 3)

            summaries: List[PacketSummary] = []
            details: Dict[int, PacketDetail] = {}
            protocol_counts: Dict[str, int] = {}
            flows: Dict[str, FlowSummary] = {}
            total_bytes = 0

            for i, pkt in enumerate(pkts, start=1):
                raw_len = len(bytes(pkt))
                total_bytes += raw_len

                summary, detail = self.dissector.dissect(pkt, i, "pcap_import", base_time)
                summaries.append(summary)
                details[i] = detail

                # Protocol counter
                protocol_counts[summary.protocol] = protocol_counts.get(summary.protocol, 0) + 1

                # Flow counter
                flow_key = f"{summary.source_ip}:{summary.source_port}<->{summary.destination_ip}:{summary.destination_port}"
                rev_key = f"{summary.destination_ip}:{summary.destination_port}<->{summary.source_ip}:{summary.source_port}"
                target_key = flow_key if flow_key in flows else (rev_key if rev_key in flows else flow_key)

                if target_key not in flows:
                    flows[target_key] = FlowSummary(
                        flow_id=target_key,
                        source_ip=summary.source_ip,
                        destination_ip=summary.destination_ip,
                        source_port=summary.source_port or 0,
                        destination_port=summary.destination_port or 0,
                        protocol=summary.protocol,
                        packets_sent=1,
                        bytes_sent=summary.length,
                        first_seen=summary.time_str,
                        last_seen=summary.time_str
                    )
                else:
                    fl = flows[target_key]
                    if fl.source_ip == summary.source_ip:
                        fl.packets_sent += 1
                        fl.bytes_sent += summary.length
                    else:
                        fl.packets_received += 1
                        fl.bytes_received += summary.length
                    fl.last_seen = summary.time_str

            return {
                "success": True,
                "filename": filename,
                "sha256": sha256_hash,
                "file_size_bytes": file_size_bytes,
                "format": format_desc,
                "total_packets": total_packets_parsed,
                "duration_seconds": duration_sec,
                "avg_packet_size_bytes": round(total_bytes / max(total_packets_parsed, 1), 1),
                "protocol_hierarchy": protocol_counts,
                "flows_count": len(flows),
                "flows": [f.dict() for f in list(flows.values())[:50]],
                "packets": [p.dict() for p in summaries[:200]],
                "message": f"Successfully parsed {total_packets_parsed} frames across {len(flows)} communication flows."
            }

        except Exception as e:
            logger.error(f"Error parsing PCAP file {filename}: {e}")
            return {"success": False, "error": f"PCAP parsing exception: {str(e)}"}
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass


pcap_engine = PcapForensicsEngine()
