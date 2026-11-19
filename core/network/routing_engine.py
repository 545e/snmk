"""
SNMK MAP ?" Routing and Connection Path Intelligence Engine
Executes traceroute diagnostics, parses hop latencies, enriches hops with ASN,
ISP, and geographical coordinates, and visualizes network paths with ICMP suppression explanations.
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import sys
from typing import Any

from core.network.geo_engine import geo_engine, is_private_ip
from core.network.infrastructure import infra_engine
from core.network.models import RouteHop

logger = logging.getLogger("snmk.map.routing")


class RouteAnalysisEngine:
    """Path trace execution and hop enrichment analyzer."""

    async def analyze_route(self, target: str, max_hops: int = 15, timeout: float = 3.0) -> dict[str, Any]:
        """Performs traceroute to target and geolocates reachable hops."""
        target = target.strip()
        max_hops = min(max(max_hops, 3), 30)

        # Validate that target does not contain command switches or invalid characters
        safe_target = str(target).replace("\r", "").replace("\n", "")[:128]
        if not target or target.startswith("-") or not re.match(r"^[a-zA-Z0-9.:-]+$", target):
            logger.warning(f"Invalid target for traceroute: {safe_target}")
            return {"target": target, "hops": [], "explanations": ["Target address contains invalid characters."]}

        # Resolve domain to a validated IP address and reconstruct from integer octets
        import ipaddress
        try:
            try:
                ip_obj = ipaddress.ip_address(target)
            except ValueError:
                resolved = socket.gethostbyname(target)
                ip_obj = ipaddress.ip_address(resolved)

            if ip_obj.version == 4:
                b = ip_obj.packed
                dest_ip = f"{int(b[0])}.{int(b[1])}.{int(b[2])}.{int(b[3])}"
            elif ip_obj.version == 6:
                dest_ip = ip_obj.exploded
            else:
                return {"target": target, "hops": [], "explanations": ["Unsupported IP version."]}
        except Exception:
            logger.warning(f"Could not resolve target to IP: {safe_target}")
            return {"target": target, "hops": [], "explanations": ["Could not resolve target to a valid IP address."]}

        hops: list[RouteHop] = []

        # Execute system traceroute
        if sys.platform.startswith("win"):
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), dest_ip]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)), dest_ip]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * max_hops + 10)
            lines = proc.stdout.splitlines()

            for line in lines:
                line_str = line.strip()
                # Pattern: 1  4 ms  2 ms  2 ms  192.168.0.1
                match = re.search(r"^\s*(\d+)\s+([<\d\*\s\w]+?)\s+([0-9a-fA-F\.:]+|\*)$", line_str)
                if match:
                    hop_num = int(match.group(1))
                    rtt_str = match.group(2)
                    ip_candidate = match.group(3)

                    # Extract numbers for RTT
                    rtts = [float(x.replace("<", "")) for x in re.findall(r"([<\d]+)\s*ms", rtt_str)]
                    avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else None

                    is_timeout = (ip_candidate == "*" or not rtts)
                    hop_ip = ip_candidate if ip_candidate != "*" else "Filtered / Timed Out"

                    hop = RouteHop(
                        hop=hop_num,
                        ip=hop_ip,
                        rtt_ms=rtts,
                        avg_rtt_ms=avg_rtt,
                        packet_loss_pct=100.0 if is_timeout else round((3 - len(rtts)) / 3.0 * 100, 1),
                        status="TIMEOUT" if is_timeout else "SUCCESS"
                    )

                    # Enrich public hop
                    if not is_timeout and not is_private_ip(hop_ip):
                        try:
                            geo = await geo_engine.lookup_ip_geolocation(hop_ip)
                            hop.city = geo.city
                            hop.country = geo.country
                            hop.latitude = geo.latitude
                            hop.longitude = geo.longitude

                            infra = await infra_engine.lookup_isp_asn(hop_ip)
                            hop.asn = infra.asn
                            hop.isp = infra.isp
                        except Exception:
                            logging.getLogger(__name__).debug("Suppressed exception (audited empty handler)", exc_info=True)
                    elif not is_timeout and is_private_ip(hop_ip):
                        hop.isp = "Local LAN / Gateway Router"
                        hop.city = "Private Subnet"

                    hops.append(hop)

        except Exception as e:
            logger.error(f"Traceroute execution error: {e}")

        # Summary explanations for missing/filtered hops
        has_filtered = any(h.status == "TIMEOUT" for h in hops)
        explanations = []
        if has_filtered:
            explanations.append(
                "Timed-out hops (*) typically reflect routers configured with ICMP Time Exceeded suppression or rate-limiting for security, rather than network failure."
            )
        explanations.append(
            "Traceroute displays observable forward hops. Asymmetric routing on the internet means return packets may take a completely different physical path."
        )

        return {
            "target": target,
            "destination_ip": dest_ip,
            "max_hops": max_hops,
            "total_hops": len(hops),
            "hops": [h.dict() for h in hops],
            "reachable": any(h.ip == dest_ip for h in hops),
            "explanations": explanations
        }


route_engine = RouteAnalysisEngine()
