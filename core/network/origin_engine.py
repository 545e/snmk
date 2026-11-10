"""
SNMK MAP ?" Network Origin Identification Engine
Correlates connection telemetry, local ARP tables, DNS records, ISP/ASN registrations,
BGP prefixes, and geolocation to classify the operational origin and infrastructure type of any network flow.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any, Dict, List, Optional

from core.network.geo_engine import geo_engine, is_private_ip
from core.network.infrastructure import infra_engine
from core.network.interfaces import get_local_network_info
from core.network.models import OriginInvestigation

logger = logging.getLogger("snmk.map.origin")

# Known Cloud and CDN Provider IP Signatures / ASN Substrings
CLOUD_ASN_SIGNATURES = [
    "AMAZON", "AWS", "CLOUDFLARE", "GOOGLE", "MICROSOFT", "AZURE", "FASTLY",
    "AKAMAI", "DIGITALOCEAN", "OVH", "HETZNER", "ORACLE", "LINODE"
]


class NetworkOriginEngine:
    """Enterprise Network Origin Identification & Attribution Analyzer."""

    async def investigate_origin(self, target: str) -> OriginInvestigation:
        """Deep correlation of network origin for any IP, domain, or flow target."""
        target = target.strip()
        local_info = get_local_network_info()

        resolved_ip = target
        dest_hostname = None
        target_type = "IPv4"

        # Check if domain
        try:
            ipaddress.ip_address(target)
            if ":" in target:
                target_type = "IPv6"
            else:
                target_type = "IPv4"
        except ValueError:
            target_type = "Domain"
            dest_hostname = target
            try:
                resolved_ip = socket.gethostbyname(target)
            except Exception as e:
                logger.debug(f"Failed to resolve domain {target}: {e}")

        # Check if local gateway or local host
        is_local_host = (resolved_ip in [local_info.local_ipv4, "127.0.0.1", "::1"])
        is_gateway = (resolved_ip == local_info.gateway_ip)
        is_private = is_private_ip(resolved_ip)

        evidence: List[str] = []
        limitations: List[str] = [
            "Network origin identification establishes routing allocations, public BGP announcements, and ISP endpoints.",
            "Attribution does NOT identify individual personal identities due to NAT/CGNAT, shared hosting, and dynamic DHCP pools."
        ]

        # Query ISP, ASN, and RDAP
        isp_info = await infra_engine.lookup_isp_asn(resolved_ip)
        # Query Geolocation
        geo_info = await geo_engine.lookup_ip_geolocation(resolved_ip)

        # Classification Logic
        classification = "Unknown"
        confidence = "Medium"

        if is_local_host:
            classification = "Local Host Device"
            confidence = "High"
            evidence.append(f"Target matches local host primary interface IP ({resolved_ip}).")
        elif is_gateway:
            classification = "Local Network Gateway"
            confidence = "High"
            evidence.append(f"Target matches system default gateway route ({resolved_ip}).")
        elif is_private:
            classification = "Private Network Endpoint (LAN / VLAN)"
            confidence = "High"
            evidence.append(f"Target is within RFC 1918 / Private allocation range ({resolved_ip}).")
            limitations.append("Private IP is non-routable on the public internet; no external ISP or BGP origin exists.")
        else:
            # Public IP: evaluate ASN/Org
            asn_org_upper = (isp_info.asn_org or "").upper()
            isp_upper = (isp_info.isp or "").upper()

            is_cloud_cdn = any(sig in asn_org_upper or sig in isp_upper for sig in CLOUD_ASN_SIGNATURES)

            if "CLOUDFLARE" in asn_org_upper or "FASTLY" in asn_org_upper or "AKAMAI" in asn_org_upper:
                classification = "Content Delivery Network (CDN) Edge"
                confidence = "High"
                evidence.append(f"ASN {isp_info.asn} corresponds to a major global Content Delivery Network.")
                limitations.append("Reverse proxy terminates TLS; actual origin web server is obscured behind CDN edge.")
            elif is_cloud_cdn:
                classification = "Cloud Hosting / Datacenter Infrastructure"
                confidence = "High"
                evidence.append(f"Announced via Cloud Provider ASN {isp_info.asn} ({isp_info.asn_org}).")
            elif "BROADBAND" in asn_org_upper or "TELECOM" in asn_org_upper or "COMMUNICATIONS" in asn_org_upper or "CABLE" in asn_org_upper:
                classification = "Residential / Commercial ISP Infrastructure"
                confidence = "Medium"
                evidence.append(f"Public IP allocated to ISP provider {isp_info.isp}.")
            else:
                classification = "Public Internet Endpoint"
                confidence = "Medium"
                evidence.append(f"Public endpoint announced by ASN {isp_info.asn} in country {isp_info.country}.")

        return OriginInvestigation(
            target=target,
            target_type=target_type,
            source_ip=local_info.local_ipv4,
            source_mac=local_info.mac_address,
            source_hostname=local_info.hostname,
            destination_ip=resolved_ip,
            destination_hostname=dest_hostname or isp_info.reverse_dns,
            isp_info=isp_info,
            geo_info=geo_info,
            origin_classification=classification,
            confidence=confidence,
            classification_evidence=evidence,
            limitations=limitations
        )


origin_engine = NetworkOriginEngine()
