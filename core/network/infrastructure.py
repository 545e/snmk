"""
SNMK MAP ?" Internet Infrastructure Intelligence Engine
Resolves Public IP, ISP, Autonomous System Number (ASN),
RDAP registry allocations, BGP announced prefix data, and Reverse DNS.
"""

from __future__ import annotations

import logging
import socket
from typing import Any

import httpx

from core.network.geo_engine import is_private_ip
from core.network.models import BgpPrefixInfo, IspAsnInfo
from core.error_sanitizer import safe_log_text

logger = logging.getLogger("snmk.map.infra")


class InternetInfrastructureEngine:
    """Discovers and queries public internet infrastructure, ASNs, and BGP routing prefixes."""

    def __init__(self):
        self._public_ip_cache = None
        self._cache = {}

    async def get_public_ip(self) -> dict[str, Any]:
        """Discovers the public IP visible from the current monitoring vantage point."""
        if self._public_ip_cache:
            return self._public_ip_cache
        endpoints = [
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/all.json",
            "https://ipinfo.io/json"
        ]
        for url in endpoints:
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    res = await client.get(url)
                    if res.status_code == 200:
                        data = res.json()
                        ip = data.get("ip") or data.get("ip_addr")
                        if ip:
                            res_obj = {"success": True, "ip": ip.strip(), "source": url}
                            self._public_ip_cache = res_obj
                            return res_obj
            except Exception as e:
                logger.debug(f"Public IP query to {safe_log_text(url)} failed: {safe_log_text(e)}")

        return {"success": False, "ip": None, "message": "Unable to discover public IP address (Internet unreachable)."}

    async def lookup_isp_asn(self, ip: str) -> IspAsnInfo:
        """Retrieves ISP, ASN, prefix, and reverse DNS for any IPv4 or IPv6."""
        import ipaddress
        import urllib.parse

        ip = ip.strip()
        try:
            ip_obj = ipaddress.ip_address(ip)
            clean_ip = str(ip_obj)
        except ValueError:
            return IspAsnInfo(
                ip=ip,
                asn="INVALID",
                asn_org="Invalid IP Format",
                isp="Invalid IP Format",
                organization="Invalid",
                rdap_registry="None",
                network_prefix="None",
                reverse_dns=None,
                bgp_announced=False,
                country="INVALID"
            )

        if clean_ip in self._cache:
            return self._cache[clean_ip]

        # Handle private address
        if is_private_ip(clean_ip) or ip_obj.is_private or ip_obj.is_loopback:
            rev_dns = "localhost" if clean_ip in ("127.0.0.1", "::1") else "internal.local"

            return IspAsnInfo(
                ip=clean_ip,
                asn="PRIVATE",
                asn_org="Private Subnet (RFC 1918 / Local Area Network)",
                isp="Local Gateway / Internal Network",
                organization="Private Enterprise Network",
                rdap_registry="IANA Reserved",
                network_prefix="Private",
                reverse_dns=rev_dns,
                bgp_announced=False,
                country="LOCAL"
            )

        # Reverse DNS lookup
        rev_dns = None
        try:
            rev_dns = socket.gethostbyaddr(clean_ip)[0]
        except Exception:
            logging.getLogger(__name__).debug("Suppressed exception (audited empty handler)", exc_info=True)

        asn = None
        asn_org = None
        isp = None
        org = None
        country = None

        safe_ip = urllib.parse.quote(clean_ip, safe="")

        # 1. Query ipinfo.io
        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                res = await client.get(f"https://ipinfo.io/{safe_ip}/json")
                if res.status_code == 200:
                    data = res.json()
                    org_str = data.get("org", "")
                    if org_str:
                        parts = org_str.split(" ", 1)
                        if parts[0].upper().startswith("AS"):
                            asn = parts[0].upper()
                            asn_org = parts[1] if len(parts) > 1 else asn
                        else:
                            asn_org = org_str
                    isp = asn_org or data.get("hostname")
                    org = asn_org
                    country = data.get("country")
                    if not rev_dns and data.get("hostname"):
                        rev_dns = data.get("hostname")
        except Exception as e:
            logger.debug(f"ipinfo ASN lookup failed for {safe_log_text(clean_ip)}: {safe_log_text(e)}")

        # 2. Query RIPEstat BGP Prefix Overview
        network_prefix = None
        bgp_announced = True
        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                res = await client.get("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": clean_ip})
                if res.status_code == 200:
                    rdata = res.json().get("data", {})
                    asns = rdata.get("asns", [])
                    if asns and not asn:
                        asn = f"AS{asns[0].get('asn')}"
                        asn_org = asns[0].get("holder")
                    block = rdata.get("block", {})
                    if block:
                        network_prefix = block.get("resource")
        except Exception as e:
            logger.debug(f"RIPEstat query failed: {safe_log_text(e)}")

        # 3. RDAP registry query if ASN still missing
        rdap_reg = "ARIN/RIPE/APNIC"
        if not asn:
            try:
                async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                    res = await client.get(f"https://rdap.arin.net/registry/ip/{safe_ip}")
                    if res.status_code == 200:
                        rdap_data = res.json()
                        rdap_reg = rdap_data.get("port43", "ARIN")
                        isp = rdap_data.get("name") or "Public Internet Endpoint"
            except Exception:
                logging.getLogger(__name__).debug("Suppressed exception (audited empty handler)", exc_info=True)

        result_obj = IspAsnInfo(
            ip=clean_ip,
            asn=asn or "AS-UNKNOWN",
            asn_org=asn_org or isp or "Autonomous System Unknown",
            isp=isp or asn_org or "Internet Service Provider",
            organization=org or asn_org or isp or "Public Network",
            rdap_registry=rdap_reg,
            network_prefix=network_prefix or f"{clean_ip}/24",
            reverse_dns=rev_dns,
            bgp_announced=bgp_announced,
            country=country or "GLOBAL"
        )
        self._cache[clean_ip] = result_obj
        return result_obj

    async def get_bgp_prefix_info(self, prefix_or_ip: str) -> BgpPrefixInfo:
        """Retrieves BGP prefix announcements, Origin ASN, and AS Path using RIPEstat."""
        import ipaddress
        import urllib.parse

        target = prefix_or_ip.strip()
        try:
            if "/" in target:
                net = ipaddress.ip_network(target, strict=False)
                clean_target = str(net)
            else:
                addr = ipaddress.ip_address(target)
                clean_target = str(addr)
        except ValueError:
            clean_target = urllib.parse.quote(target, safe="")

        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                res = await client.get("https://stat.ripe.net/data/routing-status/data.json", params={"resource": clean_target})
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    origin_asn = f"AS{data.get('origin_asn', 'Unknown')}"
                    prefix = data.get("resource", clean_target)

                    # Get AS path data
                    path_res = await client.get("https://stat.ripe.net/data/looking-glass/data.json", params={"resource": clean_target})
                    as_path = []
                    if path_res.status_code == 200:
                        rdata = path_res.json().get("data", {})
                        rts = rdata.get("rrcs", [])
                        if rts and "peers" in rts[0] and rts[0]["peers"]:
                            as_path = [str(x) for x in rts[0]["peers"][0].get("as_path", "").split()]

                    return BgpPrefixInfo(
                        prefix=prefix,
                        origin_asn=origin_asn,
                        asn_name=f"Origin {origin_asn}",
                        as_path=as_path if as_path else [origin_asn],
                        registry="RIPEstat / Global BGP Table",
                        is_valid=True
                    )
        except Exception as e:
            logger.error(f"BGP lookup failed: {safe_log_text(e)}")

        return BgpPrefixInfo(
            prefix=target,
            origin_asn="AS-UNKNOWN",
            asn_name="Unannounced / Private",
            as_path=[],
            registry="Local",
            is_valid=False
        )


infra_engine = InternetInfrastructureEngine()
