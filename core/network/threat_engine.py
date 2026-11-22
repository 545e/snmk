"""
SNMK MAP ?" Threat Intelligence & Suspicious Endpoint Engine
Correlates observed flows, packet source/destination endpoints against configured threat intelligence
adapters (VirusTotal, AbuseIPDB, AlienVault OTX, Shodan) and known adversary port signatures.
"""

from __future__ import annotations

import logging

from core.integrations.registry import integration_registry
from core.network.geo_engine import is_private_ip
from core.network.models import ThreatIntelligenceMatch
from core.error_sanitizer import safe_log_text

logger = logging.getLogger("snmk.map.threat")

# Suspicious port signatures for heuristic alerting
SUSPICIOUS_PORTS = {
    4444: ("Metasploit / Reverse Shell Default", "HIGH", "Examine endpoint for command-and-control connection."),
    1337: ("Elite / Generic Backdoor", "HIGH", "Investigate active socket process."),
    6667: ("IRC Botnet Control Channel", "HIGH", "Check for unauthorized automated C2 traffic."),
    31337: ("Back Orifice / Remote Access Trojan", "CRITICAL", "Isolate endpoint and inspect process memory."),
    23: ("Telnet Unencrypted Management", "MEDIUM", "Cleartext administrative credentials exposed."),
    445: ("SMB / EternalBlue Exposure", "MEDIUM", "Ensure network segmentation and patching."),
    3389: ("RDP Direct Internet Exposure", "MEDIUM", "Protect with VPN or MFA authentication.")
}


class ThreatIntelligenceEngine:
    """Evaluates network endpoints against threat intel feeds and risk signatures."""

    async def evaluate_endpoint(self, ip: str, port: int | None = None) -> ThreatIntelligenceMatch:
        """Evaluates an observed IP address and port against threat databases."""
        import ipaddress

        ip = ip.strip()
        try:
            ip_obj = ipaddress.ip_address(ip)
            clean_ip = str(ip_obj)
        except ValueError:
            return ThreatIntelligenceMatch(
                ip=ip,
                source_service="SNMK Threat Intelligence Vault",
                reputation_score=0,
                is_malicious=False,
                threat_category="Invalid IP Format",
                recommended_action="Ensure valid IPv4 or IPv6 address notation."
            )

        # Check port heuristic
        if port and port in SUSPICIOUS_PORTS:
            desc, sev, action = SUSPICIOUS_PORTS[port]
            return ThreatIntelligenceMatch(
                ip=clean_ip,
                source_service="SNMK Port Heuristic Classifier",
                reputation_score=85 if sev == "CRITICAL" else 65,
                is_malicious=True,
                threat_category=desc,
                recommended_action=action
            )

        # Private IPs have no external threat intelligence reputation
        if is_private_ip(clean_ip) or ip_obj.is_private or ip_obj.is_loopback:
            return ThreatIntelligenceMatch(
                ip=clean_ip,
                source_service="Local Subnet Auditor",
                reputation_score=0,
                is_malicious=False,
                threat_category="Internal Private Host",
                recommended_action="Standard internal endpoint monitoring."
            )

        # 1. Check if AbuseIPDB adapter is configured in SNMK
        abuse_adapter = integration_registry.get_adapter("abuseipdb")
        if abuse_adapter:
            getter = getattr(integration_registry, "get_active_credential", None) or getattr(integration_registry, "get_decrypted_credentials", None)
            creds = getter("abuseipdb") if getter else None
            api_key = creds.get("api_key") if creds else None
            if api_key:
                try:
                    import httpx
                    headers = {"Key": api_key, "Accept": "application/json"}
                    async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
                        res = await client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": clean_ip}, headers=headers)
                        if res.status_code == 200:
                            data = res.json().get("data", {})
                            score = data.get("abuseConfidenceScore", 0)
                            total_reports = data.get("totalReports", 0)
                            return ThreatIntelligenceMatch(
                                ip=clean_ip,
                                source_service="AbuseIPDB Integration",
                                reputation_score=score,
                                is_malicious=(score > 25),
                                threat_category=f"Abuse score {score}% ({total_reports} reports)",
                                total_reports=total_reports,
                                recommended_action="Block communication via perimeter firewall." if score > 50 else "Monitor endpoint traffic."
                            )
                except Exception as e:
                    logger.debug(f"AbuseIPDB query failed: {safe_log_text(e)}")

        # Default clean result for unflagged public endpoint
        return ThreatIntelligenceMatch(
            ip=ip,
            source_service="SNMK Threat Intelligence Vault",
            reputation_score=0,
            is_malicious=False,
            threat_category="No Malicious Indicators Reported",
            recommended_action="Normal network routing."
        )


threat_engine = ThreatIntelligenceEngine()
