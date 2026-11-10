"""
SNMK MAP ?" DNS Intelligence Engine
Performs multi-record DNS resolution (A, AAAA, MX, NS, TXT, CNAME, PTR, SOA, SRV, DNSSEC),
measures query latency, correlates domain-to-IP, and analyzes DNS tunneling/anomaly heuristics.
"""

from __future__ import annotations

import logging
import math
import time
from typing import Any, Dict, List, Optional
import dns.resolver
import dns.reversename
import dns.dnssec

from core.network.models import DnsRecord

logger = logging.getLogger("snmk.map.dns")


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect possible DNS tunneling / exfiltration payloads."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {c: data.count(c) for c in set(data)}
    for count in frequencies.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return entropy


class DnsIntelligenceEngine:
    """Enterprise DNS intelligence and query analyzer."""

    def __init__(self, nameservers: Optional[List[str]] = None):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1.0
        self.resolver.lifetime = 1.5
        if nameservers:
            self.resolver.nameservers = nameservers

    async def resolve_all(self, domain_or_ip: str) -> Dict[str, Any]:
        """Resolves comprehensive DNS records for domain or PTR for IP."""
        target = domain_or_ip.strip()
        records: List[DnsRecord] = []
        is_ip = False

        # Check if target is an IP for reverse PTR lookup
        try:
            import ipaddress
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False

        resolver_ip = self.resolver.nameservers[0] if self.resolver.nameservers else "System Default"

        if is_ip:
            start = time.perf_counter()
            try:
                rev_name = dns.reversename.from_address(target)
                ans = self.resolver.resolve(rev_name, "PTR")
                latency = round((time.perf_counter() - start) * 1000, 2)
                for rdata in ans:
                    records.append(DnsRecord(
                        domain=target,
                        record_type="PTR",
                        value=str(rdata).rstrip("."),
                        ttl=ans.rrset.ttl if ans.rrset else 300,
                        resolver=resolver_ip,
                        response_time_ms=latency
                    ))
            except Exception as e:
                logger.debug(f"PTR lookup failed for {target}: {e}")

            return {
                "target": target,
                "is_reverse": True,
                "records": [r.dict() for r in records],
                "tunneling_anomaly_score": 0.0,
                "dnssec_status": "N/A"
            }

        # Domain Query: Query common record types
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        total_time = 0.0

        for rtype in record_types:
            start = time.perf_counter()
            try:
                answers = self.resolver.resolve(target, rtype)
                latency = round((time.perf_counter() - start) * 1000, 2)
                total_time += latency
                for rdata in answers:
                    records.append(DnsRecord(
                        domain=target,
                        record_type=rtype,
                        value=str(rdata).strip('"'),
                        ttl=answers.rrset.ttl if answers.rrset else 300,
                        resolver=resolver_ip,
                        response_time_ms=latency
                    ))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception as e:
                logger.debug(f"DNS query {rtype} for {target} error: {e}")

        # Check DNSSEC status
        dnssec_valid = False
        try:
            sec_ans = self.resolver.resolve(target, "DNSKEY")
            dnssec_valid = bool(sec_ans)
        except Exception:
            dnssec_valid = False

        # Tunneling / High-Entropy Heuristic
        subdomains = target.split(".")
        longest_label = max(subdomains, key=len) if subdomains else ""
        entropy = calculate_shannon_entropy(longest_label)
        is_suspicious_tunnel = (len(longest_label) > 35) or (len(longest_label) > 20 and entropy > 3.8)

        return {
            "target": target,
            "is_reverse": False,
            "records": [r.dict() for r in records],
            "total_records": len(records),
            "dnssec_status": "SECURED (DNSSEC Active)" if dnssec_valid else "UNPROTECTED (No DNSSEC Records Found)",
            "average_response_ms": round(total_time / max(len(records), 1), 2),
            "tunneling_anomaly_detected": is_suspicious_tunnel,
            "longest_label_length": len(longest_label),
            "label_entropy": round(entropy, 2),
            "heuristic_evaluation": "High-entropy query signature detected (Potential DNS Tunneling)" if is_suspicious_tunnel else "Standard DNS Architecture"
        }


dns_engine = DnsIntelligenceEngine()
