"""
SNMK MAP ?" Network Performance and Internet Speed Engine
Executes genuine bandwidth, latency, jitter, packet loss, and DNS timing measurements.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import re
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import httpx

from core.network.models import SpeedTestResult

logger = logging.getLogger("snmk.map.perf")


class NetworkPerformanceEngine:
    """Accurate, non-destructive network throughput and latency benchmarking."""

    def __init__(self):
        self.history: List[SpeedTestResult] = []

    async def measure_ping_and_jitter(self, target: str = "1.1.1.1", count: int = 4) -> Dict[str, float]:
        """Measures ping, jitter, and packet loss using system ICMP ping."""
        rtts = []
        loss_pct = 0.0

        if sys.platform.startswith("win"):
            cmd = ["ping", "-n", str(count), target]
        else:
            cmd = ["ping", "-c", str(count), target]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            # Find times e.g. time=21ms or time<1ms
            times = [float(x) for x in re.findall(r"time[=<](\d+(?:\.\d+)?)\s*ms", proc.stdout, re.IGNORECASE)]
            rtts = times
            # Extract loss
            loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", proc.stdout, re.IGNORECASE)
            if loss_match:
                loss_pct = float(loss_match.group(1))
        except Exception as e:
            logger.debug(f"Ping failed: {e}")

        if not rtts:
            return {"ping_ms": 0.0, "jitter_ms": 0.0, "packet_loss_pct": 100.0}

        avg_ping = statistics.mean(rtts)
        jitter = statistics.stdev(rtts) if len(rtts) > 1 else 0.0

        return {
            "ping_ms": round(avg_ping, 2),
            "jitter_ms": round(jitter, 2),
            "packet_loss_pct": round(loss_pct, 1)
        }

    async def measure_dns_latency(self, domain: str = "google.com") -> float:
        """Measures resolution timing for DNS records."""
        import dns.resolver
        res = dns.resolver.Resolver()
        res.timeout = 2.0
        start = time.perf_counter()
        try:
            res.resolve(domain, "A")
            return round((time.perf_counter() - start) * 1000, 2)
        except Exception:
            return 0.0

    async def run_speed_test(self, include_upload: bool = True, duration_seconds: int = 5) -> SpeedTestResult:
        """Measures Download Mbps, Upload Mbps, Latency, Jitter, and Packet Loss."""
        start_overall = time.perf_counter()

        # 1. Ping, Jitter & Loss
        ping_data = await self.measure_ping_and_jitter("1.1.1.1", count=4)
        dns_time = await self.measure_dns_latency()

        # 2. Download Throughput (Cloudflare Speed Benchmark Chunk)
        download_mbps = 0.0
        test_server = "Cloudflare Global Edge Network"

        try:
            download_url = "https://speed.cloudflare.com/__down?bytes=10000000"
            t0 = time.perf_counter()
            async with httpx.AsyncClient(timeout=12.0) as client:
                res = await client.get(download_url)
                dur = time.perf_counter() - t0
                if res.status_code == 200 and dur > 0:
                    bytes_len = len(res.content)
                    download_mbps = round((bytes_len * 8) / (dur * 1_000_000), 2)
        except Exception as e:
            logger.debug(f"Primary speed test download failed: {e}")
            # Fallback smaller payload
            try:
                t0 = time.perf_counter()
                async with httpx.AsyncClient(timeout=8.0) as client:
                    res = await client.get("https://speed.cloudflare.com/__down?bytes=2500000")
                    dur = time.perf_counter() - t0
                    if res.status_code == 200 and dur > 0:
                        download_mbps = round((len(res.content) * 8) / (dur * 1_000_000), 2)
            except Exception:
                pass

        # 3. Upload Throughput
        upload_mbps = 0.0
        if include_upload:
            try:
                # 2 MB payload
                upload_payload = b"0" * 2_000_000
                t0 = time.perf_counter()
                async with httpx.AsyncClient(timeout=10.0) as client:
                    res = await client.post("https://speed.cloudflare.com/__up", content=upload_payload)
                    dur = time.perf_counter() - t0
                    if res.status_code in (200, 204) and dur > 0:
                        upload_mbps = round((len(upload_payload) * 8) / (dur * 1_000_000), 2)
            except Exception as e:
                logger.debug(f"Upload test failed: {e}")

        total_dur = round(time.perf_counter() - start_overall, 2)

        result = SpeedTestResult(
            download_mbps=download_mbps,
            upload_mbps=upload_mbps,
            ping_ms=ping_data["ping_ms"],
            jitter_ms=ping_data["jitter_ms"],
            packet_loss_pct=ping_data["packet_loss_pct"],
            dns_time_ms=dns_time,
            test_server=test_server,
            test_duration_seconds=total_dur,
            status="COMPLETED"
        )

        self.history.insert(0, result)
        if len(self.history) > 20:
            self.history.pop()

        return result


perf_engine = NetworkPerformanceEngine()
