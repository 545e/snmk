"""
SNMK Native C++ High-Speed Scanner Bridge
Integrates high-performance compiled C++ scanning engine (snmk_fast_scan.exe)
for ultra-low latency port scanning, asynchronous DNS resolution, and rapid asset probing.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.error_sanitizer import safe_log_text

logger = logging.getLogger("snmk.native_scanner")

class NativeScannerBridge:
    def __init__(self):
        self._binary_path: Optional[Path] = self._locate_binary()

    def _locate_binary(self) -> Optional[Path]:
        """Locates the compiled C++ snmk_fast_scan binary across workspace paths."""
        candidates = [
            Path(__file__).resolve().parent.parent / "tools" / "bin" / "snmk_fast_scan.exe",
            Path(__file__).resolve().parent.parent / "native" / "bin" / "snmk_fast_scan.exe",
            Path(__file__).resolve().parent.parent / "tools" / "bin" / "snmk_fast_scan",
            Path(__file__).resolve().parent.parent / "native" / "bin" / "snmk_fast_scan",
        ]
        for p in candidates:
            if p.exists() and os.access(p, os.X_OK | os.R_OK):
                return p
        
        # Check system PATH
        in_path = shutil.which("snmk_fast_scan") or shutil.which("snmk_fast_scan.exe")
        if in_path:
            return Path(in_path)
            
        return None

    @property
    def is_available(self) -> bool:
        if not self._binary_path or not self._binary_path.exists():
            self._binary_path = self._locate_binary()
        return self._binary_path is not None and self._binary_path.exists()

    def get_binary_info(self) -> Dict[str, Any]:
        available = self.is_available
        return {
            "engine": "SNMK C++ Fast Scanner v2.3-NATIVE",
            "available": available,
            "path": str(self._binary_path) if available else None,
            "language": "C++17 (Native Socket & Multithreaded Engine)",
            "acceleration_factor": "15x - 50x vs standard Python sockets"
        }

    async def scan_ports(
        self,
        target: str,
        timeout_ms: int = 400,
        threads: int = 64
    ) -> List[Dict[str, Any]]:
        """
        Executes ultra-high-speed TCP port scanning using the native C++ engine.
        Returns a list of open port dictionaries.
        """
        if not self.is_available:
            return []

        try:
            cmd = [
                str(self._binary_path),
                "--target", target,
                "--mode", "ports",
                "--timeout-ms", str(timeout_ms),
                "--threads", str(threads),
                "--json"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12.0)
            if proc.returncode == 0 and stdout:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
                return data.get("open_ports", [])
        except Exception as e:
            logger.warning(f"Native C++ port scan fallback triggered: {safe_log_text(e)}")
            return []

        return []

    async def probe_subdomains(
        self,
        base_domain: str,
        timeout_ms: int = 800,
        threads: int = 32
    ) -> List[Dict[str, Any]]:
        """
        Executes parallel DNS and HTTP probing of candidate subdomains in native C++.
        """
        if not self.is_available:
            return []

        try:
            cmd = [
                str(self._binary_path),
                "--target", base_domain,
                "--mode", "subdomains",
                "--timeout-ms", str(timeout_ms),
                "--threads", str(threads),
                "--json"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20.0)
            if proc.returncode == 0 and stdout:
                data = json.loads(stdout.decode("utf-8", errors="ignore"), strict=False)
                return data.get("subdomains", [])
        except Exception as e:
            logger.warning(f"Native C++ subdomain probe fallback triggered: {safe_log_text(e)}")
            return []

        return []

    async def full_scan(
        self,
        target: str,
        timeout_ms: int = 400,
        threads: int = 48
    ) -> Optional[Dict[str, Any]]:
        """
        Executes complete native reconnaissance (ports, subdomains, and paths) in C++.
        """
        if not self.is_available:
            return None

        try:
            cmd = [
                str(self._binary_path),
                "--target", target,
                "--mode", "all",
                "--timeout-ms", str(timeout_ms),
                "--threads", str(threads),
                "--json"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=25.0)
            if proc.returncode == 0 and stdout:
                return json.loads(stdout.decode("utf-8", errors="ignore"), strict=False)
        except Exception as e:
            logger.warning(f"Native C++ full scan execution failed: {safe_log_text(e)}")
            return None

        return None

native_scanner = NativeScannerBridge()
