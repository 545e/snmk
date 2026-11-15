"""
Tests for SNMK C++ High-Speed Native Scanner Engine & Python Bridge
"""

import asyncio
import os
import pytest
from core.native_scanner import native_scanner

def test_native_scanner_binary_detection():
    info = native_scanner.get_binary_info()
    assert info["engine"] == "SNMK C++ Fast Scanner v2.3-NATIVE"
    assert "C++17" in info["language"]
    assert info["available"] is True, "C++ snmk_fast_scan.exe binary must be detected"

def test_native_scanner_port_scan_localhost():
    async def _test():
        assert native_scanner.is_available is True
        ports = await native_scanner.scan_ports("127.0.0.1", timeout_ms=300, threads=32)
        assert isinstance(ports, list)
    asyncio.run(_test())

def test_native_scanner_full_recon():
    async def _test():
        assert native_scanner.is_available is True
        res = await native_scanner.full_scan("127.0.0.1", timeout_ms=250, threads=16)
        assert res is not None
        assert res.get("engine") == "SNMK C++ Fast Scanner v2.3-NATIVE"
        assert "total_duration_ms" in res
        assert res["total_duration_ms"] < 2500, "Native scan must complete within 2.5 seconds"
    asyncio.run(_test())
