# SNMK Network Security Architecture & Engineering Report

**Audit Area:** Network Security, Protocol Analysis, Socket Safety & Scope Boundaries  
**Target Repository:** `https://github.com/545e/snmk.git`  
**Network Modules:** `core/network/`, `web/network_api.py`, `core/scope_policy.py`  
**Status:** **OPERATIONAL & SCOPE BOUNDED**

---

## 1. Executive Summary

This report evaluates the networking subsystem of SNMK, including active scanning, socket lifecycle management, DNS resolution, packet capture driver interfacing, and cross-platform network safety across Windows, Linux, and macOS.

---

## 2. Network Interface & Driver Interfacing (`core/network/interfaces.py`)

SNMK supports dual-mode packet capture:
- **Windows:** Detects Npcap and WinPcap drivers via Windows Registry and system DLL lookups. If Npcap is absent, the system gracefully falls back to synthetic network emulation or standard socket probing without crashing.
- **Linux:** Interacts with `libpcap-dev` via raw AF_PACKET sockets with non-root capability detection (`CAP_NET_RAW` / `CAP_NET_ADMIN`).
- **macOS:** BPF (Berkeley Packet Filter) interface discovery.

---

## 3. Protocol Handling & Scope Boundaries

1. **IPv4 and IPv6 Handling:** Dual-stack support is enabled. IPv6 link-local addresses (`fe80::/10`) and multicast addresses (`ff00::/8`) are subject to strict target validation.
2. **DNS Resolution & Rebinding Protection:** Target domains are resolved immediately prior to socket initialization to defeat time-of-check to time-of-use (TOCTOU) DNS rebinding attacks.
3. **TCP Handshake Analysis:** The platform tracks complete 3-way handshakes (`SYN` -> `SYN/ACK` -> `ACK`) and flags abnormal terminations (`RST`, half-open scans).
4. **Subprocess Isolation:** Network scanners (Nmap, Masscan, TShark) are executed with strictly bounded parameters and child process teardown handlers.
