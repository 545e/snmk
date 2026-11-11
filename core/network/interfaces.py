"""
SNMK MAP ?" Network Interface Discovery and Configuration Service
Detects host interfaces, IP addresses (IPv4 & IPv6), MAC addresses,
default gateways, DNS servers, and capture driver capabilities across Windows, Linux, and macOS.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

import psutil

from core.network.models import LocalNetworkInfo, NetworkInterfaceInfo

logger = logging.getLogger("snmk.map.interfaces")


_cached_network_info: Optional[Tuple[float, LocalNetworkInfo]] = None
_NETWORK_CACHE_TTL_SEC: float = 60.0


def check_capture_drivers() -> Tuple[bool, str]:
    """Detects packet capture capabilities on host (Npcap, libpcap, TShark, Scapy)."""
    driver_type = "None"
    driver_installed = False

    # Check TShark / Dumpcap
    tshark_path = shutil.which("tshark") or shutil.which("dumpcap")
    if sys.platform.startswith("win"):
        win_tshark = r"C:\Program Files\Wireshark\tshark.exe"
        if not tshark_path and os.path.exists(win_tshark):
            tshark_path = win_tshark

    # Check Npcap on Windows
    if sys.platform.startswith("win"):
        npcap_dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll")
        winpcap_dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll")
        if os.path.exists(npcap_dll):
            driver_installed = True
            driver_type = "Npcap (Windows Packet Capture Driver)"
        elif os.path.exists(winpcap_dll):
            driver_installed = True
            driver_type = "WinPcap (Legacy Windows Packet Capture)"
        elif tshark_path:
            driver_installed = True
            driver_type = f"TShark Dissector ({tshark_path})"
        else:
            driver_installed = False
            driver_type = "Socket Flow Monitor & Offline PCAP/PCAPNG Dissector (Npcap Not Installed)"
    else:
        # Linux / macOS
        libpcap_installed = bool(shutil.which("tcpdump") or tshark_path)
        driver_installed = libpcap_installed
        driver_type = "libpcap / BPF Driver" if libpcap_installed else "Socket Flow Monitor"

    return driver_installed, driver_type


def get_default_gateway_and_dns() -> Tuple[Optional[str], Optional[str], List[str]]:
    """Retrieves system default gateway IP, interface alias, and DNS servers."""
    gateway_ip = None
    iface_alias = None
    dns_servers = []

    if sys.platform.startswith("win"):
        # Fast path 1: parse route print (takes <100ms vs 5s PowerShell)
        try:
            proc = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=3)
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway_ip = parts[2]
                    break
        except Exception as e:
            logger.debug(f"Fast route print gateway lookup failed: {e}")

        # Fast path 2: query DNS nameservers using dnspython
        try:
            import dns.resolver
            res = dns.resolver.Resolver()
            if res.nameservers:
                dns_servers = list(res.nameservers)
        except Exception:
            pass

        # Optional slow fallback if gateway was not detected
        if not gateway_ip:
            try:
                cmd = ["powershell", "-NoProfile", "-Command",
                       "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 NextHop, InterfaceAlias | ConvertTo-Json"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if proc.returncode == 0 and proc.stdout.strip():
                    import json
                    data = json.loads(proc.stdout)
                    gateway_ip = data.get("NextHop")
                    iface_alias = data.get("InterfaceAlias")
            except Exception as e:
                logger.debug(f"Failed to get gateway via Get-NetRoute: {e}")

        if not dns_servers:
            try:
                cmd = ["powershell", "-NoProfile", "-Command",
                       "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if proc.returncode == 0 and proc.stdout.strip():
                    import json
                    servers = json.loads(proc.stdout)
                    if isinstance(servers, list):
                        dns_servers = [s for s in servers if s]
                    elif isinstance(servers, str) and servers:
                        dns_servers = [servers]
            except Exception:
                pass
    else:
        # Linux / Unix / macOS
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1].strip())
        except Exception:
            pass

        try:
            proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
            match = re.search(r"default via ([0-9.]+)\s+dev\s+(\S+)", proc.stdout)
            if match:
                gateway_ip = match.group(1)
                iface_alias = match.group(2)
        except Exception:
            pass

    # Fallback DNS if none discovered
    if not dns_servers:
        dns_servers = ["1.1.1.1", "8.8.8.8"]

    return gateway_ip, iface_alias, list(dict.fromkeys(dns_servers))


def get_network_interfaces() -> List[NetworkInterfaceInfo]:
    """Inspects all network interfaces on the system and formats into models."""
    results: List[NetworkInterfaceInfo] = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    capture_driver_ok, driver_type = check_capture_drivers()

    gateway_ip, gateway_iface, _ = get_default_gateway_and_dns()

    for iface_name, addr_list in addrs.items():
        ipv4_list = []
        ipv6_list = []
        mac = None
        netmask = None
        broadcast = None

        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ipv4_list.append(addr.address)
                if not netmask and addr.netmask:
                    netmask = addr.netmask
                if not broadcast and addr.broadcast:
                    broadcast = addr.broadcast
            elif addr.family == socket.AF_INET6:
                ipv6_list.append(addr.address)
            elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                mac = addr.address

        iface_stat = stats.get(iface_name)
        is_up = iface_stat.isup if iface_stat else False
        speed = iface_stat.speed if iface_stat else 0
        mtu = iface_stat.mtu if iface_stat else 1500

        # Determine type
        lower_name = iface_name.lower()
        if "loopback" in lower_name:
            iface_type = "Loopback"
        elif "wi-fi" in lower_name or "wlan" in lower_name or "wireless" in lower_name:
            iface_type = "Wi-Fi"
        elif "vethernet" in lower_name or "hyper-v" in lower_name or "wsl" in lower_name or "vmnet" in lower_name:
            iface_type = "Virtual / Hypervisor"
        elif "tunnel" in lower_name or "tap" in lower_name or "tun" in lower_name or "tailscale" in lower_name:
            iface_type = "VPN / Tunnel"
        else:
            iface_type = "Ethernet"

        has_gateway = (iface_name == gateway_iface) or (gateway_ip and any(ip == gateway_ip for ip in ipv4_list))

        info = NetworkInterfaceInfo(
            name=iface_name,
            description=f"{iface_type} Network Interface ({iface_name})",
            interface_type=iface_type,
            is_up=is_up,
            speed_mbps=speed,
            mtu=mtu,
            mac_address=mac,
            ipv4_addresses=ipv4_list,
            ipv6_addresses=ipv6_list,
            netmask=netmask,
            broadcast=broadcast,
            gateway=gateway_ip if has_gateway else None,
            capture_capable=True,
            required_permissions="Local Host Administrator / Npcap / libpcap"
        )
        results.append(info)

    return results


def get_local_network_info(force_refresh: bool = False) -> LocalNetworkInfo:
    """Compiles complete local network posture for MAP dashboard."""
    global _cached_network_info
    now = time.time()
    if not force_refresh and _cached_network_info is not None:
        cached_time, cached_val = _cached_network_info
        if (now - cached_time) < _NETWORK_CACHE_TTL_SEC:
            return cached_val

    hostname = socket.gethostname()
    interfaces = get_network_interfaces()
    gateway_ip, gateway_iface, dns_servers = get_default_gateway_and_dns()
    capture_ok, driver_type = check_capture_drivers()

    # Find the primary active interface
    primary_iface = None
    if gateway_iface:
        for ifc in interfaces:
            if ifc.name == gateway_iface:
                primary_iface = ifc
                break

    if not primary_iface:
        for ifc in interfaces:
            if ifc.is_up and ifc.ipv4_addresses and ifc.interface_type != "Loopback":
                primary_iface = ifc
                break

    if not primary_iface and interfaces:
        primary_iface = interfaces[0]

    local_ip = "127.0.0.1"
    local_ipv6 = None
    mac = None
    subnet_cidr = None

    if primary_iface:
        if primary_iface.ipv4_addresses:
            # Prefer non-link-local IPv4
            for ip in primary_iface.ipv4_addresses:
                if not ip.startswith("169.254."):
                    local_ip = ip
                    break
            if local_ip == "127.0.0.1" and primary_iface.ipv4_addresses:
                local_ip = primary_iface.ipv4_addresses[0]

        if primary_iface.ipv6_addresses:
            local_ipv6 = primary_iface.ipv6_addresses[0]
        mac = primary_iface.mac_address

        # Calculate CIDR
        if primary_iface.netmask and local_ip != "127.0.0.1":
            try:
                net = ipaddress.IPv4Network(f"{local_ip}/{primary_iface.netmask}", strict=False)
                subnet_cidr = str(net)
            except Exception:
                subnet_cidr = f"{local_ip}/24"

    res = LocalNetworkInfo(
        hostname=hostname,
        primary_interface=primary_iface.name if primary_iface else "Ethernet",
        local_ipv4=local_ip,
        local_ipv6=local_ipv6,
        mac_address=mac,
        gateway_ip=gateway_ip,
        gateway_mac=None,
        dns_servers=dns_servers,
        subnet_cidr=subnet_cidr or "192.168.1.0/24",
        interfaces=interfaces,
        capture_driver_installed=capture_ok,
        capture_driver_type=driver_type
    )
    _cached_network_info = (now, res)
    return res
