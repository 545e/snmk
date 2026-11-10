"""
SNMK MAP ?" Wi-Fi and Wireless Intelligence Engine
Extracts active wireless interface metrics, SSID, BSSID, RSSI, channel,
frequency band, cipher suite, and evaluates link quality and security configuration.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

from core.network.models import WifiIntelligence

logger = logging.getLogger("snmk.map.wifi")


class WifiIntelligenceEngine:
    """Enterprise Wi-Fi adapter auditor and link quality analyzer."""

    def get_wifi_intelligence(self) -> Optional[WifiIntelligence]:
        """Queries OS wireless subsystems for connection quality and encryption parameters."""
        if sys.platform.startswith("win"):
            return self._get_windows_wifi()
        elif sys.platform.startswith("linux"):
            return self._get_linux_wifi()
        elif sys.platform.startswith("darwin"):
            return self._get_macos_wifi()
        return None

    def _get_windows_wifi(self) -> Optional[WifiIntelligence]:
        try:
            proc = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=5)
            if proc.returncode != 0 or not proc.stdout.strip():
                return None

            fields: Dict[str, str] = {}
            for line in proc.stdout.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    k = parts[0].strip()
                    v = parts[1].strip()
                    fields[k] = v

            if not fields.get("SSID") and not fields.get("State"):
                return None

            state = fields.get("State", "")
            if state.lower() != "connected":
                return WifiIntelligence(
                    interface_name=fields.get("Name", "Wi-Fi"),
                    quality_assessment="Disconnected",
                    security_warnings=["Wi-Fi interface is enabled but not associated with an access point."]
                )

            # Signal percentage
            sig_str = fields.get("Signal", "0%").replace("%", "").strip()
            signal_pct = int(sig_str) if sig_str.isdigit() else 0

            # Channel
            chan_str = fields.get("Channel", "").strip()
            channel = int(chan_str) if chan_str.isdigit() else None

            # Rates
            rx_str = fields.get("Receive rate (Mbps)", "").strip()
            tx_str = fields.get("Transmit rate (Mbps)", "").strip()
            rx_rate = int(float(rx_str)) if rx_str else None
            tx_rate = int(float(tx_str)) if tx_str else None

            # Security warnings
            warnings = []
            auth = fields.get("Authentication", "")
            if "OPEN" in auth.upper() or "NONE" in auth.upper():
                warnings.append("Insecure Open Wi-Fi Network: Traffic transmitted without 802.11 link-layer encryption.")
            elif "WEP" in auth.upper():
                warnings.append("Deprecated WEP Encryption: Cryptographically vulnerable to immediate key recovery.")
            elif "WPA-PERSONAL" in auth.upper() and not "WPA2" in auth.upper():
                warnings.append("Legacy WPA v1: Vulnerable to TKIP replay and downgrade attacks.")

            # Quality Assessment
            if signal_pct >= 75:
                quality = "Excellent Link Quality"
            elif signal_pct >= 50:
                quality = "Good Link Quality"
            elif signal_pct >= 30:
                quality = "Fair Link Quality (Potential attenuation)"
            else:
                quality = "Poor Link Quality (High Packet Loss Expected)"

            # Estimate RSSI from percentage if missing
            rssi = None
            if "Rssi" in fields:
                try:
                    rssi = int(fields["Rssi"])
                except Exception:
                    pass
            if rssi is None and signal_pct > 0:
                # Standard approximation: dBm = (signal_pct / 2) - 100
                rssi = int((signal_pct / 2.0) - 100)

            return WifiIntelligence(
                interface_name=fields.get("Name", "Wi-Fi"),
                ssid=fields.get("SSID"),
                bssid=fields.get("AP BSSID") or fields.get("BSSID"),
                signal_pct=signal_pct,
                rssi_dbm=rssi,
                channel=channel,
                band=fields.get("Band"),
                radio_type=fields.get("Radio type"),
                auth_cipher=f"{auth} / {fields.get('Cipher', 'Unknown')}",
                tx_rate_mbps=tx_rate,
                rx_rate_mbps=rx_rate,
                quality_assessment=quality,
                security_warnings=warnings
            )

        except Exception as e:
            logger.error(f"Windows Wi-Fi query failed: {e}")
            return None

    def _get_linux_wifi(self) -> Optional[WifiIntelligence]:
        try:
            proc = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi"],
                                  capture_output=True, text=True, timeout=5)
            for line in proc.stdout.splitlines():
                if line.startswith("yes:"):
                    parts = line.split(":")
                    if len(parts) >= 6:
                        signal = int(parts[3]) if parts[3].isdigit() else 0
                        channel = int(parts[4]) if parts[4].isdigit() else None
                        return WifiIntelligence(
                            interface_name="wlan0",
                            ssid=parts[1],
                            bssid=parts[2],
                            signal_pct=signal,
                            channel=channel,
                            auth_cipher=parts[5],
                            quality_assessment="Good" if signal >= 50 else "Fair"
                        )
        except Exception:
            pass
        return None

    def _get_macos_wifi(self) -> Optional[WifiIntelligence]:
        # macOS airport utility
        return None


wifi_engine = WifiIntelligenceEngine()
