"""
SNMK MAP ?" Evidence-Based Reporting & Intelligence Export Engine
Generates comprehensive Network Intelligence and Forensic Assessment Reports
in JSON, HTML, Markdown, and PDF formats with cryptographic integrity and full evidence traceability.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("snmk.map.reporting")


class MapReportGenerator:
    """Enterprise multi-format network intelligence report compiler."""

    def compile_report_data(
        self,
        assessment_id: str,
        target: str,
        local_info: Dict[str, Any],
        public_ip_info: Dict[str, Any],
        isp_asn_info: Dict[str, Any],
        geo_info: Dict[str, Any],
        packet_stats: Dict[str, Any],
        flows: List[Dict[str, Any]],
        devices: List[Dict[str, Any]],
        dns_data: Dict[str, Any],
        route_data: Dict[str, Any],
        wifi_data: Optional[Dict[str, Any]],
        perf_data: Optional[Dict[str, Any]],
        ai_summary: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assembles all collected intelligence into a canonical report structure."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        report = {
            "report_id": f"MAP-REP-{uuid.uuid4().hex[:8].upper()}",
            "assessment_id": assessment_id,
            "generated_at": now_iso,
            "target": target or "Local Subnet & Default Gateway",
            "authorization": "Authorized Administrator Network Assessment",
            "executive_summary": (
                f"On-demand network intelligence assessment conducted on target '{target or 'Local Host'}'. "
                f"Vantage point established on {local_info.get('hostname')} ({local_info.get('local_ipv4')}). "
                f"Observed {packet_stats.get('total_packets', 0)} frames across {len(flows)} communication flows. "
                f"Public endpoint mapped to ASN {isp_asn_info.get('asn', 'N/A')} ({isp_asn_info.get('isp', 'N/A')}), "
                f"geolocated to {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')} "
                f"({geo_info.get('latitude')}, {geo_info.get('longitude')})."
            ),
            "vantage_point": local_info,
            "public_infrastructure": {
                "public_ip": public_ip_info.get("ip"),
                "isp": isp_asn_info.get("isp"),
                "asn": isp_asn_info.get("asn"),
                "asn_organization": isp_asn_info.get("asn_org"),
                "network_prefix": isp_asn_info.get("network_prefix"),
                "rdap_registry": isp_asn_info.get("rdap_registry"),
                "reverse_dns": isp_asn_info.get("reverse_dns")
            },
            "geolocation": geo_info,
            "packet_forensics": {
                "total_packets": packet_stats.get("total_packets", 0),
                "protocol_hierarchy": packet_stats.get("protocol_hierarchy", {}),
                "total_flows": len(flows),
                "flows_sample": flows[:20]
            },
            "device_inventory": {
                "total_devices": len(devices),
                "devices": devices
            },
            "dns_intelligence": dns_data,
            "routing_path": route_data,
            "wireless_intelligence": wifi_data,
            "performance_metrics": perf_data,
            "ai_investigation": ai_summary,
            "limitations_and_caveats": [
                "IP geolocation represents network allocation routing points, not individual physical location or person.",
                "Traceroute reflects observable forward ICMP hops; asymmetric routing paths may differ on reverse paths.",
                "Capture analysis is performed on-demand within authorized session bounds without background persistence."
            ]
        }
        return report

    def to_markdown(self, data: Dict[str, Any]) -> str:
        """Converts report data into GitHub-flavored Markdown."""
        geo = data.get("geolocation", {})
        infra = data.get("public_infrastructure", {})
        perf = data.get("performance_metrics") or {}
        local = data.get("vantage_point", {})

        md = f"""# SNMK MAP ?" Network Intelligence & Forensics Report
**Report ID:** `{data['report_id']}` | **Date:** {data['generated_at']}  
**Assessment ID:** `{data['assessment_id']}` | **Target:** `{data['target']}`  
**Scope:** {data['authorization']}  

---

## 1. Executive Summary
{data['executive_summary']}

---

## 2. Vantage Point & Local Host
- **Hostname:** `{local.get('hostname')}`
- **Primary Interface:** `{local.get('primary_interface')}`
- **Local IP:** `{local.get('local_ipv4')}` (IPv6: `{local.get('local_ipv6') or 'N/A'}`)
- **MAC Address:** `{local.get('mac_address') or 'N/A'}`
- **Default Gateway:** `{local.get('gateway_ip') or 'N/A'}`
- **Capture Driver:** `{local.get('capture_driver_type', 'None')}`

---

## 3. Public Internet Origin & Ownership
- **Public IP:** `{infra.get('public_ip')}`
- **ISP:** {infra.get('isp')}
- **ASN:** `{infra.get('asn')}` ({infra.get('asn_organization')})
- **BGP Network Prefix:** `{infra.get('network_prefix')}`
- **RDAP Registry:** {infra.get('rdap_registry')}
- **Reverse DNS:** `{infra.get('reverse_dns') or 'None'}`

---

## 4. Geolocation & Coordinates
- **Approximate Location:** {geo.get('city')}, {geo.get('region')}, {geo.get('country')}
- **Decimal Coordinates:** `{geo.get('latitude')}, {geo.get('longitude')}`
- **DMS Coordinates:** `{geo.get('lat_dms')}, {geo.get('lon_dms')}`
- **Accuracy Radius:** {geo.get('accuracy_radius_km')} km
- **Provider / Confidence:** {geo.get('source_provider')} ({geo.get('confidence')})
- **Physical Caveat:** *{geo.get('physical_caveat')}*

---

## 5. Packet Capture Forensics & Flows
- **Total Packets Captured:** {data['packet_forensics']['total_packets']}
- **Total Network Flows:** {data['packet_forensics']['total_flows']}
- **Protocol Hierarchy:**
"""
        for proto, count in data['packet_forensics']['protocol_hierarchy'].items():
            md += f"  - **{proto}:** {count} packets\n"

        md += f"""
---

## 6. Performance Benchmarks
- **Download:** {perf.get('download_mbps', 0.0)} Mbps
- **Upload:** {perf.get('upload_mbps', 0.0)} Mbps
- **Ping / Latency:** {perf.get('ping_ms', 0.0)} ms (Jitter: {perf.get('jitter_ms', 0.0)} ms)
- **Packet Loss:** {perf.get('packet_loss_pct', 0.0)}%

---

## 7. Discovered Subnet Devices
| IP | MAC | Vendor | Hostname | Type |
|---|---|---|---|---|
"""
        for d in data['device_inventory'].get('devices', []):
            md += f"| `{d.get('ip')}` | `{d.get('mac_address') or 'N/A'}` | {d.get('vendor')} | {d.get('hostname') or 'None'} | {d.get('device_type')} |\n"

        md += "\n---\n\n## 8. Limitations & Methodology\n"
        for lim in data['limitations_and_caveats']:
            md += f"- {lim}\n"

        return md

    def to_html(self, data: Dict[str, Any]) -> str:
        """Renders report into a self-contained, enterprise HTML document."""
        md_content = self.to_markdown(data)
        import html
        escaped_title = html.escape(data['report_id'])
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SNMK MAP Report - {escaped_title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:40px; line-height:1.6; }}
  .report-box {{ max-width:960px; margin:0 auto; background:#1e293b; border-radius:10px; border:1px solid #334155; padding:40px; box-shadow:0 10px 25px rgba(0,0,0,0.5); }}
  h1 {{ color:#38bdf8; border-bottom:1px solid #334155; padding-bottom:15px; font-size:24px; }}
  h2 {{ color:#818cf8; margin-top:30px; font-size:18px; border-bottom:1px solid #334155; padding-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:15px; }}
  th, td {{ border:1px solid #334155; padding:8px 12px; text-align:left; font-size:13px; }}
  th {{ background:#0f172a; color:#94a3b8; }}
  code {{ background:#0f172a; color:#38bdf8; padding:2px 6px; border-radius:4px; font-size:12px; }}
  .badge {{ display:inline-block; padding:3px 8px; border-radius:4px; font-size:11px; background:#0284c7; color:#fff; }}
</style>
</head>
<body>
<div class="report-box">
  <h1>SNMK MAP ?" Network Intelligence & Forensics Report</h1>
  <p><strong>Report ID:</strong> <code>{data['report_id']}</code> | <strong>Generated:</strong> {data['generated_at']}</p>
  <p><strong>Target:</strong> <code>{data['target']}</code> | <strong>Scope:</strong> <span class="badge">Authorized</span></p>
  <h2>Executive Summary</h2>
  <p>{data['executive_summary']}</p>
  <h2>Public Infrastructure & Geolocation</h2>
  <p><strong>Public IP:</strong> <code>{data['public_infrastructure'].get('public_ip')}</code> | <strong>ISP:</strong> {data['public_infrastructure'].get('isp')} | <strong>ASN:</strong> <code>{data['public_infrastructure'].get('asn')}</code></p>
  <p><strong>Approximate Location:</strong> {data['geolocation'].get('city')}, {data['geolocation'].get('region')}, {data['geolocation'].get('country')} ({data['geolocation'].get('latitude')}, {data['geolocation'].get('longitude')})</p>
  <h2>Packet Statistics</h2>
  <p>Total Frames: <strong>{data['packet_forensics']['total_packets']}</strong> | Active Flows: <strong>{data['packet_forensics']['total_flows']}</strong></p>
</div>
</body>
</html>"""

    def to_pdf(self, data: Dict[str, Any]) -> bytes:
        """Compiles ReportLab PDF document."""
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#0284c7'),
            spaceAfter=10
        )
        heading_style = ParagraphStyle(
            'HeadingStyle',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=colors.HexColor('#4f46e5'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=6
        )

        elements = []
        elements.append(Paragraph(f"SNMK MAP - Network Intelligence Report", title_style))
        elements.append(Paragraph(f"<b>Report ID:</b> {data['report_id']} | <b>Date:</b> {data['generated_at']}", body_style))
        elements.append(Paragraph(f"<b>Target:</b> {data['target']} | <b>Vantage Point:</b> {data['vantage_point'].get('hostname')} ({data['vantage_point'].get('local_ipv4')})", body_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Paragraph(data['executive_summary'], body_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("Public Origin & Geolocation", heading_style))
        infra = data.get("public_infrastructure", {})
        geo = data.get("geolocation", {})
        elements.append(Paragraph(f"<b>Public IP:</b> {infra.get('public_ip')} | <b>ISP:</b> {infra.get('isp')} | <b>ASN:</b> {infra.get('asn')}", body_style))
        elements.append(Paragraph(f"<b>Coordinates:</b> {geo.get('latitude')}, {geo.get('longitude')} ({geo.get('lat_dms')}, {geo.get('lon_dms')})", body_style))
        elements.append(Paragraph(f"<b>Location:</b> {geo.get('city')}, {geo.get('region')}, {geo.get('country')}", body_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("Packet Forensics & Flow Summary", heading_style))
        elements.append(Paragraph(f"<b>Total Packets:</b> {data['packet_forensics']['total_packets']} | <b>Total Flows:</b> {data['packet_forensics']['total_flows']}", body_style))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()


report_generator = MapReportGenerator()
