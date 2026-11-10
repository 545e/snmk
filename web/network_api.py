"""
SNMK MAP ?" Enterprise Network Intelligence & Packet Forensics API Router
FastAPI router providing endpoints for network interfaces, Wireshark-style packet capture,
PCAP forensics, origin identification, geolocation, DNS, routing, BGP, Wi-Fi, speed test,
threat intelligence, AI investigation, and evidence-based reporting.
"""

from __future__ import annotations

import asyncio
import datetime
import io
import json
import logging
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, File, HTTPException, Query, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from core.app_security import authenticate_request
from core.network.ai_assistant import map_ai_assistant
from core.network.discovery import discovery_engine
from core.network.dns_engine import dns_engine
from core.network.geo_engine import geo_engine
from core.network.infrastructure import infra_engine
from core.network.interfaces import check_capture_drivers, get_local_network_info, get_network_interfaces
from core.network.models import (
    AiQueryRequest,
    CaptureStartRequest,
    DiscoveryStartRequest,
    GeocodeRequest,
    OriginInvestigationRequest,
    RouteAnalyzeRequest,
    SpeedTestRequest,
)
from core.network.origin_engine import origin_engine
from core.network.packet_engine import live_capture
from core.network.pcap_forensics import pcap_engine
from core.network.performance_engine import perf_engine
from core.network.reporting import report_generator
from core.network.routing_engine import route_engine
from core.network.threat_engine import threat_engine
from core.network.wifi_engine import wifi_engine

logger = logging.getLogger("snmk.map.api")

router = APIRouter(prefix="/api/network", tags=["Network Intelligence (MAP)"])

# In-memory storage for active assessment sessions and generated reports
_active_sessions: Dict[str, Dict[str, Any]] = {}
_saved_reports: Dict[str, Dict[str, Any]] = {}


# --- Interface & Host Posture Endpoints ---

@router.get("/interfaces")
async def list_network_interfaces(request: Request):
    """Retrieves all detected host network interfaces with IPv4, IPv6, MAC, and capabilities."""
    authenticate_request(request)
    interfaces = get_network_interfaces()
    capture_ok, driver_type = check_capture_drivers()
    return {
        "success": True,
        "total": len(interfaces),
        "capture_driver_installed": capture_ok,
        "capture_driver_type": driver_type,
        "interfaces": [ifc.dict() for ifc in interfaces]
    }


@router.get("/local-info")
async def get_local_posture(request: Request):
    """Returns local network posture, default gateway, DNS servers, and subnet CIDR."""
    authenticate_request(request)
    info = get_local_network_info()
    return {"success": True, "posture": info.dict()}


@router.get("/public-ip")
async def get_public_ip_address(request: Request):
    """Discovers public IPv4/IPv6 visible to external internet from monitoring vantage point."""
    authenticate_request(request)
    result = await infra_engine.get_public_ip()
    return result


# --- IP, ISP, ASN, Geolocation & Infrastructure ---

@router.get("/ip-intelligence")
async def get_ip_intelligence(request: Request, ip: Optional[str] = Query(None)):
    """Correlates ISP, ASN, BGP prefix, reverse DNS, and geolocation for an IP address."""
    authenticate_request(request)
    target_ip = ip
    if not target_ip:
        pub = await infra_engine.get_public_ip()
        target_ip = pub.get("ip") or "127.0.0.1"

    isp_info = await infra_engine.lookup_isp_asn(target_ip)
    geo_info = await geo_engine.lookup_ip_geolocation(target_ip)
    bgp_info = await infra_engine.get_bgp_prefix_info(target_ip)

    return {
        "success": True,
        "ip": target_ip,
        "isp": isp_info.dict(),
        "geolocation": geo_info.dict(),
        "bgp": bgp_info.dict()
    }


@router.get("/isp")
async def get_isp_details(request: Request, ip: str = Query(...)):
    authenticate_request(request)
    info = await infra_engine.lookup_isp_asn(ip)
    return {"success": True, "data": info.dict()}


@router.get("/asn")
async def get_asn_details(request: Request, ip: str = Query(...)):
    authenticate_request(request)
    info = await infra_engine.lookup_isp_asn(ip)
    return {"success": True, "asn": info.asn, "organization": info.asn_org, "data": info.dict()}


@router.get("/geolocation")
async def get_geolocation(request: Request, ip: str = Query(...)):
    """Geolocates public IPv4/IPv6 with Decimal and DMS coordinates."""
    authenticate_request(request)
    geo = await geo_engine.lookup_ip_geolocation(ip)
    return {"success": True, "geolocation": geo.dict()}


@router.post("/geolocation/forward")
async def forward_geocode(request: Request, body: GeocodeRequest):
    """Forward geocode: Address/Place -> Latitude + Longitude."""
    authenticate_request(request)
    result = await geo_engine.forward_geocode(body.query)
    return result


@router.post("/geolocation/reverse")
async def reverse_geocode(request: Request, body: Dict[str, float]):
    """Reverse geocode: Lat + Lon -> Address."""
    authenticate_request(request)
    lat = body.get("latitude")
    lon = body.get("longitude")
    if lat is None or lon is None:
        raise HTTPException(status_code=400, detail="latitude and longitude required.")
    result = await geo_engine.reverse_geocode(lat, lon)
    return result


# --- Wireshark-Style Packet Capture & Analysis ---

@router.post("/capture/start")
async def start_packet_capture(request: Request, body: CaptureStartRequest):
    """Starts bounded, on-demand live packet capture session."""
    ctx = authenticate_request(request)
    if ctx.role not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient privileges to initiate packet capture.")

    res = live_capture.start_capture(
        interface=body.interface,
        packet_limit=body.packet_limit,
        duration_limit=body.duration_limit,
        bpf_filter=body.bpf_filter
    )
    return res


@router.post("/capture/stop")
async def stop_packet_capture(request: Request):
    """Stops the active packet capture session."""
    authenticate_request(request)
    return live_capture.stop_capture()


@router.get("/capture/status")
async def get_capture_status(request: Request):
    """Returns status, packet count, elapsed seconds, and driver readiness."""
    authenticate_request(request)
    return live_capture.get_status()


@router.get("/capture/packets")
async def get_captured_packets(
    request: Request,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    filter: str = Query("")
):
    """Returns filtered, paginated packet summaries for the Wireshark grid table."""
    authenticate_request(request)
    return live_capture.get_packets(offset=offset, limit=limit, filter_query=filter)


@router.get("/capture/packet/{packet_no}")
async def get_packet_detail(request: Request, packet_no: int):
    """Returns deep protocol hierarchy, layer fields, and Wireshark-style hex dump for a packet."""
    authenticate_request(request)
    detail = live_capture.get_packet_detail(packet_no)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Packet #{packet_no} not found in active session.")
    return {"success": True, "packet": detail.dict()}


@router.post("/pcap/upload")
async def upload_pcap_file(request: Request, file: UploadFile = File(...)):
    """Accepts PCAP/PCAPNG file, validates SHA256 integrity, dissects frames, and extracts flows."""
    authenticate_request(request)
    content = await file.read()
    if len(content) > 25 * 1024 * 1024:  # 25 MB max bound
        raise HTTPException(status_code=413, detail="Capture file exceeds maximum size limit (25 MB).")

    res = pcap_engine.analyze_bytes(content, filename=file.filename or "upload.pcap")
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Malformed PCAP file."))
    return res


@router.get("/flows")
async def get_traffic_flows(request: Request):
    """Returns active communication flows (conversations) with sent/received statistics."""
    authenticate_request(request)
    flows = live_capture.get_flows()
    return {"success": True, "total": len(flows), "flows": [f.dict() for f in flows]}


# --- Device Discovery & Local Asset Inventory ---

@router.get("/devices")
async def list_discovered_devices(request: Request):
    """Returns discovered devices from the authorized local subnet inventory."""
    authenticate_request(request)
    devices = discovery_engine.discover_local_devices()
    return {"success": True, "total": len(devices), "devices": [d.dict() for d in devices]}


@router.post("/discovery/start")
async def start_device_discovery(request: Request, body: DiscoveryStartRequest):
    """Executes on-demand ARP/NDP subnet sweep and reports baseline changes."""
    authenticate_request(request)
    if not body.authorized_confirmation:
        raise HTTPException(status_code=400, detail="Authorized assessment confirmation required.")

    devices = discovery_engine.discover_local_devices(authorized_subnet=body.subnet_cidr)
    comparison = discovery_engine.compare_snapshots(devices)
    return {
        "success": True,
        "total_devices": len(devices),
        "comparison": comparison,
        "devices": [d.dict() for d in devices]
    }


# --- DNS, Routing, BGP & Wi-Fi ---

@router.get("/dns")
async def inspect_dns(request: Request, target: str = Query(...)):
    """Resolves DNS records (A, AAAA, MX, NS, TXT, SOA, PTR), latency, and tunneling heuristic."""
    authenticate_request(request)
    return await dns_engine.resolve_all(target)


@router.post("/route/analyze")
async def analyze_route_path(request: Request, body: RouteAnalyzeRequest):
    """Executes traceroute and enriches observable hops with ISP and coordinates."""
    authenticate_request(request)
    return await route_engine.analyze_route(target=body.target, max_hops=body.max_hops, timeout=body.timeout)


@router.get("/bgp")
async def get_bgp_info(request: Request, target: str = Query(...)):
    """Queries BGP routing status, announced prefix, and Origin ASN from global routing tables."""
    authenticate_request(request)
    info = await infra_engine.get_bgp_prefix_info(target)
    return {"success": True, "bgp": info.dict()}


@router.get("/wifi")
async def get_wifi_intelligence(request: Request):
    """Extracts wireless link parameters: SSID, BSSID, RSSI, channel, band, and security warnings."""
    authenticate_request(request)
    info = wifi_engine.get_wifi_intelligence()
    if not info:
        return {"success": False, "message": "No active Wi-Fi interface detected on host."}
    return {"success": True, "wifi": info.dict()}


# --- Performance & Speed Testing ---

@router.post("/speed-test")
async def run_speed_test(request: Request, body: SpeedTestRequest):
    """Measures genuine download/upload throughput, latency, jitter, and packet loss."""
    authenticate_request(request)
    res = await perf_engine.run_speed_test(include_upload=body.include_upload, duration_seconds=body.duration_seconds)
    return {"success": True, "result": res.dict()}


@router.get("/speed-test/history")
async def get_speed_test_history(request: Request):
    authenticate_request(request)
    return {"success": True, "history": [r.dict() for r in perf_engine.history]}


# --- Network Origin Identification & Threat Intel ---

@router.post("/origin/investigate")
async def investigate_network_origin(request: Request, body: OriginInvestigationRequest):
    """Correlates target IP/domain, local route, ASN, ISP, and classifies origin infrastructure."""
    authenticate_request(request)
    res = await origin_engine.investigate_origin(body.target)
    return {"success": True, "origin": res.dict()}


@router.post("/threat/investigate")
async def evaluate_threat_intelligence(request: Request, body: Dict[str, Any]):
    """Evaluates IP endpoint against AbuseIPDB / VirusTotal threat reputation feeds."""
    authenticate_request(request)
    ip = body.get("ip")
    port = body.get("port")
    if not ip:
        raise HTTPException(status_code=400, detail="Target IP address is required.")
    res = await threat_engine.evaluate_endpoint(ip, port)
    return {"success": True, "threat": res.dict()}


# --- AI Investigation Assistant ---

@router.post("/ai/query")
async def query_map_ai_assistant(request: Request, body: AiQueryRequest):
    """Answers user queries grounded in real MAP collected evidence and telemetry."""
    authenticate_request(request)
    res = await map_ai_assistant.answer_query(body.query, body.context)
    return {"success": True, "result": res}


# --- Evidence Reports & Exports ---

@router.post("/report/generate")
async def generate_map_report(request: Request, body: Dict[str, Any]):
    """Compiles complete network assessment intelligence into an auditable report."""
    authenticate_request(request)
    assessment_id = body.get("assessment_id", f"MAP-{uuid.uuid4().hex[:6].upper()}")
    target = body.get("target", "")

    local_info = get_local_network_info().dict()
    public_ip_res = await infra_engine.get_public_ip()
    pub_ip = public_ip_res.get("ip") or local_info.get("local_ipv4")

    # Fetch enrichment concurrently for low latency
    async def get_isp():
        try:
            return (await infra_engine.lookup_isp_asn(pub_ip)).dict()
        except Exception:
            return {}

    async def get_geo():
        try:
            return (await geo_engine.lookup_ip_geolocation(pub_ip)).dict()
        except Exception:
            return {}

    async def get_dns():
        try:
            if target:
                return await dns_engine.resolve_all(target)
            return {"target": "N/A", "records": [], "tunneling_anomaly_score": 0.0, "dnssec_status": "N/A"}
        except Exception:
            return {}

    async def get_ai():
        try:
            return await map_ai_assistant.answer_query("Summarize this network capture.", None)
        except Exception:
            return {}

    isp_info, geo_info, dns_data, ai_summary = await asyncio.gather(
        get_isp(), get_geo(), get_dns(), get_ai()
    )

    cap_status = live_capture.get_status()
    flows = [f.dict() for f in live_capture.get_flows()]
    devices = [d.dict() for d in discovery_engine.discover_local_devices()]
    wifi_data = wifi_engine.get_wifi_intelligence()
    perf_data = perf_engine.history[0].dict() if perf_engine.history else None
    route_data = {"target": target or pub_ip or "local", "destination_ip": pub_ip or "127.0.0.1", "hops": [], "hop_count": 0, "path_complete": True, "icmp_suppression_noted": False}

    report_data = report_generator.compile_report_data(
        assessment_id=assessment_id,
        target=target,
        local_info=local_info,
        public_ip_info=public_ip_res,
        isp_asn_info=isp_info,
        geo_info=geo_info,
        packet_stats={"total_packets": cap_status.get("packet_count", 0), "protocol_hierarchy": live_capture.get_protocol_hierarchy()},
        flows=flows,
        devices=devices,
        dns_data=dns_data,
        route_data=route_data,
        wifi_data=wifi_data.dict() if wifi_data else None,
        perf_data=perf_data,
        ai_summary=ai_summary
    )

    report_id = report_data["report_id"]
    _saved_reports[report_id] = report_data

    return {"success": True, "report_id": report_id, "report": report_data}


@router.get("/reports")
async def list_reports(request: Request):
    authenticate_request(request)
    return {
        "success": True,
        "total": len(_saved_reports),
        "reports": [
            {
                "report_id": r["report_id"],
                "assessment_id": r["assessment_id"],
                "target": r["target"],
                "generated_at": r["generated_at"],
                "summary": r["executive_summary"][:120] + "..."
            }
            for r in _saved_reports.values()
        ]
    }


@router.get("/report/{report_id}")
async def get_report_by_id(request: Request, report_id: str):
    authenticate_request(request)
    report = _saved_reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {"success": True, "report": report}


@router.get("/report/{report_id}/download")
async def download_report_file(request: Request, report_id: str, format: str = Query("json")):
    """Downloads report in json, markdown, html, or pdf format."""
    authenticate_request(request)
    report = _saved_reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    fmt = format.lower()
    if fmt == "json":
        return Response(
            content=json.dumps(report, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={report_id}.json"}
        )
    elif fmt in ("md", "markdown"):
        md_text = report_generator.to_markdown(report)
        return Response(
            content=md_text,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename={report_id}.md"}
        )
    elif fmt == "html":
        html_text = report_generator.to_html(report)
        return HTMLResponse(content=html_text)
    elif fmt == "pdf":
        try:
            pdf_bytes = report_generator.to_pdf(report)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={report_id}.pdf"}
            )
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'. Use json, md, html, or pdf.")


# --- WebSocket Streaming ---

@router.websocket("/ws")
async def map_websocket_stream(websocket: WebSocket):
    """Streams live capture telemetry, packet counts, and flow updates."""
    await websocket.accept()
    try:
        while True:
            # Poll status every 1 second while connection is alive
            status = live_capture.get_status()
            await websocket.send_json({
                "type": "CAPTURE_STATUS",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": status
            })
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"WebSocket closed: {e}")
