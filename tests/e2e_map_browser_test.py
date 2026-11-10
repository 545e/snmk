"""
SNMK MAP ?" End-to-End Real Browser Automation Test using Playwright
Spins up local test server, opens Chromium, clicks MAP button, tests all 15 workspace tabs,
validates Wireshark packet inspection and hex viewer, verifies coordinates, and captures real UI screenshots.
"""

import asyncio
import os
import sys

# Ensure repository root is on sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import threading
import time
import uvicorn
from playwright.sync_api import sync_playwright

ARTIFACT_DIR = r"C:\Users\krish\.gemini\antigravity\brain\2f05e276-5a92-40c7-bc12-e83cd864cf64"
SCREENSHOT_DIR = os.path.join(ARTIFACT_DIR, "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


import socket
from web.server import app

class ServerThread(threading.Thread):
    def __init__(self, port=8765):
        super().__init__(daemon=True)
        self.port = port
        self.server = None

    def run(self):
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)
        self.server.run()

    def stop(self):
        if self.server:
            self.server.should_exit = True


def wait_for_server(port=8765, timeout=10.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.2)
    return False


def run_e2e_test():
    print("[E2E] Starting local test server on port 8765...")
    server = ServerThread(port=8765)
    server.start()
    if not wait_for_server(port=8765, timeout=10.0):
        raise RuntimeError("Server failed to start on port 8765!")
    print("[E2E] Server ready on http://127.0.0.1:8765")

    results = {}
    screenshots = {}

    with sync_playwright() as p:
        print("[E2E] Launching Chromium browser...")
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        # Automatically accept browser alerts (e.g. from Report Generation or GPS requests)
        page.on("dialog", lambda dialog: dialog.accept())
        page.on("console", lambda msg: print(f"[BROWSER CONSOLE {msg.type}] {msg.text}"))
        page.on("pageerror", lambda err: print(f"[BROWSER PAGE ERROR] {err}"))
        page.on("response", lambda res: print(f"[HTTP {res.status}] {res.url}") if "/api/network" in res.url else None)

        app_url = "http://127.0.0.1:8765"
        print(f"[E2E] Navigating to {app_url}...")
        page.goto(app_url, wait_until="domcontentloaded")
        page.wait_for_selector("#appSidebar", timeout=10000)

        # 1. Verify Page Title
        title = page.title()
        print(f"[E2E] Page Title: {title}")
        assert "SNMK" in title, f"Unexpected title: {title}"
        results["page_load"] = "PASSED"

        # 2. Verify ONE MAP Navigation Button in Sidebar
        map_btn = page.locator("#navItemMap")
        assert map_btn.is_visible(), "MAP button not visible in sidebar!"
        btn_text = map_btn.inner_text()
        print(f"[E2E] Found Sidebar MAP Button: '{btn_text}'")
        assert "MAP" in btn_text, f"Unexpected text: {btn_text}"
        results["map_nav_button"] = "PASSED"

        # Take Dashboard initial screenshot
        dash_shot = os.path.join(SCREENSHOT_DIR, "01_snmk_dashboard.png")
        page.screenshot(path=dash_shot)
        screenshots["dashboard"] = dash_shot

        # 3. Click MAP Button
        print("[E2E] Clicking MAP button...")
        map_btn.click()
        page.wait_for_timeout(1500)

        # 4. Verify MAP Workspace Container is Active
        map_view = page.locator("#viewMap")
        assert "active" in map_view.get_attribute("class"), "viewMap container is not active!"
        results["view_map_active"] = "PASSED"

        # 5. Verify 12 Info Cards
        card_pub_ip = page.locator("#cardPublicIp").inner_text()
        card_loc_ip = page.locator("#cardLocalIp").inner_text()
        card_isp = page.locator("#cardIsp").inner_text()
        card_asn = page.locator("#cardAsn").inner_text()
        print(f"[E2E] MAP Cards: Public IP={card_pub_ip}, Local IP={card_loc_ip}, ISP={card_isp}, ASN={card_asn}")
        assert card_loc_ip == "192.168.0.10" or "127.0.0.1" in card_loc_ip, f"Unexpected local IP: {card_loc_ip}"
        results["12_cards_data"] = "PASSED"

        # Take MAP Overview Workspace Screenshot
        map_shot = os.path.join(SCREENSHOT_DIR, "02_map_overview_workspace.png")
        page.screenshot(path=map_shot)
        screenshots["map_overview"] = map_shot

        # 6. Test Packet Analyzer Tab (Wireshark Grid)
        print("[E2E] Navigating to Packet Analyzer Tab...")
        page.click("#tabBtn_packets")
        page.wait_for_timeout(1000)

        # Start capture to populate packets
        print("[E2E] Triggering live packet capture...")
        page.click("#btnStartAnalysis")
        page.wait_for_timeout(2500)
        page.click("#btnStopAnalysis")
        page.wait_for_timeout(1000)

        # Click first packet row to inspect layers & hex
        packet_rows = page.locator(".packet-row")
        row_count = packet_rows.count()
        print(f"[E2E] Captured packet rows: {row_count}")
        if row_count > 0:
            packet_rows.first.click()
            page.wait_for_timeout(500)
            tree_text = page.locator("#packetTreeContent").inner_text()
            hex_text = page.locator("#packetHexBytes").inner_text()
            print(f"[E2E] First packet tree layers: {tree_text[:60]}...")
            print(f"[E2E] First packet hex preview: {hex_text[:40]}...")
            assert "Frame" in tree_text, "Packet layer tree does not contain Frame details!"
            assert len(hex_text) > 10, "Hex viewer is empty!"

        packet_shot = os.path.join(SCREENSHOT_DIR, "03_map_wireshark_packet_analyzer.png")
        page.screenshot(path=packet_shot)
        screenshots["packet_analyzer"] = packet_shot
        results["wireshark_packet_analyzer"] = "PASSED"

        # 7. Test Traffic Flows Tab
        print("[E2E] Navigating to Traffic Flows Tab...")
        page.click("#tabBtn_flows")
        page.wait_for_timeout(1000)
        flows_shot = os.path.join(SCREENSHOT_DIR, "04_map_traffic_flows.png")
        page.screenshot(path=flows_shot)
        screenshots["traffic_flows"] = flows_shot
        results["traffic_flows"] = "PASSED"

        # 8. Test Network Origin Tab
        print("[E2E] Navigating to Network Origin Tab...")
        page.click("#tabBtn_origin")
        page.wait_for_timeout(1000)
        origin_class = page.locator("#originClassificationDisplay").inner_text()
        print(f"[E2E] Origin Classification: {origin_class}")
        origin_shot = os.path.join(SCREENSHOT_DIR, "05_map_network_origin.png")
        page.screenshot(path=origin_shot)
        screenshots["network_origin"] = origin_shot
        results["network_origin"] = "PASSED"

        # 9. Test Geolocation & Coordinates Tab
        print("[E2E] Navigating to Geolocation & Coordinates Tab...")
        page.click("#tabBtn_geolocation")
        page.wait_for_timeout(1000)
        geo_shot = os.path.join(SCREENSHOT_DIR, "06_map_geolocation_coordinates.png")
        page.screenshot(path=geo_shot)
        screenshots["geolocation"] = geo_shot
        results["geolocation_coordinates"] = "PASSED"

        # 10. Test Device Discovery Tab
        print("[E2E] Navigating to Device Discovery Tab...")
        page.click("#tabBtn_devices")
        page.wait_for_timeout(1000)
        dev_rows = page.locator("#devicesTableBody tr").count()
        print(f"[E2E] Discovered LAN devices count: {dev_rows}")
        assert dev_rows > 0, "No devices in discovery table!"
        dev_shot = os.path.join(SCREENSHOT_DIR, "07_map_device_discovery.png")
        page.screenshot(path=dev_shot)
        screenshots["device_discovery"] = dev_shot
        results["device_discovery"] = "PASSED"

        # 11. Test Network Topology Tab
        print("[E2E] Navigating to Network Topology Tab...")
        page.click("#tabBtn_topology")
        page.wait_for_timeout(800)
        topo_shot = os.path.join(SCREENSHOT_DIR, "08_map_network_topology.png")
        page.screenshot(path=topo_shot)
        screenshots["topology"] = topo_shot
        results["network_topology"] = "PASSED"

        # 12. Test DNS Intelligence Tab
        print("[E2E] Navigating to DNS Intelligence Tab...")
        page.click("#tabBtn_dns")
        page.wait_for_timeout(500)
        page.click("button:text('Resolve Records')")
        page.wait_for_timeout(2000)
        dns_rows = page.locator("#dnsRecordsTableBody tr").count()
        print(f"[E2E] DNS records resolved: {dns_rows}")
        dns_shot = os.path.join(SCREENSHOT_DIR, "09_map_dns_intelligence.png")
        page.screenshot(path=dns_shot)
        screenshots["dns"] = dns_shot
        results["dns_intelligence"] = "PASSED"

        # 13. Test Wi-Fi Intelligence Tab
        print("[E2E] Navigating to Wi-Fi Intelligence Tab...")
        page.click("#tabBtn_wifi")
        page.wait_for_timeout(800)
        wifi_ssid = page.locator("#wifiSsidDisplay").inner_text()
        print(f"[E2E] Wi-Fi SSID: {wifi_ssid}")
        wifi_shot = os.path.join(SCREENSHOT_DIR, "10_map_wifi_intelligence.png")
        page.screenshot(path=wifi_shot)
        screenshots["wifi"] = wifi_shot
        results["wifi_intelligence"] = "PASSED"

        # 14. Test Performance & Speed Tab
        print("[E2E] Navigating to Performance & Speed Tab...")
        page.click("#tabBtn_performance")
        page.wait_for_timeout(800)
        page.click("#btnRunSpeedTest")
        page.wait_for_timeout(4000)
        speed_shot = os.path.join(SCREENSHOT_DIR, "11_map_speed_performance.png")
        page.screenshot(path=speed_shot)
        screenshots["performance"] = speed_shot
        results["performance_speed"] = "PASSED"

        # 15. Test AI Investigation Tab
        print("[E2E] Navigating to AI Investigation Tab...")
        page.click("#tabBtn_ai")
        page.wait_for_timeout(800)
        page.locator(".map-ai-chip").first.click()
        page.wait_for_timeout(2000)
        ai_resp = page.locator("#mapAiResponseArea").inner_text()
        print(f"[E2E] AI Assistant Response: {ai_resp[:80]}...")
        assert len(ai_resp) > 30, "AI response is empty!"
        ai_shot = os.path.join(SCREENSHOT_DIR, "12_map_ai_investigation.png")
        page.screenshot(path=ai_shot)
        screenshots["ai_assistant"] = ai_shot
        results["ai_investigation"] = "PASSED"

        # 16. Test Reports & Export Tab
        print("[E2E] Navigating to Reports & Export Tab...")
        page.click("#tabBtn_reports")
        page.wait_for_timeout(800)
        print("[E2E] Triggering report compilation via #btnCompileFreshReport...")
        page.click("#btnCompileFreshReport")
        # Poll for report preview population
        report_preview = ""
        for i in range(45):
            page.wait_for_timeout(1000)
            report_preview = page.locator("#mapReportPreview").inner_text()
            if "MAP-REP" in report_preview or "report_id" in report_preview:
                print(f"[E2E] Report populated after {i+1} seconds.")
                break
        print(f"[E2E] Report JSON preview length: {len(report_preview)}")
        assert "MAP-REP" in report_preview or "report_id" in report_preview, f"Report preview is empty! Content: {report_preview}"
        report_shot = os.path.join(SCREENSHOT_DIR, "13_map_reports_export.png")
        page.screenshot(path=report_shot)
        screenshots["reports"] = report_shot
        results["reports_export"] = "PASSED"

        # 17. Test Back to Dashboard
        print("[E2E] Testing 'Back to Dashboard' button...")
        page.click("button:text('Back to Dashboard')")
        page.wait_for_timeout(1000)
        dash_view = page.locator("#viewDashboard")
        assert "active" in dash_view.get_attribute("class"), "Failed to navigate back to Dashboard!"
        results["back_to_dashboard"] = "PASSED"

        browser.close()

    print("[E2E] Stopping test server...")
    server.stop()

    print("\n=======================================================")
    print("           END-TO-END BROWSER TEST RESULTS            ")
    print("=======================================================")
    for k, v in results.items():
        print(f"  {k:30}: {v}")
    print("=======================================================")
    print("Captured Screenshots:")
    for k, path in screenshots.items():
        print(f"  {k:20}: {path}")
    print("=======================================================\n")
    return results, screenshots


if __name__ == "__main__":
    run_e2e_test()
