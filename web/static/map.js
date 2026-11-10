/**
 * SNMK MAP — Enterprise Network Intelligence, Wireshark Forensics & Geolocation Controller
 * Real-time packet inspection, traffic flow correlation, speed benchmarking, Leaflet mapping & AI
 */

let mapLeafletInstance = null;
let mapWsConnection = null;
let mapSelectedPacketNo = null;
let mapCurrentAssessmentId = "MAP-" + Math.random().toString(36).substring(2, 8).toUpperCase();
let mapCurrentTarget = "";
let mapCaptureActive = false;

// Initialize MAP View when navigated to
async function initMapView() {
    console.log("[MAP] Initializing Enterprise Network Intelligence Workspace...");
    const tsEl = document.getElementById("mapLastUpdated");
    if (tsEl) tsEl.textContent = new Date().toLocaleTimeString();

    const assessIdEl = document.getElementById("mapAssessmentId");
    if (assessIdEl) assessIdEl.textContent = mapCurrentAssessmentId;

    // Load Local Posture and Cards
    await loadMapHeaderAndCards();
    // Load Interfaces into selector
    await loadMapInterfaces();
    // Initialize Leaflet Map
    initMapLeaflet();
    // Connect WebSocket stream
    connectMapWebSocket();
    // Load initial devices & packets
    await loadDiscoveredDevices();
    await loadCapturedPackets(0, 100);
    await loadTrafficFlows();
}

// 1. Load Header & 12 Metrics Cards
async function loadMapHeaderAndCards() {
    try {
        const [localRes, publicRes, captureRes] = await Promise.all([
            fetch('/api/network/local-info').then(r => r.json()).catch(() => ({})),
            fetch('/api/network/public-ip').then(r => r.json()).catch(() => ({})),
            fetch('/api/network/capture/status').then(r => r.json()).catch(() => ({}))
        ]);

        const posture = localRes.posture || {};
        const publicIp = publicRes.ip || "Unreachable";

        // Update Header Strip
        const ifaceEl = document.getElementById("mapActiveIfaceBadge");
        if (ifaceEl) ifaceEl.textContent = posture.primary_interface || "Wi-Fi";

        const driverEl = document.getElementById("mapDriverBadge");
        if (driverEl) driverEl.textContent = posture.capture_driver_type || "Socket Monitor";

        // Card 1: Public IP
        const cardPubIp = document.getElementById("cardPublicIp");
        if (cardPubIp) cardPubIp.textContent = publicIp;

        // Card 2: Local IP
        const cardLocIp = document.getElementById("cardLocalIp");
        if (cardLocIp) cardLocIp.textContent = posture.local_ipv4 || "127.0.0.1";

        // Card 10: Total Captured Packets
        const cardPkts = document.getElementById("cardTotalPackets");
        if (cardPkts) cardPkts.textContent = captureRes.packet_count || "0";

        // Card 11: Active Flows
        const cardFlows = document.getElementById("cardActiveFlows");
        if (cardFlows) cardFlows.textContent = captureRes.flow_count || "0";

        // Fetch IP Intelligence for Public IP to populate ISP, ASN, Location
        if (publicIp && publicIp !== "Unreachable") {
            const intelRes = await fetch(`/api/network/ip-intelligence?ip=${encodeURIComponent(publicIp)}`).then(r => r.json()).catch(() => ({}));
            if (intelRes.success) {
                const isp = intelRes.isp || {};
                const geo = intelRes.geolocation || {};

                // Card 3: ISP
                const cardIsp = document.getElementById("cardIsp");
                if (cardIsp) cardIsp.textContent = (isp.isp || "Unknown ISP").substring(0, 24);

                // Card 4: ASN
                const cardAsn = document.getElementById("cardAsn");
                if (cardAsn) cardAsn.textContent = isp.asn || "AS-UNKNOWN";

                // Card 5: Location
                const cardLoc = document.getElementById("cardLocation");
                if (cardLoc) cardLoc.textContent = `${geo.city || "Unknown"}, ${geo.country || "IN"}`;

                // Update Leaflet marker with public IP location
                if (geo.latitude && geo.longitude && mapLeafletInstance) {
                    updateMapVantagePoint(geo.latitude, geo.longitude, publicIp, isp.isp, geo.city);
                }
            }
        }
    } catch (err) {
        console.error("[MAP] Error loading posture:", err);
    }
}

// 2. Load Network Interfaces dropdown
async function loadMapInterfaces() {
    try {
        const res = await fetch('/api/network/interfaces').then(r => r.json());
        const sel = document.getElementById("mapInterfaceSelect");
        if (!sel || !res.interfaces) return;

        sel.innerHTML = "";
        const defaultOpt = document.createElement("option");
        defaultOpt.value = "default";
        defaultOpt.textContent = "Primary Host Interface (Auto)";
        sel.appendChild(defaultOpt);

        res.interfaces.forEach(ifc => {
            const opt = document.createElement("option");
            opt.value = ifc.name;
            const ipStr = ifc.ipv4_addresses.length ? `(${ifc.ipv4_addresses[0]})` : `(${ifc.interface_type})`;
            opt.textContent = `${ifc.name} ${ipStr} - ${ifc.is_up ? 'UP' : 'DOWN'}`;
            sel.appendChild(opt);
        });
    } catch (err) {
        console.error("[MAP] Error loading interfaces:", err);
    }
}

// 3. Connect WebSocket for live streaming
function connectMapWebSocket() {
    if (mapWsConnection && mapWsConnection.readyState === WebSocket.OPEN) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/network/ws`;

    try {
        mapWsConnection = new WebSocket(wsUrl);
        mapWsConnection.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                if (data.type === "CAPTURE_STATUS") {
                    const st = data.status || {};
                    const cardPkts = document.getElementById("cardTotalPackets");
                    if (cardPkts && st.packet_count !== undefined) cardPkts.textContent = st.packet_count;

                    const cardFlows = document.getElementById("cardActiveFlows");
                    if (cardFlows && st.flow_count !== undefined) cardFlows.textContent = st.flow_count;

                    const statusPill = document.getElementById("mapSessionStatusPill");
                    if (statusPill) {
                        if (st.is_running) {
                            statusPill.className = "map-badge-pill badge-active";
                            statusPill.textContent = "CAPTURE ACTIVE (" + st.packet_count + " PKTS)";
                        }
                    }
                }
            } catch (e) {}
        };
        mapWsConnection.onclose = function() {
            setTimeout(connectMapWebSocket, 5000);
        };
    } catch (e) {
        console.debug("[MAP] WebSocket initialization:", e);
    }
}

// 4. Start / Stop Analysis
async function startMapAnalysis() {
    const targetInput = document.getElementById("mapTargetInput");
    const target = targetInput ? targetInput.value.trim() : "";
    const ifaceSel = document.getElementById("mapInterfaceSelect");
    const iface = ifaceSel ? ifaceSel.value : "default";

    const authCheck = document.getElementById("mapAuthCheck");
    if (authCheck && !authCheck.checked) {
        alert("Please confirm authorization to assess this network scope before starting analysis.");
        return;
    }

    mapCurrentTarget = target;
    mapCaptureActive = true;
    mapCurrentAssessmentId = "MAP-" + Math.random().toString(36).substring(2, 8).toUpperCase();
    document.getElementById("mapAssessmentId").textContent = mapCurrentAssessmentId;

    const statusPill = document.getElementById("mapSessionStatusPill");
    if (statusPill) {
        statusPill.className = "map-badge-pill badge-active";
        statusPill.textContent = "ANALYSIS RUNNING";
    }

    // Start Packet Capture
    try {
        await fetch('/api/network/capture/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                interface: iface,
                packet_limit: 200,
                duration_limit: 30
            })
        });
    } catch (e) {}

    // Start Device Discovery
    try {
        fetch('/api/network/discovery/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ authorized_confirmation: true })
        }).then(r => r.json()).then(data => {
            if (data.devices) renderDeviceTable(data.devices, data.comparison);
        });
    } catch (e) {}

    // Investigate target origin if specified
    if (target) {
        investigateOriginTarget(target);
    }

    // Poll captured packets after short delay
    setTimeout(() => {
        loadCapturedPackets(0, 100);
        loadTrafficFlows();
    }, 1500);
}

async function stopMapAnalysis() {
    mapCaptureActive = false;
    try {
        await fetch('/api/network/capture/stop', { method: 'POST' });
    } catch (e) {}

    const statusPill = document.getElementById("mapSessionStatusPill");
    if (statusPill) {
        statusPill.className = "map-badge-pill badge-online";
        statusPill.textContent = "ASSESSMENT COMPLETED";
    }
    loadCapturedPackets(0, 100);
    loadTrafficFlows();
}

function clearMapResults() {
    const targetInput = document.getElementById("mapTargetInput");
    if (targetInput) targetInput.value = "";
    document.getElementById("packetTableBody").innerHTML = `<tr><td colspan="10" style="text-align:center; padding:30px; color:#64748b;">No packet capture in progress. Click Start Analysis or Import PCAP.</td></tr>`;
    document.getElementById("packetTreeContent").innerHTML = `<div style="color:#64748b; padding:15px;">Select a packet from the list above to inspect its protocol layers.</div>`;
    document.getElementById("packetHexBytes").textContent = "0000  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --";
    document.getElementById("packetHexAscii").textContent = "................";
}

function setQuickTarget(val) {
    const input = document.getElementById("mapTargetInput");
    if (input) {
        input.value = val;
        input.focus();
    }
}

// 5. Tab Switching
function switchMapTab(tabName) {
    document.querySelectorAll('.map-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.map-tab-pane').forEach(pane => pane.classList.remove('active'));

    const btn = document.getElementById(`tabBtn_${tabName}`);
    if (btn) btn.classList.add('active');

    const pane = document.getElementById(`tabPane_${tabName}`);
    if (pane) pane.classList.add('active');

    // Trigger specific loaders based on tab
    if (tabName === 'overview' && mapLeafletInstance) {
        setTimeout(() => mapLeafletInstance.invalidateSize(), 150);
    } else if (tabName === 'packets') {
        loadCapturedPackets(0, 100);
    } else if (tabName === 'flows') {
        loadTrafficFlows();
    } else if (tabName === 'devices') {
        loadDiscoveredDevices();
    } else if (tabName === 'wifi') {
        loadWifiIntelligence();
    } else if (tabName === 'geolocation') {
        setTimeout(() => { if (mapLeafletInstance) mapLeafletInstance.invalidateSize(); }, 150);
    }
}

// 6. Packet Analyzer (Wireshark Grid & Inspector)
async function loadCapturedPackets(offset = 0, limit = 100) {
    const filterInput = document.getElementById("packetFilterInput");
    const filterQuery = filterInput ? filterInput.value.trim() : "";

    try {
        const url = `/api/network/capture/packets?offset=${offset}&limit=${limit}&filter=${encodeURIComponent(filterQuery)}`;
        const res = await fetch(url).then(r => r.json());
        const tbody = document.getElementById("packetTableBody");
        if (!tbody) return;

        if (!res.packets || res.packets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; padding:30px; color:#64748b;">No frames match current filter. Start capture or upload PCAP.</td></tr>`;
            return;
        }

        tbody.innerHTML = "";
        res.packets.forEach(p => {
            const tr = document.createElement("tr");
            tr.className = "packet-row";
            if (mapSelectedPacketNo === p.no) tr.classList.add("selected");
            tr.onclick = () => selectPacket(p.no, tr);

            const protoLower = p.protocol.toLowerCase();
            const protoBadge = `<span class="proto-badge proto-${protoLower}">${p.protocol}</span>`;

            tr.innerHTML = `
                <td>${p.no}</td>
                <td>${p.time_str}</td>
                <td>${p.source_ip}</td>
                <td>${p.destination_ip}</td>
                <td>${p.source_port || '-'}</td>
                <td>${p.destination_port || '-'}</td>
                <td>${protoBadge}</td>
                <td>${p.length}</td>
                <td>${p.interface}</td>
                <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis;">${p.info}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("[MAP] Error loading packets:", err);
    }
}

async function selectPacket(pktNo, rowEl) {
    mapSelectedPacketNo = pktNo;
    document.querySelectorAll(".packet-row").forEach(r => r.classList.remove("selected"));
    if (rowEl) rowEl.classList.add("selected");

    try {
        const res = await fetch(`/api/network/capture/packet/${pktNo}`).then(r => r.json());
        if (!res.success || !res.packet) return;

        const pkt = res.packet;
        const treeContainer = document.getElementById("packetTreeContent");
        if (treeContainer) {
            let treeHtml = "";
            // Frame info
            treeHtml += `<div class="tree-node"><div class="tree-header">? Frame ${pkt.frame_info['Frame Number']}: ${pkt.frame_info['Frame Length']} on interface ${pkt.frame_info['Capture Interface']}</div><div class="tree-fields">`;
            for (const [k, v] of Object.entries(pkt.frame_info)) {
                treeHtml += `<div class="tree-field"><span>${k}:</span><strong>${v}</strong></div>`;
            }
            treeHtml += `</div></div>`;

            // Layer details
            for (const [layerName, fields] of Object.entries(pkt.layer_fields || {})) {
                treeHtml += `<div class="tree-node"><div class="tree-header">? ${layerName}</div><div class="tree-fields">`;
                for (const [k, v] of Object.entries(fields)) {
                    treeHtml += `<div class="tree-field"><span>${k}:</span><strong>${v}</strong></div>`;
                }
                treeHtml += `</div></div>`;
            }

            treeContainer.innerHTML = treeHtml;
        }

        // Wireshark Raw Hex Dump
        const hexBytes = document.getElementById("packetHexBytes");
        const hexAscii = document.getElementById("packetHexAscii");
        if (hexBytes && hexAscii) {
            hexBytes.textContent = pkt.hex_dump || "No payload";
            hexAscii.textContent = pkt.ascii_dump || "";
        }
    } catch (err) {
        console.error("[MAP] Error selecting packet:", err);
    }
}

function applyPacketFilter() {
    loadCapturedPackets(0, 100);
}

// 7. PCAP File Upload & Dissection
async function uploadPcapFile(inputEl) {
    if (!inputEl.files || !inputEl.files[0]) return;
    const file = inputEl.files[0];

    const formData = new FormData();
    formData.append("file", file);

    const btn = document.getElementById("btnImportPcap");
    if (btn) btn.textContent = "Analyzing PCAP...";

    try {
        const res = await fetch('/api/network/pcap/upload', {
            method: 'POST',
            body: formData
        }).then(r => r.json());

        if (res.success) {
            alert(`PCAP Analysis Complete: ${res.total_packets} frames parsed across ${res.flows_count} communication flows. SHA256: ${res.sha256.substring(0, 16)}...`);
            loadCapturedPackets(0, 100);
            loadTrafficFlows();
            switchMapTab('packets');
        } else {
            alert(`PCAP Analysis Failed: ${res.error || 'Invalid file format.'}`);
        }
    } catch (err) {
        alert(`Upload error: ${err.message}`);
    } finally {
        if (btn) btn.textContent = "Import PCAP/PCAPNG";
        inputEl.value = "";
    }
}

// 8. Traffic Flows (Conversations)
async function loadTrafficFlows() {
    try {
        const res = await fetch('/api/network/flows').then(r => r.json());
        const tbody = document.getElementById("flowsTableBody");
        if (!tbody) return;

        if (!res.flows || res.flows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:25px; color:#64748b;">No active conversations recorded. Start an assessment or import a PCAP.</td></tr>`;
            return;
        }

        tbody.innerHTML = "";
        res.flows.forEach(f => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><code>${f.source_ip}:${f.source_port}</code></td>
                <td><code>${f.destination_ip}:${f.destination_port}</code></td>
                <td><span class="proto-badge proto-${f.protocol.toLowerCase()}">${f.protocol}</span></td>
                <td>${f.packets_sent} / ${f.packets_received}</td>
                <td>${(f.bytes_sent / 1024).toFixed(1)} KB / ${(f.bytes_received / 1024).toFixed(1)} KB</td>
                <td>${f.first_seen}</td>
                <td>${f.last_seen}</td>
                <td><span class="map-badge-pill badge-online">${f.state}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("[MAP] Error loading flows:", err);
    }
}

// 9. Device Discovery Table
async function loadDiscoveredDevices() {
    try {
        const res = await fetch('/api/network/devices').then(r => r.json());
        if (res.devices) {
            renderDeviceTable(res.devices, null);
            const cardDevs = document.getElementById("cardConnectedDevices");
            if (cardDevs) cardDevs.textContent = `${res.devices.length} Devices`;
        }
    } catch (err) {
        console.error("[MAP] Error loading devices:", err);
    }
}

function renderDeviceTable(devices, comparison) {
    const tbody = document.getElementById("devicesTableBody");
    if (!tbody) return;

    if (!devices || devices.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:25px; color:#64748b;">No local devices discovered. Ensure interface has subnet access.</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    devices.forEach(d => {
        const tr = document.createElement("tr");
        const statusBadge = d.is_gateway
            ? `<span class="map-badge-pill badge-purple">GATEWAY</span>`
            : (d.status === 'NEW' ? `<span class="map-badge-pill badge-active">NEW</span>` : `<span class="map-badge-pill badge-online">ACTIVE</span>`);

        tr.innerHTML = `
            <td><code>${d.ip}</code></td>
            <td><code>${d.mac_address || 'Unresolved'}</code></td>
            <td>${d.vendor || 'Unknown Vendor'}</td>
            <td>${d.hostname || 'None'}</td>
            <td>${d.device_type}</td>
            <td>${d.response_time_ms ? d.response_time_ms + ' ms' : 'Reachability OK'}</td>
            <td>${statusBadge}</td>
        `;
        tbody.appendChild(tr);
    });

    // Update diff alert if comparison present
    const diffEl = document.getElementById("discoveryDiffAlert");
    if (diffEl && comparison) {
        diffEl.style.display = "block";
        diffEl.innerHTML = `<strong>Baseline Comparison:</strong> ${comparison.current_count} active endpoints | ${comparison.new_devices_count} new devices detected | ${comparison.changed_devices_count} MAC changes`;
    }
}

// 10. Origin Investigation
async function investigateOriginTarget(target) {
    try {
        const res = await fetch('/api/network/origin/investigate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: target, authorized_confirmation: true })
        }).then(r => r.json());

        if (res.success && res.origin) {
            const o = res.origin;
            const targetEl = document.getElementById("originTargetDisplay");
            if (targetEl) targetEl.textContent = o.target;

            const classEl = document.getElementById("originClassificationDisplay");
            if (classEl) classEl.textContent = o.origin_classification;

            const ispEl = document.getElementById("originIspDisplay");
            if (ispEl && o.isp_info) ispEl.textContent = `${o.isp_info.isp} (${o.isp_info.asn})`;

            const geoEl = document.getElementById("originGeoDisplay");
            if (geoEl && o.geo_info) geoEl.textContent = `${o.geo_info.city || 'Unknown'}, ${o.geo_info.country || 'N/A'} [${o.geo_info.latitude}, ${o.geo_info.longitude}]`;

            const evList = document.getElementById("originEvidenceList");
            if (evList && o.classification_evidence) {
                evList.innerHTML = o.classification_evidence.map(e => `<li>${e}</li>`).join('');
            }
        }
    } catch (err) {
        console.error("[MAP] Origin investigation error:", err);
    }
}

// 11. DNS Intelligence
async function runDnsLookup() {
    const input = document.getElementById("dnsTargetInput");
    const domain = input ? input.value.trim() : "google.com";

    try {
        const res = await fetch(`/api/network/dns?target=${encodeURIComponent(domain)}`).then(r => r.json());
        const tbody = document.getElementById("dnsRecordsTableBody");
        if (!tbody) return;

        tbody.innerHTML = "";
        if (!res.records || res.records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:#64748b;">No DNS records resolved for ${domain}.</td></tr>`;
            return;
        }

        res.records.forEach(r => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${r.record_type}</strong></td>
                <td><code>${r.value}</code></td>
                <td>${r.ttl}s</td>
                <td>${r.response_time_ms} ms</td>
                <td>${r.resolver}</td>
            `;
            tbody.appendChild(tr);
        });

        const statusEl = document.getElementById("dnsSecStatusDisplay");
        if (statusEl) statusEl.textContent = res.dnssec_status;

        const tunnelEl = document.getElementById("dnsTunnelDisplay");
        if (tunnelEl) {
            tunnelEl.textContent = res.heuristic_evaluation;
            tunnelEl.style.color = res.tunneling_anomaly_detected ? '#ef4444' : '#34d399';
        }
    } catch (err) {
        console.error("[MAP] DNS lookup error:", err);
    }
}

// 12. Routing & Path Tracing
async function runRouteTrace() {
    const input = document.getElementById("routeTargetInput");
    const target = input ? input.value.trim() : "8.8.8.8";

    const tbody = document.getElementById("routeHopsTableBody");
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:#38bdf8;">Executing traceroute diagnostics to ${target}...</td></tr>`;

    try {
        const res = await fetch('/api/network/route/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ target: target, max_hops: 15, timeout: 2.0 })
        }).then(r => r.json());

        if (!tbody) return;
        tbody.innerHTML = "";

        if (!res.hops || res.hops.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:#64748b;">No hops received from target traceroute.</td></tr>`;
            return;
        }

        res.hops.forEach(h => {
            const tr = document.createElement("tr");
            const rttStr = h.avg_rtt_ms !== null ? `${h.avg_rtt_ms} ms` : `* (${h.packet_loss_pct}% loss)`;
            const locStr = h.city ? `${h.city}, ${h.country || ''}` : 'Local / ISP Transit';
            tr.innerHTML = `
                <td><strong>${h.hop}</strong></td>
                <td><code>${h.ip}</code></td>
                <td>${rttStr}</td>
                <td>${h.packet_loss_pct}%</td>
                <td>${h.asn || 'Transit'}</td>
                <td>${h.isp || 'Backbone'}</td>
                <td>${locStr}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("[MAP] Route trace error:", err);
    }
}

// 13. Internet Speed Benchmark
async function runSpeedBenchmark() {
    const btn = document.getElementById("btnRunSpeedTest");
    if (btn) { btn.disabled = true; btn.textContent = "Benchmarking..."; }

    try {
        const res = await fetch('/api/network/speed-test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ include_upload: true, duration_seconds: 5 })
        }).then(r => r.json());

        if (res.success && res.result) {
            const r = res.result;
            const dlEl = document.getElementById("gaugeDownloadVal");
            if (dlEl) dlEl.textContent = r.download_mbps;

            const ulEl = document.getElementById("gaugeUploadVal");
            if (ulEl) ulEl.textContent = r.upload_mbps;

            const pingEl = document.getElementById("gaugePingVal");
            if (pingEl) pingEl.textContent = r.ping_ms;

            const jitterEl = document.getElementById("gaugeJitterVal");
            if (jitterEl) jitterEl.textContent = r.jitter_ms;

            // Also update top KPI cards
            const cardDl = document.getElementById("cardDownloadSpeed");
            if (cardDl) cardDl.textContent = `${r.download_mbps} Mbps`;
            const cardUl = document.getElementById("cardUploadSpeed");
            if (cardUl) cardUl.textContent = `${r.upload_mbps} Mbps`;
            const cardPing = document.getElementById("cardPingLatency");
            if (cardPing) cardPing.textContent = `${r.ping_ms} ms`;
        }
    } catch (err) {
        alert(`Speed benchmark error: ${err.message}`);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = "Start Speed Benchmark"; }
    }
}

// 14. Wi-Fi Intelligence
async function loadWifiIntelligence() {
    try {
        const res = await fetch('/api/network/wifi').then(r => r.json());
        if (res.success && res.wifi) {
            const w = res.wifi;
            const ssidEl = document.getElementById("wifiSsidDisplay");
            if (ssidEl) ssidEl.textContent = w.ssid || "Connected";

            const bssidEl = document.getElementById("wifiBssidDisplay");
            if (bssidEl) bssidEl.textContent = w.bssid || "N/A";

            const sigEl = document.getElementById("wifiSignalDisplay");
            if (sigEl) sigEl.textContent = `${w.signal_pct}% (${w.rssi_dbm || '-'} dBm)`;

            const chanEl = document.getElementById("wifiChannelDisplay");
            if (chanEl) chanEl.textContent = `${w.channel || 'Auto'} (${w.band || '5 GHz'})`;

            const qualEl = document.getElementById("wifiQualityDisplay");
            if (qualEl) qualEl.textContent = w.quality_assessment;

            const authEl = document.getElementById("wifiAuthDisplay");
            if (authEl) authEl.textContent = w.auth_cipher || "WPA2";
        }
    } catch (err) {
        console.error("[MAP] Wi-Fi error:", err);
    }
}

// 15. Leaflet Global Interactive Map
function initMapLeaflet() {
    const container = document.getElementById("mapLeafletContainer");
    if (!container || mapLeafletInstance) return;

    if (typeof L === 'undefined') {
        container.innerHTML = `<div style="padding:40px; text-align:center; color:#64748b;">Interactive World Map loaded. Connect network target to visualize geolocation.</div>`;
        return;
    }

    try {
        mapLeafletInstance = L.map('mapLeafletContainer').setView([20.0, 0.0], 2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(mapLeafletInstance);
    } catch (err) {
        console.error("[MAP] Leaflet initialization error:", err);
    }
}

function updateMapVantagePoint(lat, lon, ip, isp, city) {
    if (!mapLeafletInstance || typeof L === 'undefined') return;
    try {
        mapLeafletInstance.setView([lat, lon], 7);
        const marker = L.circleMarker([lat, lon], {
            radius: 8,
            fillColor: "#38bdf8",
            color: "#0284c7",
            weight: 2,
            opacity: 1,
            fillOpacity: 0.8
        }).addTo(mapLeafletInstance);

        marker.bindPopup(`<b>Monitoring Vantage Point</b><br>IP: ${ip}<br>ISP: ${isp}<br>City: ${city}<br>Coordinates: ${lat}, ${lon}`).openPopup();
    } catch (e) {}
}

// 16. AI Investigation Assistant
async function askMapAi(queryText) {
    const input = document.getElementById("mapAiQueryInput");
    const q = queryText || (input ? input.value.trim() : "");
    if (!q) return;

    const respArea = document.getElementById("mapAiResponseArea");
    if (respArea) respArea.innerHTML = `<div style="color:#38bdf8;">Querying MAP AI Network Intelligence Agent for: <em>"${q}"</em>...</div>`;

    try {
        const res = await fetch('/api/network/ai/query', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ query: q })
        }).then(r => r.json());

        if (res.success && res.result) {
            const out = res.result;
            // Convert markdown headings/bullets to HTML simply
            let formatted = out.response
                .replace(/^### (.*$)/gim, '<h4 style="color:#38bdf8; margin:10px 0 4px 0;">$1</h4>')
                .replace(/^## (.*$)/gim, '<h3 style="color:#818cf8; margin:12px 0 6px 0;">$1</h3>')
                .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
                .replace(/\*(.*?)\*/gim, '<em>$1</em>')
                .replace(/`([^`]+)`/gim, '<code style="background:#0f172a; padding:2px 5px; border-radius:4px; color:#38bdf8;">$1</code>')
                .replace(/^\- (.*$)/gim, '<li style="margin-left:18px;">$1</li>');

            respArea.innerHTML = `
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px; border-bottom:1px solid #334155; padding-bottom:4px;">
                    Model: <strong>${out.model_used}</strong> (${out.provider_used}) | Citations: ${out.evidence_citations ? out.evidence_citations.join(', ') : 'Direct telemetry'}
                </div>
                <div>${formatted}</div>
            `;
        }
    } catch (err) {
        if (respArea) respArea.innerHTML = `<div style="color:#ef4444;">AI Query failed: ${err.message}</div>`;
    }
}

// 17. Reports & Export
async function generateCurrentMapReport() {
    console.log("[MAP] Starting generateCurrentMapReport()...");
    const btn = document.getElementById("btnGenerateReport");
    if (btn) btn.textContent = "Compiling Report...";

    try {
        const res = await fetch('/api/network/report/generate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                assessment_id: mapCurrentAssessmentId,
                target: mapCurrentTarget
            })
        }).then(r => r.json());

        console.log("[MAP] Report response received: success=" + (res ? res.success : false));
        if (res.success && res.report) {
            const r = res.report;
            // Update report preview
            const prevEl = document.getElementById("mapReportPreview");
            if (prevEl) {
                prevEl.textContent = JSON.stringify(r, null, 2);
                console.log("[MAP] Updated #mapReportPreview with length: " + prevEl.textContent.length);
            }

            // Update download links
            const pdfBtn = document.getElementById("btnDlPdf");
            if (pdfBtn) pdfBtn.onclick = () => window.open(`/api/network/report/${r.report_id}/download?format=pdf`, '_blank');
            const htmlBtn = document.getElementById("btnDlHtml");
            if (htmlBtn) htmlBtn.onclick = () => window.open(`/api/network/report/${r.report_id}/download?format=html`, '_blank');
            const mdBtn = document.getElementById("btnDlMd");
            if (mdBtn) mdBtn.onclick = () => window.open(`/api/network/report/${r.report_id}/download?format=md`, '_blank');
            const jsonBtn = document.getElementById("btnDlJson");
            if (jsonBtn) jsonBtn.onclick = () => window.open(`/api/network/report/${r.report_id}/download?format=json`, '_blank');

            alert(`Report Generated Successfully!\nReport ID: ${r.report_id}\nTarget: ${r.target || 'Current Network'}\nFrames: ${r.packet_forensics ? r.packet_forensics.total_packets : 0}`);
        }
    } catch (err) {
        alert(`Report generation error: ${err.message}`);
    } finally {
        if (btn) btn.textContent = "Generate Intelligence Report";
    }
}

// Register global MAP controller
window.initMapView = initMapView;
window.startMapAnalysis = startMapAnalysis;
window.stopMapAnalysis = stopMapAnalysis;
window.clearMapResults = clearMapResults;
window.setQuickTarget = setQuickTarget;
window.switchMapTab = switchMapTab;
window.applyPacketFilter = applyPacketFilter;
window.uploadPcapFile = uploadPcapFile;
window.runDnsLookup = runDnsLookup;
window.runRouteTrace = runRouteTrace;
window.runSpeedBenchmark = runSpeedBenchmark;
window.askMapAi = askMapAi;
window.generateCurrentMapReport = generateCurrentMapReport;
