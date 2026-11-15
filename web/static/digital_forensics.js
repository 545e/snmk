/**
 * SNMK Enterprise Digital Forensics & Data Recovery Client Module
 * Provides controllers for Storage Media Inspector, PhotoRec Carving Station with 'Left ⬅ Back' navigation,
 * Autopsy Case Management, ExifTool GPS Geolocation (Zero Cloudinary), and Cryptographic Chain-of-Custody Ledger.
 */

let currentBrowsePath = "";
let parentBrowsePath = "";
let activeCarveJobId = null;
let carvePollInterval = null;

function switchForensicsSubtab(tabId, btn) {
    document.querySelectorAll('.dfir-subtab-pane').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.dfir-subtab-btn').forEach(el => {
        el.classList.remove('active');
        el.style.borderBottom = '2px solid transparent';
        el.style.color = 'var(--text-muted)';
    });

    const target = document.getElementById(tabId);
    if (target) target.style.display = 'block';

    if (btn) {
        btn.classList.add('active');
        btn.style.borderBottom = '2px solid #818cf8';
        btn.style.color = '#818cf8';
    }

    if (tabId === 'dfirPaneStorage') loadStorageDevices();
    if (tabId === 'dfirPanePhotorec') initPhotorecStation();
    if (tabId === 'dfirPaneAutopsy') loadAutopsyCases();
    if (tabId === 'dfirPaneCustody') loadCustodyRecords();
}

// =====================================================================
// 1. STORAGE MEDIA & DISK IMAGES
// =====================================================================

async function loadStorageDevices() {
    const listEl = document.getElementById('dfirStorageList');
    if (!listEl) return;
    listEl.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 20px; color: var(--text-muted);"><span class="spin-anim">⚡</span> Enumerating storage devices & forensic disk images...</td></tr>`;

    try {
        const res = await fetch('/api/forensics/storage/devices');
        const data = await res.json();
        const devices = data.devices || [];

        if (devices.length === 0) {
            listEl.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 20px; color: var(--text-muted);">No physical devices detected.</td></tr>`;
            return;
        }

        listEl.innerHTML = devices.map(d => `
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 10px 12px; font-weight: 600; color: #e2e8f0;">
                    <div style="display:flex; align-items:center; gap: 8px;">
                        <span>💾</span>
                        <div>
                            <div>${escapeHtml(d.name)}</div>
                            <div style="font-size: 11px; color: var(--text-muted); font-family: var(--mono);">${escapeHtml(d.path)}</div>
                        </div>
                    </div>
                </td>
                <td style="padding: 10px 12px;"><span class="badge" style="background: rgba(99,102,241,0.15); color: #818cf8; font-size: 11px;">${escapeHtml(d.device_type)}</span></td>
                <td style="padding: 10px 12px; font-weight: 600; color: #38bdf8;">${escapeHtml(d.size_human)}</td>
                <td style="padding: 10px 12px; font-family: var(--mono); font-size: 12px;">${escapeHtml(d.partition_scheme)} / ${escapeHtml(d.filesystem)}</td>
                <td style="padding: 10px 12px;">
                    <span class="badge" style="background: rgba(16,185,129,0.15); color: #10b981; font-size: 11px;">🔒 READ-ONLY ENFORCED</span>
                </td>
                <td style="padding: 10px 12px; font-size: 11.5px; color: var(--text-muted); font-family: var(--mono);">${escapeHtml(d.serial_number)}</td>
                <td style="padding: 10px 12px; text-align: right;">
                    <button class="btn btn-secondary" onclick="hashForensicTarget('${escapeHtml(d.path)}')" style="padding: 4px 8px; font-size: 11px;"># Hash SHA-256</button>
                    <button class="btn btn-primary" onclick="selectDeviceForCarving('${escapeHtml(d.device_id)}', '${escapeHtml(d.name)}')" style="padding: 4px 8px; font-size: 11px; margin-left: 4px;">Carve</button>
                </td>
            </tr>
        `).join('');

        // Also update PhotoRec target selector dropdown
        const sel = document.getElementById('dfirCarveTargetSelect');
        if (sel) {
            sel.innerHTML = devices.map(d => `<option value="${escapeHtml(d.device_id)}">${escapeHtml(d.name)} (${d.size_human}) [${d.filesystem}]</option>`).join('');
        }
    } catch (e) {
        listEl.innerHTML = `<tr><td colspan="7" style="color: #f85149; padding: 15px;">Failed to enumerate storage media: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function hashForensicTarget(path) {
    showToast(`Initiating cryptographic SHA-256/SHA-512 stream on ${path}...`, "info");
    try {
        const res = await fetch(`/api/forensics/storage/hash?file_path=${encodeURIComponent(path)}`, { method: 'POST' });
        const data = await res.json();
        if (data.hashes) {
            alert(`Forensic Integrity Certificate:\n\nTarget: ${path}\nSHA-256: ${data.hashes.sha256}\nSHA-512: ${data.hashes.sha512}\nMD5: ${data.hashes.md5}\nSize: ${data.hashes.size_bytes} bytes\n\nStatus: Bitstream Verified Immutable.`);
        } else {
            showToast(data.detail || "Hash computation complete.", "info");
        }
    } catch (e) {
        showToast(`Hashing error: ${e.message}`, "error");
    }
}

function selectDeviceForCarving(deviceId, name) {
    switchForensicsSubtab('dfirPanePhotorec', document.getElementById('btnSubtabPhotorec'));
    const sel = document.getElementById('dfirCarveTargetSelect');
    if (sel) sel.value = deviceId;
    showToast(`Target media set to ${name}`, "info");
}

// =====================================================================
// 2. PHOTOREC CARVING STATION WITH MANDATORY 'LEFT ⬅ BACK' NAVIGATION
// =====================================================================

async function initPhotorecStation() {
    loadPhotorecSignatures();
    browseCarvingDirectory(".");
}

async function loadPhotorecSignatures() {
    const box = document.getElementById('dfirSignatureCheckboxes');
    if (!box) return;
    try {
        const res = await fetch('/api/forensics/photorec/signatures');
        const data = await res.json();
        const fams = data.families || {};
        box.innerHTML = Object.entries(fams).map(([famName, exts]) => `
            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 6px; padding: 10px;">
                <div style="font-weight: 700; font-size: 12px; color: #818cf8; margin-bottom: 6px;">${escapeHtml(famName)}</div>
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                    ${exts.map(ext => `
                        <label style="display: flex; align-items: center; gap: 4px; font-size: 11.5px; color: #cbd5e1; cursor: pointer;">
                            <input type="checkbox" name="dfirSigFilter" value="${ext}" checked>
                            <span style="font-family: var(--mono);">${ext}</span>
                        </label>
                    `).join('')}
                </div>
            </div>
        `).join('');
    } catch (e) {
        console.debug('Signatures fetch error:', e);
    }
}

async function browseCarvingDirectory(targetPath) {
    const breadcrumbEl = document.getElementById('dfirBrowseBreadcrumb');
    const listEl = document.getElementById('dfirDirItemList');
    const backBtn = document.getElementById('dfirBtnLeftBack');

    try {
        const url = targetPath ? `/api/forensics/photorec/browse?path=${encodeURIComponent(targetPath)}` : '/api/forensics/photorec/browse';
        const res = await fetch(url);
        const data = await res.json();
        const b = data.browse || {};

        currentBrowsePath = b.current_path || "";
        parentBrowsePath = b.parent_path || "";

        if (breadcrumbEl) breadcrumbEl.textContent = currentBrowsePath;
        const destInput = document.getElementById('dfirCarveDestInput');
        if (destInput) destInput.value = currentBrowsePath;

        // Mandatory 'Left ⬅ Back' navigation control
        if (backBtn) {
            if (b.has_parent && parentBrowsePath) {
                backBtn.disabled = false;
                backBtn.style.opacity = '1';
                backBtn.style.cursor = 'pointer';
                backBtn.onclick = () => browseCarvingDirectory(parentBrowsePath);
            } else {
                backBtn.disabled = true;
                backBtn.style.opacity = '0.4';
                backBtn.style.cursor = 'not-allowed';
            }
        }

        if (listEl) {
            const items = b.items || [];
            if (items.length === 0) {
                listEl.innerHTML = `<div style="padding: 12px; color: var(--text-muted); font-size: 12px;">Folder is empty.</div>`;
            } else {
                listEl.innerHTML = items.map(item => `
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; border-bottom: 1px solid rgba(255,255,255,0.03); font-size: 12px;">
                        <div style="display: flex; align-items: center; gap: 8px; cursor: ${item.is_dir ? 'pointer' : 'default'}; color: ${item.is_dir ? '#38bdf8' : '#e2e8f0'};"
                             ${item.is_dir ? `onclick="browseCarvingDirectory('${escapeHtml(item.path.replace(/\\/g, '/'))}')"` : ''}>
                            <span>${item.is_dir ? '📁' : '📄'}</span>
                            <span style="font-weight: ${item.is_dir ? '600' : '400'};">${escapeHtml(item.name)}</span>
                        </div>
                        <div style="font-family: var(--mono); font-size: 11px; color: var(--text-muted);">
                            ${item.is_dir ? 'Directory' : `${(item.size_bytes / 1024).toFixed(1)} KB`}
                        </div>
                    </div>
                `).join('');
            }
        }
    } catch (e) {
        showToast(`Directory browse error: ${e.message}`, "error");
    }
}

async function startPhotorecCarving() {
    const targetSel = document.getElementById('dfirCarveTargetSelect');
    const target = targetSel ? targetSel.value : 'DEV-DISK-001';
    const modeSel = document.getElementById('dfirCarveModeSelect');
    const mode = modeSel ? modeSel.value : 'WHOLE';
    const destInput = document.getElementById('dfirCarveDestInput');
    const dest = destInput ? destInput.value : 'forensics/recovered';

    const sigs = Array.from(document.querySelectorAll('input[name="dfirSigFilter"]:checked')).map(el => el.value);

    try {
        const res = await fetch('/api/forensics/photorec/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_target: target,
                partition_mode: mode,
                file_types: sigs.length > 0 ? sigs : ["jpg", "png", "pdf", "docx", "zip", "sqlite"],
                destination_dir: dest
            })
        });
        const data = await res.json();
        const job = data.job;
        activeCarveJobId = job.job_id;

        document.getElementById('dfirCarveLiveArea').style.display = 'block';
        document.getElementById('dfirCarveStatusBadge').textContent = 'RUNNING';
        document.getElementById('dfirCarveStatusBadge').style.background = '#38bdf8';

        showToast(`PhotoRec carving station initialized: Job ${job.job_id}`, "success");

        if (carvePollInterval) clearInterval(carvePollInterval);
        carvePollInterval = setInterval(pollCarvingTelemetry, 800);
    } catch (e) {
        showToast(`Carving launch error: ${e.message}`, "error");
    }
}

async function pollCarvingTelemetry() {
    if (!activeCarveJobId) return;
    try {
        const res = await fetch(`/api/forensics/photorec/status/${activeCarveJobId}`);
        const data = await res.json();
        const job = data.job;

        const bar = document.getElementById('dfirCarveProgressBar');
        if (bar) bar.style.width = `${job.progress_pct}%`;
        const pctText = document.getElementById('dfirCarveProgressText');
        if (pctText) pctText.textContent = `${job.progress_pct}%`;

        const secText = document.getElementById('dfirCarveSectorsText');
        if (secText) secText.textContent = `${job.sectors_processed.toLocaleString()} / ${job.total_sectors.toLocaleString()} Sectors`;

        const countText = document.getElementById('dfirCarveRecoveredCount');
        if (countText) countText.textContent = `${job.files_recovered_count} Files Carved`;

        const logTerm = document.getElementById('dfirCarveLogTerminal');
        if (logTerm && job.log_messages) {
            logTerm.innerHTML = job.log_messages.map(m => `<div>${escapeHtml(m)}</div>`).join('');
            logTerm.scrollTop = logTerm.scrollHeight;
        }

        if (job.status === 'COMPLETED' || job.status === 'STOPPED') {
            clearInterval(carvePollInterval);
            const badge = document.getElementById('dfirCarveStatusBadge');
            if (badge) {
                badge.textContent = job.status;
                badge.style.background = job.status === 'COMPLETED' ? '#10b981' : '#f85149';
            }
            showToast(`PhotoRec file carving ${job.status.toLowerCase()}! Recovered ${job.files_recovered_count} files.`, "success");
        }
    } catch (e) {
        console.debug('Carving poll error:', e);
    }
}

async function cancelPhotorecCarving() {
    if (!activeCarveJobId) return;
    try {
        await fetch(`/api/forensics/photorec/cancel/${activeCarveJobId}`, { method: 'POST' });
        showToast(`Carving job ${activeCarveJobId} cancelled.`, "info");
    } catch (e) {
        showToast(e.message, "error");
    }
}

// =====================================================================
// 3. AUTOPSY CASE MANAGEMENT & INGEST
// =====================================================================

async function loadAutopsyCases() {
    const listEl = document.getElementById('dfirAutopsyCasesList');
    if (!listEl) return;
    try {
        const res = await fetch('/api/forensics/autopsy/cases');
        const data = await res.json();
        const cases = data.cases || [];

        listEl.innerHTML = cases.map(c => `
            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 12px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom: 10px;">
                    <div>
                        <div style="font-weight: 700; font-size: 15px; color: #e2e8f0; display:flex; align-items:center; gap: 8px;">
                            <span>📁</span> ${escapeHtml(c.case_name)}
                            <span class="badge" style="background: rgba(99,102,241,0.2); color: #818cf8; font-size: 11px;">${escapeHtml(c.case_number)}</span>
                        </div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px;">
                            Examiner: <strong style="color: #cbd5e1;">${escapeHtml(c.examiner_name)}</strong> &bull; Created: ${escapeHtml(new Date(c.created_at).toLocaleString())}
                        </div>
                    </div>
                    <div>
                        <span class="badge" style="background: ${c.ingest_status === 'COMPLETED' ? 'rgba(16,185,129,0.2)' : 'rgba(56,189,248,0.2)'}; color: ${c.ingest_status === 'COMPLETED' ? '#10b981' : '#38bdf8'}; font-size: 11px;">
                            ${escapeHtml(c.ingest_status)} (${c.ingest_progress}%)
                        </span>
                    </div>
                </div>
                <div style="font-size: 12.5px; color: #94a3b8; margin-bottom: 12px;">${escapeHtml(c.description || 'No description provided.')}</div>

                <div style="display:flex; gap: 16px; flex-wrap: wrap; background: rgba(0,0,0,0.2); padding: 10px; border-radius: 6px; margin-bottom: 12px;">
                    <div><span style="color:var(--text-muted); font-size: 11px;">Data Sources:</span> <strong>${c.data_sources.length}</strong></div>
                    <div><span style="color:var(--text-muted); font-size: 11px;">Ingest Modules:</span> <strong>${c.ingest_modules_enabled.length}</strong></div>
                    <div><span style="color:var(--text-muted); font-size: 11px;">Discovered Artifacts:</span> <strong>${c.discovered_artifacts.length}</strong></div>
                </div>

                <div style="display:flex; gap: 8px;">
                    <button class="btn btn-secondary" onclick="triggerCaseIngest('${escapeHtml(c.case_id)}')" style="font-size: 11px; padding: 5px 10px;">⚡ Run Ingest Pipeline</button>
                    <button class="btn btn-secondary" onclick="addDataSourceModal('${escapeHtml(c.case_id)}')" style="font-size: 11px; padding: 5px 10px;">+ Mount Evidence Image</button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        listEl.innerHTML = `<div style="color: #f85149; padding: 15px;">Failed to load cases: ${escapeHtml(e.message)}</div>`;
    }
}

async function triggerCaseIngest(caseId) {
    showToast(`Triggering NSRL hash lookup, keyword indexing, and artifact extraction for case ${caseId}...`, "info");
    try {
        const res = await fetch(`/api/forensics/autopsy/cases/${caseId}/ingest`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ modules: ["mod_hash_lookup", "mod_file_id", "mod_keyword", "mod_exif"] })
        });
        const data = await res.json();
        showToast(data.message || "Ingest triggered.", "success");
        setTimeout(loadAutopsyCases, 1200);
    } catch (e) {
        showToast(e.message, "error");
    }
}

// =====================================================================
// 4. EXIFTOOL METADATA & GPS EXTRACTION (ZERO CLOUDINARY)
// =====================================================================

async function runExifExtraction(fileInput) {
    const reportArea = document.getElementById('dfirExifReportArea');
    if (!reportArea) return;

    let payload = {};
    if (fileInput && fileInput.files && fileInput.files[0]) {
        const file = fileInput.files[0];
        const reader = new FileReader();
        reader.onload = async () => {
            const b64 = reader.result.split(',')[1];
            payload = { file_base64: b64, filename: file.name };
            await executeExifApi(payload);
        };
        reader.readAsDataURL(file);
        return;
    } else {
        payload = {};  // Triggers baseline forensic sample
        await executeExifApi(payload);
    }
}

async function executeExifApi(payload) {
    const reportArea = document.getElementById('dfirExifReportArea');
    reportArea.innerHTML = `<div style="padding: 20px; text-align:center; color: var(--text-muted);"><span class="spin-anim">⚡</span> Dissecting binary EXIF tags & GPS metadata...</div>`;

    try {
        const res = await fetch('/api/forensics/exif/extract', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        const r = data.report;

        reportArea.innerHTML = `
            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 8px; padding: 16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 14px;">
                    <div>
                        <div style="font-weight: 700; font-size: 15px; color: #e2e8f0;">📷 ${escapeHtml(r.filename)}</div>
                        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--mono); margin-top: 2px;">SHA-256: ${escapeHtml(r.sha256)}</div>
                    </div>
                    <span class="badge" style="background: rgba(16,185,129,0.15); color: #10b981; font-size: 11px;">ZERO CLOUDINARY ENFORCED</span>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 16px;">
                    <div style="background: rgba(0,0,0,0.25); padding: 10px; border-radius: 6px;">
                        <span style="font-size: 11px; color: var(--text-muted);">Camera Make & Model:</span>
                        <div style="font-weight: 600; color: #38bdf8;">${escapeHtml(r.camera_make || 'N/A')} ${escapeHtml(r.camera_model || '')}</div>
                    </div>
                    <div style="background: rgba(0,0,0,0.25); padding: 10px; border-radius: 6px;">
                        <span style="font-size: 11px; color: var(--text-muted);">Capture Timestamp:</span>
                        <div style="font-weight: 600; color: #cbd5e1;">${escapeHtml(r.date_time_original || 'N/A')}</div>
                    </div>
                    <div style="background: rgba(0,0,0,0.25); padding: 10px; border-radius: 6px;">
                        <span style="font-size: 11px; color: var(--text-muted);">Optics / Lens:</span>
                        <div style="font-weight: 600; color: #cbd5e1;">${escapeHtml(r.lens_model || 'Standard Focal Length')}</div>
                    </div>
                    <div style="background: rgba(0,0,0,0.25); padding: 10px; border-radius: 6px;">
                        <span style="font-size: 11px; color: var(--text-muted);">Software / Firmware:</span>
                        <div style="font-weight: 600; color: #cbd5e1;">${escapeHtml(r.software || 'N/A')}</div>
                    </div>
                </div>

                ${r.has_gps ? `
                    <div style="background: rgba(99,102,241,0.08); border: 1px solid rgba(99,102,241,0.3); border-radius: 6px; padding: 14px; margin-bottom: 14px;">
                        <div style="font-weight: 700; font-size: 13px; color: #818cf8; margin-bottom: 6px; display:flex; align-items:center; gap: 6px;">
                            <span>📍 Geolocation Lock Extracted:</span>
                            <span style="font-family: var(--mono); font-size: 12px; color: #38bdf8;">${escapeHtml(r.gps_coordinates_formatted)}</span>
                        </div>
                        <div style="display:flex; gap: 10px; margin-top: 8px;">
                            <a href="${escapeHtml(r.map_url_osm)}" target="_blank" class="btn btn-secondary" style="font-size: 11px; padding: 5px 10px;">🗺️ OpenStreetMap</a>
                            <a href="${escapeHtml(r.map_url_google)}" target="_blank" class="btn btn-secondary" style="font-size: 11px; padding: 5px 10px;">🌐 Google Maps</a>
                            <a href="${escapeHtml(r.external_verification_url)}" target="_blank" class="btn btn-secondary" style="font-size: 11px; padding: 5px 10px;">🔍 Jimpl External Workflow</a>
                        </div>
                    </div>
                ` : `
                    <div style="padding: 10px; color: var(--text-muted); font-size: 12px; background: rgba(0,0,0,0.2); border-radius: 6px; margin-bottom: 12px;">
                        No embedded GPS coordinates found in image header.
                    </div>
                `}
            </div>
        `;
    } catch (e) {
        reportArea.innerHTML = `<div style="color: #f85149; padding: 15px;">EXIF Parsing Failed: ${escapeHtml(e.message)}</div>`;
    }
}

// =====================================================================
// 5. CHAIN-OF-CUSTODY IMMUTABLE EVIDENCE LEDGER
// =====================================================================

async function loadCustodyRecords() {
    const listEl = document.getElementById('dfirCustodyTableBody');
    if (!listEl) return;
    try {
        const res = await fetch('/api/forensics/custody/records');
        const data = await res.json();
        const records = data.records || [];

        if (records.length === 0) {
            listEl.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 20px; color: var(--text-muted);">No evidence registered in the chain-of-custody ledger yet.</td></tr>`;
            return;
        }

        listEl.innerHTML = records.map(r => `
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 12px;">
                <td style="padding: 10px 12px; font-family: var(--mono); color: #818cf8; font-weight: 600;">${escapeHtml(r.evidence_id)}</td>
                <td style="padding: 10px 12px; font-weight: 600; color: #e2e8f0;">${escapeHtml(r.item_name)}</td>
                <td style="padding: 10px 12px; color: var(--text-muted);">${escapeHtml(r.source_device)}</td>
                <td style="padding: 10px 12px; color: #cbd5e1;">${escapeHtml(r.examiner_name)}</td>
                <td style="padding: 10px 12px; font-family: var(--mono); font-size: 11px; color: #38bdf8;" title="SHA-256: ${escapeHtml(r.sha256_hash)}">
                    ${escapeHtml(r.sha256_hash.slice(0, 16))}...
                </td>
                <td style="padding: 10px 12px;">
                    <span class="badge" style="background: rgba(16,185,129,0.15); color: #10b981; font-size: 11px;">${escapeHtml(r.verification_status)}</span>
                </td>
                <td style="padding: 10px 12px; text-align: right;">
                    <button class="btn btn-secondary" onclick="verifyCustodyItem('${escapeHtml(r.record_id)}')" style="padding: 4px 8px; font-size: 11px;">🔍 Re-verify Hash</button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        listEl.innerHTML = `<tr><td colspan="7" style="color: #f85149; padding: 15px;">Failed to load evidence records: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function verifyCustodyItem(recordId) {
    showToast(`Auditing cryptographic hash for record ${recordId}...`, "info");
    try {
        const res = await fetch(`/api/forensics/custody/verify/${recordId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ examiner_name: "Audit Specialist" })
        });
        const data = await res.json();
        const v = data.verification;
        if (v && v.verified) {
            showToast(`Evidence ${v.evidence_id} integrity confirmed! Hash matches disk bitstream.`, "success");
            loadCustodyRecords();
        } else {
            showToast(`Warning: Integrity mismatch on ${v.evidence_id}!`, "error");
        }
    } catch (e) {
        showToast(e.message, "error");
    }
}
