"""
Tests for Intelligent Tool Dependency Manager & Real-Time Health Center
Verifies:
- Manifest metadata completeness
- Dependency DAG topological sort & cycle detection (3-color DFS)
- Security controls: Source allowlist validation, ZipSlip path traversal protection
- 5-Tier Level 1-5 health verification engine
- SQLite WAL audit persistence
- Full REST API endpoints and dynamic counting
"""

import os
import sys
import uuid
import zipfile
import asyncio
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure SWA root is in path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from core.tool_dependency_manager import (
    tool_dependency_manager,
    DependencyGraph,
    SecureToolInstaller,
    ToolHealthEngine,
    ToolHealthState,
    InstallStatus,
    ToolDependencyManifestItem,
    SecurityError
)
from core.database import db
from web.server import app

client = TestClient(app)


# -----------------------------------------------------------------------------
# 1. Manifest Catalog Tests
# -----------------------------------------------------------------------------

def test_manifest_catalog_completeness():
    manifest = tool_dependency_manager.get_manifest()
    assert len(manifest) >= 15, f"Expected at least 15 registered tools, got {len(manifest)}"
    
    # Required core security tools from prompt
    required_keys = ["nuclei", "semgrep", "bandit", "trivy", "gitleaks", "nmap", "sqlmap", "nikto"]
    valid_adapters = ("github_release_binary", "pip_package", "npm_package", "system_package", "system_native", "builtin")
    for k in required_keys:
        assert k in manifest, f"Missing required security tool: {k}"
        item = manifest[k]
        assert item.name, f"Tool {k} missing name"
        assert item.category, f"Tool {k} missing category"
        assert item.install_adapter in valid_adapters, f"Invalid adapter for {k}: {item.install_adapter}"
        assert isinstance(item.dependencies, list), f"Dependencies must be a list for {k}"
        assert isinstance(item.capabilities, list), f"Capabilities must be a list for {k}"


# -----------------------------------------------------------------------------
# 2. Dependency Graph & Topological Sorting Tests
# -----------------------------------------------------------------------------

def test_dependency_graph_topological_sort():
    graph = DependencyGraph()
    graph.add_node("python")
    graph.add_node("bandit")
    graph.add_dependency("bandit", "python") # bandit depends on python

    order = graph.topological_sort(["python", "bandit"])
    assert order == ["python", "bandit"], f"Expected ['python', 'bandit'], got {order}"


def test_dependency_graph_cycle_detection():
    graph = DependencyGraph()
    graph.add_node("A")
    graph.add_node("B")
    graph.add_dependency("A", "B")
    graph.add_dependency("B", "A") # Cycle A <-> B

    with pytest.raises(ValueError, match="Dependency cycle detected"):
        graph.topological_sort(["A", "B"])


# -----------------------------------------------------------------------------
# 3. Security Controls & Validation Tests
# -----------------------------------------------------------------------------

def test_source_allowlist_enforcement(tmp_path):
    installer = SecureToolInstaller(bin_dir=str(tmp_path))
    
    # Approved official source should not raise
    installer._validate_source_url("https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_windows_amd64.zip")
    installer._validate_source_url("https://pypi.org/project/bandit/")
    
    # Insecure HTTP scheme should be rejected immediately
    with pytest.raises(ValueError, match="Installation requires HTTPS"):
        installer._validate_source_url("http://malicious-mirror.evil.com/tools/nuclei.exe")

    # Untrusted domain with HTTPS should be rejected by allowlist
    with pytest.raises(ValueError, match="not in the approved official source allowlist"):
        installer._validate_source_url("https://malicious-mirror.evil.com/tools/nuclei.exe")


def test_zipslip_path_traversal_protection(tmp_path):
    installer = SecureToolInstaller(bin_dir=str(tmp_path))
    malicious_zip = tmp_path / "evil.zip"
    
    # Create a malicious zip containing a path traversal entry (e.g. ../../escape.txt)
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../escape.txt", "MALICIOUS PAYLOAD")
    
    extract_target = tmp_path / "extracted"
    os.makedirs(extract_target, exist_ok=True)
    
    with pytest.raises(SecurityError, match="ZipSlip path traversal attempt detected"):
        installer._safe_extract_zip(str(malicious_zip), str(extract_target))


# -----------------------------------------------------------------------------
# 4. Tiered Health Verification Tests (Level 1 - 5)
# -----------------------------------------------------------------------------

def test_tool_health_tiered_verification():
    async def _test():
        manifest = tool_dependency_manager.get_manifest()
        health_engine = tool_dependency_manager.health_engine
        
        # SWA Native engine is always available and should be HEALTHY
        swa_item = manifest.get("swa_native")
        assert swa_item is not None
        diag = await health_engine.verify_tool_health(swa_item, requested_level=5)
        assert diag.status == ToolHealthState.HEALTHY
        assert diag.level_passed == 5
        assert len(diag.checks_passed) > 0
    asyncio.run(_test())


def test_health_summary_dynamic_calculation():
    async def _test():
        snapshot, summary = await tool_dependency_manager.get_all_health(force_refresh=True)
        assert summary.total_monitored == 15
        assert summary.total_monitored == (
            summary.healthy + summary.degraded + summary.unavailable +
            summary.misconfigured + summary.disabled + summary.checking + summary.unknown
        )
        assert f"{summary.healthy}/{summary.total_monitored} Tools Healthy" in summary.nav_text
        assert summary.overall_status in ("HEALTHY", "DEGRADED", "ATTENTION_REQUIRED")
    asyncio.run(_test())


# -----------------------------------------------------------------------------
# 5. SQLite Audit Persistence Tests
# -----------------------------------------------------------------------------

def test_database_health_snapshot_persistence():
    unique_id = f"test_ths_{uuid.uuid4().hex[:8]}"
    test_snap = {
        "id": unique_id,
        "tool_id": "nuclei",
        "health_state": "UNAVAILABLE",
        "installed_version": None,
        "required_version": ">=3.0.0",
        "binary_path": None,
        "latency_ms": 2.5,
        "level_reached": 1,
        "checks_passed": ["manifest_valid"],
        "checks_failed": ["binary_present"],
        "remediation_advice": "Install via one-click installer",
        "diagnostics": {"os": "win32"}
    }
    db.save_tool_health_snapshot(test_snap)
    
    history = db.get_tool_health_history("nuclei", limit=10)
    assert len(history) >= 1
    found = [h for h in history if h.get("id") == unique_id]
    assert len(found) == 1
    assert found[0]["health_state"] == "UNAVAILABLE"


def test_database_install_job_lifecycle():
    unique_job_id = f"job_test_bandit_{uuid.uuid4().hex[:8]}"
    job_record = {
        "job_id": unique_job_id,
        "tool_id": "bandit",
        "target_version": "1.7.9",
        "status": InstallStatus.INSTALLING,
        "stage": "pip_download",
        "progress_percent": 45,
        "logs": ["Starting pip installation"],
        "requested_by": "sec_admin"
    }
    db.save_tool_install_job(job_record)
    
    fetched = db.get_tool_install_job(unique_job_id)
    assert fetched is not None
    assert fetched["status"] == "INSTALLING"
    assert fetched["progress_percent"] == 45
    
    # Update job
    db.update_tool_install_job(unique_job_id, {"status": "SUCCESS", "progress_percent": 100})
    updated = db.get_tool_install_job(unique_job_id)
    assert updated["status"] == "SUCCESS"
    assert updated["progress_percent"] == 100


# -----------------------------------------------------------------------------
# 6. REST API Endpoint Integration Tests
# -----------------------------------------------------------------------------

def test_api_tools_health_summary():
    res = client.get("/api/tools/health/summary")
    assert res.status_code == 200
    data = res.json()
    assert "nav_text" in data
    assert "total_monitored" in data
    assert "healthy" in data
    assert "overall_status" in data


def test_api_tools_health_all():
    res = client.get("/api/tools/health")
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "SUCCESS"
    assert "tools" in data
    assert len(data["tools"]) == 15
    assert "summary" in data


def test_api_single_tool_health():
    res = client.get("/api/tools/health/nuclei")
    assert res.status_code == 200
    data = res.json()
    assert data["tool_id"] == "nuclei"
    assert "status" in data

    # 404 for unknown tool
    res_404 = client.get("/api/tools/health/nonexistent_tool_xyz")
    assert res_404.status_code == 404


def test_api_tools_dependencies_graph():
    res = client.get("/api/tools/dependencies")
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "SUCCESS"
    assert "topological_sequence" in data
    assert "graph" in data
    assert len(data["graph"]["nodes"]) >= 15


def test_api_system_status_integration():
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.json()
    components = data.get("components", [])
    tool_dep_comp = next((c for c in components if c["id"] == "security_tool_dependencies"), None)
    assert tool_dep_comp is not None, "security_tool_dependencies not found in /api/system/status"
    assert "Tools Healthy" in tool_dep_comp.get("reason", "")
