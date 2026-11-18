"""
Unit and Integration Tests for SNMK MySQL Database Architecture and Alert Management Subsystems.
"""

from core.alert_manager import (
    AlertCategory,
    AlertRecord,
    AlertSeverity,
    AlertStatus,
    alert_manager,
)
from core.mysql_database import MySQLConfig, MySQLDatabaseManager, mysql_manager


def test_mysql_config_and_telemetry():
    cfg = MySQLConfig()
    d = cfg.to_dict(mask_password=True)
    assert d["port"] == 3306
    assert d["database"] == "snmk"
    assert "password" not in d or d.get("password") != cfg.password
    assert d["driver"] in ("pymysql", "none")

    mgr = MySQLDatabaseManager(cfg)
    health = mgr.get_health_status(force_refresh=True)
    assert health["status"] in ("HEALTHY", "STANDBY_OFFLINE", "DEGRADED")
    assert "metrics" in health
    assert "driver" in health
    assert health["driver"] in ("pymysql", "missing")


def test_alert_manager_lifecycle():
    # 1. Create alert
    alert = alert_manager.create_alert(
        severity=AlertSeverity.HIGH,
        category=AlertCategory.SECURITY,
        title="Unauthenticated S3 Bucket Access Attempt",
        description="Public probe detected targeting cloud asset",
        affected_asset="s3://enterprise-data-store",
        correlation_id="corr_test_001",
        remediation="Restrict ACL permissions and apply IAM bucket policy",
    )
    assert isinstance(alert, AlertRecord)
    assert alert.severity == AlertSeverity.HIGH
    assert alert.status == AlertStatus.ACTIVE
    assert alert.fingerprint != ""

    # 2. Test deduplication within window
    dup_alert = alert_manager.create_alert(
        severity=AlertSeverity.HIGH,
        category=AlertCategory.SECURITY,
        title="Unauthenticated S3 Bucket Access Attempt",
        description="Public probe detected targeting cloud asset",
        affected_asset="s3://enterprise-data-store",
    )
    assert dup_alert.id == alert.id

    # 3. Filter alerts
    alerts_list = alert_manager.get_alerts(severity="HIGH", limit=10)
    assert any(a["id"] == alert.id for a in alerts_list)

    # 4. Update status
    updated = alert_manager.update_status(
        alert_id=alert.id,
        new_status=AlertStatus.RESOLVED,
        owner="lead_sec_auditor",
        notes="Applied IAM bucket policy restricting public access",
    )
    assert updated is True

    resolved_alerts = alert_manager.get_alerts(status="RESOLVED")
    assert any(a["id"] == alert.id and a["assigned_owner"] == "lead_sec_auditor" for a in resolved_alerts)

    # 5. Summary metrics
    summary = alert_manager.get_summary()
    assert summary["total_alerts"] >= 1
    assert "by_severity" in summary
    assert "by_category" in summary
    assert "by_status" in summary


def test_api_database_and_alerts_endpoints():
    from fastapi.testclient import TestClient
    from web.server import app

    client = TestClient(app)

    # 1. Database status
    res_db = client.get("/api/database/status")
    assert res_db.status_code == 200
    data_db = res_db.json()
    assert "sqlite" in data_db
    assert "mysql" in data_db
    # The table count must be measured from the live schema, never hardcoded.
    from core.database import db as _db
    with _db.get_connection() as _c:
        _expected = _c.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0]
    assert data_db["sqlite"]["tables_count"] == _expected > 0

    # 2. MySQL health endpoint
    res_my = client.get("/api/database/mysql/health")
    assert res_my.status_code == 200
    data_my = res_my.json()
    assert "driver" in data_my
    assert data_my["driver"] in ("pymysql", "missing")

    # 3. Alerts endpoints
    res_summary = client.get("/api/alerts/summary")
    assert res_summary.status_code == 200
    data_summary = res_summary.json()
    assert "total_alerts" in data_summary

    # Create alert via API
    res_create = client.post("/api/alerts", json={
        "severity": "CRITICAL",
        "category": "SECURITY",
        "title": "SQL Injection Detected on /api/v1/search",
        "description": "Boolean-based blind injection verified via SQLmap prober",
        "affected_asset": "http://127.0.0.1:8000/api/v1/search",
        "remediation": "Apply parameterized prepared statements"
    })
    assert res_create.status_code == 200
    created_alert = res_create.json()
    assert created_alert["severity"] == "CRITICAL"
    alert_id = created_alert["id"]

    # List alerts
    res_list = client.get("/api/alerts?severity=CRITICAL")
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert any(a["id"] == alert_id for a in data_list["alerts"])

    # Update alert status
    res_update = client.patch(f"/api/alerts/{alert_id}/status", json={
        "status": "ACKNOWLEDGED",
        "owner": "sec_lead",
        "notes": "Triage in progress"
    })
    assert res_update.status_code == 200
    assert res_update.json()["success"] is True
