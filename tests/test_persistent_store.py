"""
Regression tests for durable, honest scan persistence.

These tests exercise the real SQLite code path and a controllable fake MySQL
manager.  They never assume a live MySQL server exists, which is why the
``PENDING``/outbox behaviour is tested explicitly.
"""

from __future__ import annotations

import contextlib
import sqlite3
import tempfile
from pathlib import Path

import pytest

from core.persistent_store import (
    PersistenceState,
    ScanPersistence,
    persistent_store,
)


class _TempDB:
    """A throwaway SQLite database with the same connection contract as core.db."""

    def __init__(self, path: str):
        self.path = path

    @contextlib.contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()


class _FakeCursor:
    def __init__(self, writes):
        self._writes = writes

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=()):
        if "FROM persistence_outbox" in sql:
            return self
        self._writes.append((sql, tuple(params)))
        if "INSERT INTO scans" in sql:
            raise RuntimeError("simulated duplicate")
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _FakeConn:
    def __init__(self, writes, fail=False):
        self._writes = writes
        self._fail = fail

    def cursor(self):
        if self._fail:
            raise RuntimeError("simulated MySQL outage")
        return _FakeCursor(self._writes)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class _FakeMySQL:
    def __init__(self, fail=False):
        self.fail = fail
        self.writes = []

    def is_configured(self):
        return True

    def get_connection(self):
        return _FakeConn(self.writes, fail=self.fail)


@pytest.fixture()
def store(tmp_path: Path):
    path = str(tmp_path / "persistence_test.db")
    temp_db = _TempDB(path)
    with temp_db.get_connection() as conn:
        conn.execute(
            """CREATE TABLE scans (
                   id TEXT PRIMARY KEY, target_url TEXT NOT NULL, status TEXT NOT NULL,
                   profile TEXT NOT NULL, progress_percent INTEGER DEFAULT 0,
                   created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT,
                   duration_seconds REAL, findings_count INTEGER DEFAULT 0
               )"""
        )
    return ScanPersistence(sqlite_db=temp_db, mysql_manager=None)


def test_schema_initialization_creates_all_required_tables(store):
    result = store.initialize_schema()
    assert result["sqlite"] == "ok"
    assert result["sqlite_tables"] >= 7
    with store._db.get_connection() as conn:
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert {
        "subdomains", "tool_executions", "vulnerability_findings",
        "scan_results", "scan_reports", "scan_audit_logs", "persistence_outbox",
    }.issubset(tables)


def test_scan_create_update_and_retrieve(store):
    assert store.create_scan("scan-1", "subdomain", "example.com", {"passive": True}) == (
        PersistenceState.LOCAL_ONLY
    )
    row = store.get_scan("scan-1")
    assert row is not None
    assert row["target_url"] == "example.com"
    assert row["status"] == "INITIALIZED"
    assert row["user_id"] == "operator"

    store.update_scan("scan-1", status="COMPLETED", total_findings=3)
    row = store.get_scan("scan-1")
    assert row["status"] == "COMPLETED"
    assert row["total_findings"] == 3


def test_subdomain_dedup_preserves_first_seen_and_sources(store):
    store.create_scan("scan-2", "subdomain", "example.com")
    store.record_subdomain(
        "scan-2", "example.com", "API.Example.Com.",
        ip_addresses=["203.0.113.10"], discovery_source="crt.sh", confidence=0.8,
    )
    store.record_subdomain(
        "scan-2", "example.com", "api.example.com",
        ip_addresses=["203.0.113.11"], discovery_source="certspotter", confidence=0.95,
    )
    rows = store.get_subdomains("scan-2")
    assert len(rows) == 1
    assert rows[0]["subdomain"] == "api.example.com"
    assert rows[0]["first_seen"] <= rows[0]["last_seen"]
    assert "203.0.113.11" in rows[0]["ip_addresses"]


def test_all_record_types_are_retrievable(store):
    store.create_scan("scan-3", "universal", "http://example.com")
    store.record_tool_execution(
        "scan-3", "nuclei", "COMPLETED", tool_id="nuclei", exit_code=0,
        arguments={"target": "example.com"},
    )
    store.record_finding(
        "scan-3", "Missing CSP header", "MEDIUM", scanner_name="header_check",
        evidence="content-security-policy absent",
    )
    store.record_result("scan-3", "summary", {"scanned": 1})
    store.add_report("scan-3", "json", "/api/scans/scan-3/results")
    store.record_audit("operator", "scan-3", "SCAN_COMPLETED", {"ok": True})

    assert len(store.get_tool_executions("scan-3")) == 1
    assert len(store.get_findings("scan-3")) == 1
    assert len(store.get_results("scan-3")) == 1
    assert len(store.get_reports("scan-3")) == 1
    assert len(store.get_audit("scan-3")) >= 1
    assert store.get_findings("scan-3")[0]["severity"] == "MEDIUM"


def test_mysql_unavailable_is_pending_not_success(store):
    failing = _FakeMySQL(fail=True)
    store._mysql = failing
    store.initialize_schema()
    state = store.record_finding("scan-4", "Test finding", "LOW", scanner_name="unit")
    assert state == PersistenceState.PENDING
    with store._db.get_connection() as conn:
        rows = conn.execute(
            "SELECT status, attempts FROM persistence_outbox"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "PENDING"


def test_outbox_flush_retries_and_clears_when_mysql_recovers(store):
    failing = _FakeMySQL(fail=True)
    store._mysql = failing
    store.initialize_schema()
    store.record_subdomain("scan-5", "example.com", "www.example.com",
                           discovery_source="crt.sh")

    recovered = _FakeMySQL(fail=False)
    store._mysql = recovered
    outcome = store.flush_outbox()
    assert outcome["succeeded"] >= 1
    assert outcome["pending"] == 0
    assert recovered.writes


def test_mysql_reachable_reports_persisted(store):
    working = _FakeMySQL(fail=False)
    store._mysql = working
    store.initialize_schema()
    state = store.record_result("scan-6", "summary", {"ok": True})
    assert state == PersistenceState.PERSISTED
    assert working.writes


def test_results_survive_new_instance_same_database(store):
    """A fresh ScanPersistence instance (backend restart) reads prior records."""
    store.create_scan("restart-1", "subdomain", "example.com")
    store.record_subdomain("restart-1", "example.com", "www.example.com",
                           discovery_source="crt.sh")
    store.record_result("restart-1", "summary", {"discovered": 1})

    restarted = ScanPersistence(sqlite_db=store._db, mysql_manager=None)
    assert restarted.get_scan("restart-1")["target_url"] == "example.com"
    assert len(restarted.get_subdomains("restart-1")) == 1
    assert restarted.get_results("restart-1")[0]["result_data"] == '{"discovered": 1}'


def test_user_isolation_on_subdomain_queries(store):
    store.create_scan("iso-1", "subdomain", "example.com", user_id="alice")
    store.record_subdomain("iso-1", "example.com", "a.example.com",
                           user_id="alice", discovery_source="crt.sh")
    assert len(store.get_subdomains("iso-1")) == 1
    assert store.get_subdomains("iso-1")[0]["user_id"] == "alice"


def test_global_store_is_singleton():
    from core.persistent_store import persistent_store as other
    assert persistent_store is other


def test_api_never_invents_loopback_subdomains():
    """The subdomain API must return zero fabricated assets for an IP literal."""
    from fastapi.testclient import TestClient
    from web.server import app

    response = TestClient(app).post("/api/tools/subdomains", json={"domain": "127.0.0.1"})
    assert response.status_code == 200
    data = response.json()
    assert data["subdomains"] == []
    assert data["count"] == 0
    assert data["discovery_mode"] == "not_applicable"
    assert "requires a registrable domain" in data["note"]
    assert data["scan_id"]
    # The no-op was still durably recorded.
    assert store_rows(data["scan_id"])


def store_rows(scan_id: str):
    return len(persistent_store.get_results(scan_id))


def test_database_status_table_count_is_measured():
    """The /api/database/status table count must equal the live schema."""
    from fastapi.testclient import TestClient
    from core.database import db
    from web.server import app

    with db.get_connection() as conn:
        expected = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        ).fetchone()[0]
    data = TestClient(app).get("/api/database/status").json()
    assert data["sqlite"]["tables_count"] == expected
