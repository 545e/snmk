"""
SNMK durable scan persistence layer.

This module is the single place where scan lifecycle data is written.  It was
introduced to fix the original defect where scan results (in particular
subdomain enumeration) were returned to the browser but never stored, and
where MySQL failures were logged as warnings while the API still reported a
successful save.

Design rules enforced here:

* SQLite is always the authoritative local store.  A scan is never considered
  "saved" unless the local write committed.
* MySQL is optional.  It is used only when it is both configured and
  reachable.  A failed MySQL write is *never* reported as success: the record
  is marked PENDING and placed in a durable outbox (in SQLite) for retry.
* Every write is short-lived, idempotent (UPSERT), parameterized and committed
  in its own transaction.  No database transaction is held open while an
  external scanner is running.
* ``flush_outbox`` retries pending MySQL operations safely.  Replaying an
  operation is harmless because every target table has a unique key.

Nothing in this module starts a scanner or interprets scanner output; it only
stores data that a caller has already validated.
"""

from __future__ import annotations

import datetime
import json
import logging
import time
import uuid
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional

from core.database import db

logger = logging.getLogger("snmk.persistence")


class PersistenceState(str, Enum):
    """The truthful persistence outcome returned by every write method."""

    PERSISTED = "PERSISTED"      # local + MySQL (when configured)
    LOCAL_ONLY = "LOCAL_ONLY"    # MySQL not configured; SQLite is authoritative
    PENDING = "PENDING"          # MySQL configured but unreachable; queued for retry
    FAILED = "FAILED"            # local write failed - nothing was stored


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False)


def _loads(value: Any, default: Any = None) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SQLITE_DDL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS scan_audit_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        scan_id TEXT,
        event_type TEXT NOT NULL,
        event_details TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tool_executions (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        tool_id TEXT,
        tool_name TEXT NOT NULL,
        execution_status TEXT NOT NULL,
        arguments_metadata TEXT,
        started_at TEXT,
        completed_at TEXT,
        exit_code INTEGER,
        stdout_reference TEXT,
        stderr_reference TEXT,
        error_message TEXT,
        pid INTEGER,
        created_at TEXT NOT NULL,
        UNIQUE (scan_id, tool_id, started_at)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS subdomains (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        user_id TEXT,
        root_domain TEXT NOT NULL,
        subdomain TEXT NOT NULL,
        ip_addresses TEXT,
        cname_records TEXT,
        dns_status TEXT,
        http_status INTEGER,
        discovery_source TEXT,
        discovery_type TEXT,
        confidence REAL DEFAULT 0.0,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        verification_timestamp TEXT,
        UNIQUE (scan_id, root_domain, subdomain)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerability_findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        user_id TEXT,
        target TEXT,
        finding_title TEXT NOT NULL,
        severity TEXT,
        confidence TEXT,
        description TEXT,
        evidence TEXT,
        remediation TEXT,
        scanner_name TEXT,
        status TEXT DEFAULT 'OPEN',
        created_at TEXT NOT NULL,
        UNIQUE (scan_id, finding_title, scanner_name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_results (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        result_type TEXT NOT NULL,
        result_data TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (scan_id, result_type)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_reports (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        report_type TEXT NOT NULL,
        report_reference TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE (scan_id, report_type, report_reference)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS persistence_outbox (
        id TEXT PRIMARY KEY,
        target_table TEXT NOT NULL,
        operation TEXT NOT NULL,
        payload TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        attempts INTEGER DEFAULT 0,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_persist_outbox_status
        ON persistence_outbox(status, created_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_persist_subdomains_scan
        ON subdomains(scan_id, root_domain)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_persist_subdomains_domain
        ON subdomains(root_domain, subdomain)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_persist_findings_scan
        ON vulnerability_findings(scan_id, severity)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_persist_tools_scan
        ON tool_executions(scan_id, tool_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_persist_audit_scan
        ON scan_audit_logs(scan_id, created_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_persist_reports_scan
        ON scan_reports(scan_id, created_at)
    """,
)

MYSQL_DDL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS scan_audit_logs (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(128) NULL,
        scan_id VARCHAR(64) NULL,
        event_type VARCHAR(128) NOT NULL,
        event_details TEXT NULL,
        created_at VARCHAR(40) NOT NULL,
        KEY idx_audit_scan (scan_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS tool_executions (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL,
        tool_id VARCHAR(128) NULL,
        tool_name VARCHAR(160) NOT NULL,
        execution_status VARCHAR(40) NOT NULL,
        arguments_metadata TEXT NULL,
        started_at VARCHAR(40) NULL,
        completed_at VARCHAR(40) NULL,
        exit_code INT NULL,
        stdout_reference TEXT NULL,
        stderr_reference TEXT NULL,
        error_message TEXT NULL,
        pid INT NULL,
        created_at VARCHAR(40) NOT NULL,
        UNIQUE KEY uq_tool_exec (scan_id, tool_id, started_at),
        KEY idx_tool_scan (scan_id, tool_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS subdomains (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(128) NULL,
        root_domain VARCHAR(255) NOT NULL,
        subdomain VARCHAR(255) NOT NULL,
        ip_addresses TEXT NULL,
        cname_records TEXT NULL,
        dns_status VARCHAR(64) NULL,
        http_status INT NULL,
        discovery_source VARCHAR(128) NULL,
        discovery_type VARCHAR(64) NULL,
        confidence DOUBLE DEFAULT 0,
        first_seen VARCHAR(40) NOT NULL,
        last_seen VARCHAR(40) NOT NULL,
        verification_timestamp VARCHAR(40) NULL,
        UNIQUE KEY uq_subdomain (scan_id, root_domain, subdomain),
        KEY idx_sub_domain (root_domain, subdomain)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerability_findings (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(128) NULL,
        target TEXT NULL,
        finding_title VARCHAR(512) NOT NULL,
        severity VARCHAR(32) NULL,
        confidence VARCHAR(32) NULL,
        description TEXT NULL,
        evidence TEXT NULL,
        remediation TEXT NULL,
        scanner_name VARCHAR(128) NULL,
        status VARCHAR(32) DEFAULT 'OPEN',
        created_at VARCHAR(40) NOT NULL,
        UNIQUE KEY uq_finding (scan_id, finding_title(191), scanner_name),
        KEY idx_finding_scan (scan_id, severity)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_results (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL,
        result_type VARCHAR(128) NOT NULL,
        result_data LONGTEXT NULL,
        created_at VARCHAR(40) NOT NULL,
        UNIQUE KEY uq_result (scan_id, result_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_reports (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(64) NOT NULL,
        report_type VARCHAR(64) NOT NULL,
        report_reference TEXT NOT NULL,
        created_at VARCHAR(40) NOT NULL,
        UNIQUE KEY uq_report (scan_id, report_type, report_reference(191))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS persistence_outbox (
        id VARCHAR(64) PRIMARY KEY,
        target_table VARCHAR(64) NOT NULL,
        operation VARCHAR(32) NOT NULL,
        payload LONGTEXT NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
        attempts INT DEFAULT 0,
        last_error TEXT NULL,
        created_at VARCHAR(40) NOT NULL,
        updated_at VARCHAR(40) NOT NULL,
        KEY idx_outbox_status (status, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
)

# Columns added to the pre-existing ``scans`` table so it can serve as the
# canonical scan record without creating a redundant second scan table.
SCAN_EXTRA_COLUMNS: tuple[tuple[str, str], ...] = (
    ("user_id", "TEXT"),
    ("scan_type", "TEXT"),
    ("configuration", "TEXT"),
    ("total_findings", "INTEGER DEFAULT 0"),
    ("error_message", "TEXT"),
)

# Map the persistence layer's scan fields onto the legacy ``scans`` columns.
_SCAN_FIELD_MAP: Dict[str, str] = {
    "user_id": "user_id",
    "scan_type": "scan_type",
    "configuration": "configuration",
    "total_findings": "total_findings",
    "error_message": "error_message",
    "status": "status",
    "target": "target_url",
    "started_at": "started_at",
    "completed_at": "completed_at",
    "duration_seconds": "duration_seconds",
}


class ScanPersistence:
    """Writes scan lifecycle records to SQLite (always) and MySQL (when live)."""

    def __init__(self, sqlite_db: Any = None, mysql_manager: Any = None):
        self._db = sqlite_db or db
        self._mysql = mysql_manager
        self._lock = __import__("threading").RLock()
        self._schema_ready = False

    # -- MySQL plumbing -----------------------------------------------------
    def _mysql_active(self) -> bool:
        if self._mysql is None:
            try:
                from core.mysql_database import mysql_manager as mgr

                self._mysql = mgr
            except Exception:  # pragma: no cover - optional dependency
                self._mysql = False
        return bool(getattr(self._mysql, "is_configured", lambda: False)())

    def _mysql_conn(self):
        return self._mysql.get_connection()

    def _mysql_write(self, sql: str, params: Iterable[Any]) -> None:
        """Execute one MySQL write with a bounded retry and no open transaction."""
        last_error: Exception | None = None
        for attempt in range(3):
            conn = None
            try:
                conn = self._mysql_conn()
                with conn.cursor() as cursor:
                    cursor.execute(sql, tuple(params))
                conn.commit()
                return
            except Exception as exc:  # noqa: BLE001 - any driver error is retryable
                last_error = exc
                if conn is not None:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                if attempt < 2:
                    time.sleep(0.2 * (attempt + 1))
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
        raise RuntimeError(f"MySQL write failed: {type(last_error).__name__}: {last_error}")

    def _state(self, local_ok: bool, sql: str, params: Iterable[Any]) -> PersistenceState:
        """Combine a completed local write with the (optional) MySQL mirror."""
        if not local_ok:
            return PersistenceState.FAILED
        if not self._mysql_active():
            return PersistenceState.LOCAL_ONLY
        try:
            self._mysql_write(sql, tuple(params))
            return PersistenceState.PERSISTED
        except Exception as exc:  # noqa: BLE001
            self._enqueue(sql, tuple(params), str(exc))
            return PersistenceState.PENDING

    def _enqueue(self, sql: str, params: tuple, error: str) -> None:
        """Durably queue a MySQL operation that must be retried later."""
        entry = {
            "id": uuid.uuid4().hex,
            "sql": sql,
            "params": list(params),
            "error": error,
        }
        try:
            with self._db.get_connection() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO persistence_outbox
                       (id, target_table, operation, payload, status, attempts,
                        last_error, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?)""",
                    (
                        entry["id"], "mysql", "WRITE", _dumps(entry),
                        error[:500], _now(), _now(),
                    ),
                )
        except Exception:  # pragma: no cover - outbox itself must not break the scan
            logger.exception("Failed to write MySQL retry outbox entry")

    # -- Schema -------------------------------------------------------------
    def initialize_schema(self) -> Dict[str, Any]:
        """Create all persistence tables in SQLite and, when live, in MySQL."""
        result: Dict[str, Any] = {"sqlite": "ok", "mysql": "not_configured"}
        with self._lock:
            with self._db.get_connection() as conn:
                for ddl in SQLITE_DDL:
                    conn.execute(ddl)
                columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
                }
                for name, decl in SCAN_EXTRA_COLUMNS:
                    if name not in columns:
                        conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {decl}")
                result["sqlite_tables"] = len(
                    conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                )

            if self._mysql_active():
                try:
                    conn = self._mysql_conn()
                    try:
                        with conn.cursor() as cursor:
                            for ddl in MYSQL_DDL:
                                cursor.execute(ddl)
                        conn.commit()
                        result["mysql"] = "ok"
                    finally:
                        conn.close()
                except Exception as exc:  # noqa: BLE001
                    result["mysql"] = f"failed: {type(exc).__name__}: {exc}"
                    logger.warning("MySQL schema initialization failed: %s", exc)
        self._schema_ready = True
        return result

    def _ensure(self) -> None:
        if not self._schema_ready:
            self.initialize_schema()

    # -- Scan lifecycle -----------------------------------------------------
    def create_scan(
        self,
        scan_id: str,
        scan_type: str,
        target: str,
        configuration: Optional[Dict[str, Any]] = None,
        user_id: str = "operator",
        status: str = "INITIALIZED",
    ) -> PersistenceState:
        self._ensure()
        created = _now()
        config = _dumps(configuration or {})
        sqlite_sql = """
            INSERT OR IGNORE INTO scans
            (id, target_url, status, profile, progress_percent, created_at,
             user_id, scan_type, configuration, total_findings)
            VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, 0)
        """
        sqlite_params = (scan_id, target, status, scan_type, created,
                         user_id, scan_type, config)
        mysql_sql = """
            INSERT INTO scans (id, target_url, status, profile, progress_percent,
                               created_at, user_id, scan_type, configuration, total_findings)
            VALUES (%s, %s, %s, %s, 0, %s, %s, %s, %s, 0)
            ON DUPLICATE KEY UPDATE status=VALUES(status), configuration=VALUES(configuration)
        """
        try:
            with self._db.get_connection() as conn:
                conn.execute(sqlite_sql, sqlite_params)
            local_ok = True
        except Exception:  # pragma: no cover
            logger.exception("Failed to create local scan record %s", scan_id)
            local_ok = False
        state = self._state(local_ok, mysql_sql, (
            scan_id, target, status, scan_type, created,
            user_id, scan_type, config,
        ))
        self.record_audit(user_id, scan_id, "SCAN_CREATED", {
            "scan_type": scan_type, "target": target, "persistence": state.value,
        })
        return state

    def update_scan(self, scan_id: str, **fields: Any) -> PersistenceState:
        """Update allowed scan fields using parameterized SQL."""
        self._ensure()
        updates: Dict[str, Any] = {}
        for key, value in fields.items():
            column = _SCAN_FIELD_MAP.get(key)
            if column is None:
                continue
            if key == "configuration" and not isinstance(value, str):
                value = _dumps(value or {})
            updates[column] = value
        if not updates:
            return PersistenceState.LOCAL_ONLY
        assignments = ", ".join(f"{col} = ?" for col in updates)
        params = tuple(updates.values()) + (scan_id,)
        try:
            with self._db.get_connection() as conn:
                conn.execute(f"UPDATE scans SET {assignments} WHERE id = ?", params)
            local_ok = True
        except Exception:  # pragma: no cover
            logger.exception("Failed to update scan %s", scan_id)
            local_ok = False
        mysql_sql = (
            f"UPDATE scans SET {', '.join(f'{c} = %s' for c in updates)} WHERE id = %s"
        )
        return self._state(local_ok, mysql_sql, params)

    # -- Record writers -----------------------------------------------------
    def record_tool_execution(
        self,
        scan_id: str,
        tool_name: str,
        execution_status: str,
        tool_id: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        started_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        exit_code: Optional[int] = None,
        stdout_reference: Optional[str] = None,
        stderr_reference: Optional[str] = None,
        error_message: Optional[str] = None,
        pid: Optional[int] = None,
    ) -> PersistenceState:
        self._ensure()
        record_id = uuid.uuid4().hex
        started = started_at or _now()
        args = _dumps(arguments or {})
        values = (
            record_id, scan_id, tool_id, tool_name, execution_status, args,
            started, completed_at, exit_code, stdout_reference,
            stderr_reference, (error_message or "")[:1000], pid, _now(),
        )
        columns = ("id", "scan_id", "tool_id", "tool_name", "execution_status",
                   "arguments_metadata", "started_at", "completed_at", "exit_code",
                   "stdout_reference", "stderr_reference", "error_message",
                   "pid", "created_at")
        local_ok = self._upsert_local(
            "tool_executions", columns, values,
            "ON CONFLICT(scan_id, tool_id, started_at) DO UPDATE SET "
            "execution_status=excluded.execution_status, "
            "completed_at=excluded.completed_at, exit_code=excluded.exit_code, "
            "error_message=excluded.error_message",
        )
        mysql_sql = self._mysql_upsert(
            "tool_executions", columns,
            "execution_status=VALUES(execution_status), "
            "completed_at=VALUES(completed_at), exit_code=VALUES(exit_code), "
            "error_message=VALUES(error_message)",
        )
        return self._state(local_ok, mysql_sql, values)

    def record_subdomain(
        self,
        scan_id: str,
        root_domain: str,
        subdomain: str,
        user_id: str = "operator",
        ip_addresses: Optional[List[str]] = None,
        cname_records: Optional[List[str]] = None,
        dns_status: str = "UNKNOWN",
        http_status: Optional[int] = None,
        discovery_source: str = "unknown",
        discovery_type: str = "passive",
        confidence: float = 0.0,
        verification_timestamp: Optional[str] = None,
    ) -> PersistenceState:
        self._ensure()
        subdomain = subdomain.strip().rstrip(".").lower()
        root_domain = root_domain.strip().rstrip(".").lower()
        if not subdomain:
            return PersistenceState.FAILED
        seen = _now()
        record_id = uuid.uuid4().hex
        values = (
            record_id, scan_id, user_id, root_domain, subdomain,
            _dumps(ip_addresses or []), _dumps(cname_records or []),
            dns_status, http_status, discovery_source, discovery_type,
            float(confidence), seen, seen,
            verification_timestamp or seen,
        )
        columns = ("id", "scan_id", "user_id", "root_domain", "subdomain",
                   "ip_addresses", "cname_records", "dns_status", "http_status",
                   "discovery_source", "discovery_type", "confidence",
                   "first_seen", "last_seen", "verification_timestamp")
        # Preserve first_seen across rescans; only the latest observation
        # and last_seen are updated.
        local_ok = self._upsert_local(
            "subdomains", columns, values,
            "ON CONFLICT(scan_id, root_domain, subdomain) DO UPDATE SET "
            "last_seen=excluded.last_seen, ip_addresses=excluded.ip_addresses, "
            "cname_records=excluded.cname_records, dns_status=excluded.dns_status, "
            "http_status=excluded.http_status, confidence=excluded.confidence, "
            "verification_timestamp=excluded.verification_timestamp",
        )
        mysql_sql = self._mysql_upsert(
            "subdomains", columns,
            "last_seen=VALUES(last_seen), ip_addresses=VALUES(ip_addresses), "
            "cname_records=VALUES(cname_records), dns_status=VALUES(dns_status), "
            "http_status=VALUES(http_status), confidence=VALUES(confidence), "
            "verification_timestamp=VALUES(verification_timestamp)",
        )
        return self._state(local_ok, mysql_sql, values)

    def record_finding(
        self,
        scan_id: str,
        finding_title: str,
        severity: str = "INFO",
        user_id: str = "operator",
        target: Optional[str] = None,
        confidence: str = "HIGH",
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        scanner_name: str = "snmk",
        status: str = "OPEN",
    ) -> PersistenceState:
        self._ensure()
        values = (
            uuid.uuid4().hex, scan_id, user_id, target, finding_title,
            severity, confidence, description, evidence, remediation,
            scanner_name, status, _now(),
        )
        columns = ("id", "scan_id", "user_id", "target", "finding_title",
                   "severity", "confidence", "description", "evidence",
                   "remediation", "scanner_name", "status", "created_at")
        local_ok = self._upsert_local(
            "vulnerability_findings", columns, values,
            "ON CONFLICT(scan_id, finding_title, scanner_name) DO UPDATE SET "
            "severity=excluded.severity, evidence=excluded.evidence, "
            "description=excluded.description, remediation=excluded.remediation, "
            "status=excluded.status",
        )
        mysql_sql = self._mysql_upsert(
            "vulnerability_findings", columns,
            "severity=VALUES(severity), evidence=VALUES(evidence), "
            "description=VALUES(description), remediation=VALUES(remediation), "
            "status=VALUES(status)",
        )
        return self._state(local_ok, mysql_sql, values)

    def record_result(self, scan_id: str, result_type: str, data: Any) -> PersistenceState:
        self._ensure()
        values = (uuid.uuid4().hex, scan_id, result_type, _dumps(data), _now())
        columns = ("id", "scan_id", "result_type", "result_data", "created_at")
        local_ok = self._upsert_local(
            "scan_results", columns, values,
            "ON CONFLICT(scan_id, result_type) DO UPDATE SET "
            "result_data=excluded.result_data, created_at=excluded.created_at",
        )
        mysql_sql = self._mysql_upsert(
            "scan_results", columns,
            "result_data=VALUES(result_data), created_at=VALUES(created_at)",
        )
        return self._state(local_ok, mysql_sql, values)

    def add_report(self, scan_id: str, report_type: str, reference: str) -> PersistenceState:
        self._ensure()
        values = (uuid.uuid4().hex, scan_id, report_type, reference, _now())
        columns = ("id", "scan_id", "report_type", "report_reference", "created_at")
        local_ok = self._upsert_local(
            "scan_reports", columns, values,
            "ON CONFLICT(scan_id, report_type, report_reference) DO NOTHING",
        )
        mysql_sql = self._mysql_upsert(
            "scan_reports", columns, "", ignore_duplicates=True
        )
        return self._state(local_ok, mysql_sql, values)

    def record_audit(
        self,
        user_id: Optional[str],
        scan_id: Optional[str],
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> PersistenceState:
        self._ensure()
        values = (uuid.uuid4().hex, user_id, scan_id, event_type,
                  _dumps(details or {}), _now())
        columns = ("id", "user_id", "scan_id", "event_type", "event_details", "created_at")
        local_ok = self._upsert_local("scan_audit_logs", columns, values, "")
        mysql_sql = self._mysql_upsert("scan_audit_logs", columns, "")
        return self._state(local_ok, mysql_sql, values)

    # -- Generic upsert helpers --------------------------------------------
    def _upsert_local(
        self, table: str, columns: tuple[str, ...], values: tuple,
        conflict_clause: str,
    ) -> bool:
        placeholders = ", ".join("?" for _ in columns)
        sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
        if conflict_clause:
            sql += f" {conflict_clause}"
        try:
            with self._db.get_connection() as conn:
                conn.execute(sql, values)
            return True
        except Exception:  # pragma: no cover
            logger.exception("Local persistence failed for %s", table)
            return False

    @staticmethod
    def _mysql_upsert(
        table: str, columns: tuple[str, ...], update_clause: str,
        ignore_duplicates: bool = False,
    ) -> str:
        placeholders = ", ".join("%s" for _ in columns)
        verb = "INSERT IGNORE INTO" if ignore_duplicates else "INSERT INTO"
        sql = f"{verb} {table} ({', '.join(columns)}) VALUES ({placeholders})"
        if update_clause and not ignore_duplicates:
            sql += f" ON DUPLICATE KEY UPDATE {update_clause}"
        return sql

    # -- Reads (always from the authoritative local store) ------------------
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        self._ensure()
        with self._db.get_connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def _rows(self, sql: str, params: tuple) -> List[Dict[str, Any]]:
        self._ensure()
        with self._db.get_connection() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def get_subdomains(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain", (scan_id,)
        )

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM vulnerability_findings WHERE scan_id = ? ORDER BY created_at",
            (scan_id,),
        )

    def get_tool_executions(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM tool_executions WHERE scan_id = ? ORDER BY started_at",
            (scan_id,),
        )

    def get_results(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY created_at", (scan_id,)
        )

    def get_reports(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM scan_reports WHERE scan_id = ? ORDER BY created_at", (scan_id,)
        )

    def get_audit(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._rows(
            "SELECT * FROM scan_audit_logs WHERE scan_id = ? ORDER BY created_at", (scan_id,)
        )

    # -- Recovery -----------------------------------------------------------
    def flush_outbox(self, limit: int = 50) -> Dict[str, int]:
        """Retry pending MySQL writes. Returns counts of succeeded/failed rows."""
        result = {"succeeded": 0, "failed": 0, "pending": 0}
        if not self._mysql_active():
            result["pending"] = -1
            return result
        self._ensure()
        rows = self._rows(
            "SELECT * FROM persistence_outbox WHERE status = 'PENDING' "
            "ORDER BY created_at LIMIT ?", (limit,)
        )
        for row in rows:
            try:
                payload = _loads(row["payload"], {})
                self._mysql_write(payload["sql"], payload.get("params", []))
                with self._db.get_connection() as conn:
                    conn.execute(
                        "UPDATE persistence_outbox SET status='DONE', updated_at=? WHERE id=?",
                        (_now(), row["id"]),
                    )
                result["succeeded"] += 1
            except Exception as exc:  # noqa: BLE001
                with self._db.get_connection() as conn:
                    conn.execute(
                        "UPDATE persistence_outbox SET attempts=attempts+1, last_error=?, "
                        "updated_at=? WHERE id=?",
                        (str(exc)[:500], _now(), row["id"]),
                    )
                result["failed"] += 1
        result["pending"] = len(self._rows(
            "SELECT id FROM persistence_outbox WHERE status = 'PENDING'", ()
        ))
        return result


persistent_store = ScanPersistence()
