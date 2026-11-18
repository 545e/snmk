"""Durable scan persistence schema (MySQL mirror).

Revision ID: 0001_durable_persistence
Revises:
Create Date: 2026-11-18

Creates the canonical persistence tables used by core.persistent_store:

* scans is extended with user_id / scan_type / configuration / totals
* tool_executions, subdomains, vulnerability_findings, scan_results,
  scan_reports, scan_audit_logs hold the actual scan evidence
* persistence_outbox holds writes that could not be mirrored to MySQL while
  the server was unreachable, so no result is ever silently discarded.

This migration only runs against an explicitly configured MySQL backend
(see migrations/env.py). The SQLite deployment is unaffected.
"""

from __future__ import annotations

from alembic import op

revision = "0001_durable_persistence"
down_revision = None
branch_labels = None
depends_on = None


SCAN_COLUMNS = (
    ("user_id", "VARCHAR(128) NULL"),
    ("scan_type", "VARCHAR(64) NULL"),
    ("configuration", "TEXT NULL"),
    ("total_findings", "INT DEFAULT 0"),
    ("error_message", "TEXT NULL"),
)

TABLES = (
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

DROP_ORDER = (
    "persistence_outbox",
    "scan_audit_logs",
    "scan_reports",
    "scan_results",
    "vulnerability_findings",
    "subdomains",
    "tool_executions",
)


def upgrade() -> None:
    # Extend the pre-existing scans table idempotently.
    for name, definition in SCAN_COLUMNS:
        op.execute(
            f"ALTER TABLE scans ADD COLUMN IF NOT EXISTS {name} {definition}"
        )
    for ddl in TABLES:
        op.execute(ddl)


def downgrade() -> None:
    for table in DROP_ORDER:
        op.execute(f"DROP TABLE IF EXISTS {table}")
    for name, _ in reversed(SCAN_COLUMNS):
        op.execute(f"ALTER TABLE scans DROP COLUMN IF EXISTS {name}")
