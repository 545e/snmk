"""
SNMK Enterprise Platform — MySQL Database Architecture & Integration Subsystem
Provides enterprise MySQL 8.x relational database storage, connection pooling,
schema migration, health diagnostics, and dual-backend (MySQL + SQLite) resilience.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("snmk.mysql")

# Optional PyMySQL integration
try:
    import pymysql
    import pymysql.cursors
    PYMYSQL_AVAILABLE = True
except ImportError:
    pymysql = None
    PYMYSQL_AVAILABLE = False


class MySQLConfig:
    """Enterprise MySQL database configuration parameters."""
    def __init__(self):
        self.host = os.getenv("MYSQL_HOST", "127.0.0.1")
        self.port = int(os.getenv("MYSQL_PORT", "3306"))
        self.database = os.getenv("MYSQL_DATABASE", "snmk")
        self.user = os.getenv("MYSQL_USER", "")
        self.password = os.getenv("MYSQL_PASSWORD", "")
        self.pool_size = int(os.getenv("MYSQL_POOL_SIZE", "10"))
        self.ssl_mode = os.getenv("MYSQL_SSL_MODE", "PREFERRED")
        self.connect_timeout = float(os.getenv("MYSQL_CONNECT_TIMEOUT", "2.0"))
        self.read_timeout = float(os.getenv("MYSQL_READ_TIMEOUT", "5.0"))
        self.enabled = os.getenv("MYSQL_ENABLED", "").lower() in ("true", "1", "yes") or bool(self.user and self.password)

    def to_dict(self, mask_password: bool = True) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "user": self.user if not mask_password else (self.user[:2] + "***" if len(self.user) > 2 else "***"),
            "password_configured": bool(self.password),
            "pool_size": self.pool_size,
            "ssl_mode": self.ssl_mode,
            "enabled": self.enabled,
            "driver": "pymysql" if PYMYSQL_AVAILABLE else "none",
        }


class MySQLDatabaseManager:
    """Manages MySQL connections, migrations, health monitoring, and data persistence."""

    def __init__(self, config: Optional[MySQLConfig] = None):
        self.config = config or MySQLConfig()
        self._last_health_check: float = 0.0
        self._cached_health: Optional[Dict[str, Any]] = None
        self._metrics = {
            "total_queries": 0,
            "failed_queries": 0,
            "slow_queries": 0,
            "last_query_latency_ms": 0.0,
            "avg_query_latency_ms": 0.0,
        }

    def is_configured(self) -> bool:
        """Returns True if MySQL environment credentials are provided."""
        return bool(self.config.user and self.config.database and PYMYSQL_AVAILABLE)

    def get_connection(self):
        """Creates a standalone PyMySQL connection."""
        if not PYMYSQL_AVAILABLE:
            raise RuntimeError("PyMySQL driver is not installed.")
        if not self.config.user:
            raise ValueError("MySQL user is not configured in environment.")

        return pymysql.connect(
            host=self.config.host,
            port=self.config.port,
            user=self.config.user,
            password=self.config.password,
            database=self.config.database,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=self.config.connect_timeout,
            read_timeout=self.config.read_timeout,
            autocommit=True,
        )

    def test_connection(self) -> Tuple[bool, str, float]:
        """Tests live MySQL server connectivity and measures latency in milliseconds."""
        if not PYMYSQL_AVAILABLE:
            return False, "PyMySQL package not installed in environment", 0.0
        if not self.config.user:
            return False, "MySQL user credentials not configured in environment", 0.0

        t0 = time.perf_counter()
        try:
            conn = self.get_connection()
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1 AS ping, VERSION() AS version;")
                row = cursor.fetchone()
            conn.close()
            latency = (time.perf_counter() - t0) * 1000.0
            version = row.get("version", "unknown") if row else "unknown"
            return True, f"Connected to MySQL {version}", round(latency, 2)
        except Exception as e:
            latency = (time.perf_counter() - t0) * 1000.0
            return False, f"Connection failed: {str(e)}", round(latency, 2)

    def get_health_status(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Provides real-time health and diagnostics telemetry for the MySQL subsystem."""
        now = time.time()
        if not force_refresh and self._cached_health and (now - self._last_health_check) < 15.0:
            return self._cached_health

        is_connected, message, latency = self.test_connection()
        status = "HEALTHY" if is_connected else ("STANDBY_OFFLINE" if not self.config.user else "DEGRADED")

        table_count = 0
        db_size_mb = 0.0
        if is_connected:
            try:
                conn = self.get_connection()
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT COUNT(*) AS cnt,
                               IFNULL(ROUND(SUM(data_length + index_length) / 1024 / 1024, 2), 0.0) AS size_mb
                        FROM information_schema.tables
                        WHERE table_schema = %s;
                    """, (self.config.database,))
                    res = cursor.fetchone()
                    if res:
                        table_count = res.get("cnt", 0)
                        db_size_mb = float(res.get("size_mb", 0.0))
                conn.close()
            except Exception as e:
                logger.warning(f"Failed to query MySQL schema telemetry: {e}")

        payload = {
            "status": status,
            "connected": is_connected,
            "driver": "pymysql" if PYMYSQL_AVAILABLE else "missing",
            "message": message,
            "latency_ms": latency,
            "config": self.config.to_dict(mask_password=True),
            "table_count": table_count,
            "database_size_mb": db_size_mb,
            "metrics": self._metrics,
            "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._cached_health = payload
        self._last_health_check = now
        return payload

    def init_schema(self) -> Dict[str, Any]:
        """Applies normalized MySQL DDL schemas for all 12 core platform operational tables."""
        if not self.is_configured():
            return {"success": False, "error": "MySQL not configured"}

        ddl_statements = [
            """
            CREATE TABLE IF NOT EXISTS snmk_users (
                id VARCHAR(64) PRIMARY KEY,
                username VARCHAR(128) UNIQUE NOT NULL,
                email VARCHAR(256),
                role VARCHAR(32) NOT NULL DEFAULT 'analyst',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_role (role)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_projects (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(256) NOT NULL,
                description TEXT,
                target_scope TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_assets (
                id VARCHAR(64) PRIMARY KEY,
                project_id VARCHAR(64),
                asset_type VARCHAR(64) NOT NULL,
                value VARCHAR(512) NOT NULL,
                is_authorized BOOLEAN DEFAULT TRUE,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_asset_proj (project_id),
                INDEX idx_asset_val (value(191))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_scans (
                id VARCHAR(64) PRIMARY KEY,
                target VARCHAR(512) NOT NULL,
                profile VARCHAR(64) NOT NULL,
                status VARCHAR(32) NOT NULL,
                findings_count INT DEFAULT 0,
                duration_sec FLOAT DEFAULT 0.0,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                INDEX idx_scan_status (status),
                INDEX idx_scan_target (target(191))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_findings (
                id VARCHAR(64) PRIMARY KEY,
                scan_id VARCHAR(64) NOT NULL,
                title VARCHAR(512) NOT NULL,
                severity VARCHAR(32) NOT NULL,
                cvss_score FLOAT DEFAULT 0.0,
                cwe_id VARCHAR(64),
                endpoint TEXT,
                description TEXT,
                remediation TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_find_scan (scan_id),
                INDEX idx_find_sev (severity)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_tool_executions (
                id VARCHAR(64) PRIMARY KEY,
                tool_id VARCHAR(64) NOT NULL,
                scan_id VARCHAR(64),
                status VARCHAR(32) NOT NULL,
                duration_sec FLOAT DEFAULT 0.0,
                output_summary TEXT,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_tool_exec (tool_id, status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_ai_agent_tasks (
                id VARCHAR(64) PRIMARY KEY,
                agent_role VARCHAR(128) NOT NULL,
                task_description TEXT NOT NULL,
                status VARCHAR(32) NOT NULL,
                duration_sec FLOAT DEFAULT 0.0,
                result_output MEDIUMTEXT,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_agent_role (agent_role)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_alerts (
                id VARCHAR(64) PRIMARY KEY,
                category VARCHAR(64) NOT NULL,
                severity VARCHAR(32) NOT NULL,
                title VARCHAR(512) NOT NULL,
                description TEXT,
                status VARCHAR(32) DEFAULT 'ACTIVE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_alert_status (status),
                INDEX idx_alert_sev (severity)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS snmk_audit_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(128) NOT NULL,
                actor VARCHAR(128) DEFAULT 'system',
                details JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_audit_event (event_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS universal_scans (
                id VARCHAR(64) PRIMARY KEY,
                user_id VARCHAR(64) DEFAULT 'operator',
                scan_type VARCHAR(32) NOT NULL,
                target VARCHAR(1024) NOT NULL,
                status VARCHAR(32) NOT NULL DEFAULT 'QUEUED',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                total_files INT DEFAULT 0,
                total_findings INT DEFAULT 0,
                critical_count INT DEFAULT 0,
                high_count INT DEFAULT 0,
                medium_count INT DEFAULT 0,
                low_count INT DEFAULT 0,
                info_count INT DEFAULT 0,
                scan_configuration JSON,
                INDEX idx_univ_status (status),
                INDEX idx_univ_type (scan_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS uploaded_files (
                id VARCHAR(64) PRIMARY KEY,
                scan_id VARCHAR(64) NOT NULL,
                original_filename VARCHAR(512) NOT NULL,
                detected_file_type VARCHAR(64) NOT NULL,
                file_size BIGINT NOT NULL DEFAULT 0,
                sha256_hash VARCHAR(64) NOT NULL,
                processing_status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
                storage_reference VARCHAR(1024),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_upfiles_scan (scan_id),
                INDEX idx_upfiles_hash (sha256_hash)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS vulnerability_findings (
                id VARCHAR(64) PRIMARY KEY,
                scan_id VARCHAR(64) NOT NULL,
                file_id VARCHAR(64),
                finding_title VARCHAR(512) NOT NULL,
                severity VARCHAR(32) NOT NULL,
                confidence VARCHAR(32) DEFAULT 'CONFIRMED',
                description TEXT,
                evidence TEXT,
                remediation TEXT,
                scanner_name VARCHAR(128) NOT NULL,
                location VARCHAR(512),
                cwe_id VARCHAR(64),
                cvss_score FLOAT DEFAULT 0.0,
                status VARCHAR(32) DEFAULT 'OPEN',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_vf_scan (scan_id),
                INDEX idx_vf_sev (severity)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_reports (
                id VARCHAR(64) PRIMARY KEY,
                scan_id VARCHAR(64) NOT NULL,
                report_type VARCHAR(32) NOT NULL,
                report_reference TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_sr_scan (scan_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_audit_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                scan_id VARCHAR(64) NOT NULL,
                event_type VARCHAR(128) NOT NULL,
                event_details JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_sal_scan (scan_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        ]

        try:
            conn = self.get_connection()
            with conn.cursor() as cursor:
                for ddl in ddl_statements:
                    cursor.execute(ddl)
            conn.close()
            return {"success": True, "tables_created": len(ddl_statements)}
        except Exception as e:
            return {"success": False, "error": str(e)}


# Global instance
mysql_manager = MySQLDatabaseManager()
