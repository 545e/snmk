"""
SWA AI — Optional MySQL integration.

This module does **not** replace SQLite. SQLite remains the primary store:
it is working, holds 43 tables and real user data, and switching the primary
database needs a reviewed migration and explicit approval.

What this module provides is a ready, *opt-in* MySQL backend for deployments
that need a shared relational store:

* environment-driven configuration (no hardcoded credentials);
* a SQLAlchemy connection pool with bounded size, retries and timeouts;
* TLS configuration support;
* a health probe and real telemetry (server version, connections, db size,
  table count, slow-query count) read from MySQL itself;
* a clear ``NOT_AVAILABLE`` state when no server is configured.

Every reported metric comes from a real query. Nothing is estimated and no
statistics are fabricated. Credentials are never logged or returned.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from core.error_sanitizer import safe_error

__all__ = ["MySQLConfig", "mysql_health", "mysql_metrics", "mysql_status"]


class MySQLUnavailable(RuntimeError):
    """Raised when MySQL is configured but cannot be reached."""


@dataclass(frozen=True)
class MySQLConfig:
    host: str
    port: int
    database: str
    user: str
    password: str
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 10
    connect_timeout: int = 5
    ssl_mode: str = ""

    @classmethod
    def from_env(cls) -> MySQLConfig | None:
        """
        Builds a config from the environment.

        Returns ``None`` when MySQL has not been enabled, so the platform can
        run its normal SQLite path without any MySQL dependency.
        """
        if os.environ.get("SWA_DB_BACKEND", "sqlite").strip().lower() not in ("mysql", "mariadb"):
            return None
        password = os.environ.get("MYSQL_PASSWORD", "")
        if not (os.environ.get("MYSQL_HOST") and os.environ.get("MYSQL_USER") and password):
            raise MySQLUnavailable(
                "SWA_DB_BACKEND=mysql requires MYSQL_HOST, MYSQL_USER and MYSQL_PASSWORD."
            )
        try:
            port = int(os.environ.get("MYSQL_PORT", "3306"))
            pool = int(os.environ.get("MYSQL_POOL_SIZE", "5"))
        except ValueError as exc:
            raise MySQLUnavailable(safe_error("Invalid MySQL numeric configuration", exc))
        return cls(
            host=os.environ["MYSQL_HOST"],
            port=port,
            database=os.environ.get("MYSQL_DATABASE", "snmk"),
            user=os.environ["MYSQL_USER"],
            password=password,
            pool_size=max(1, min(pool, 50)),
            ssl_mode=os.environ.get("MYSQL_SSL_MODE", "").strip(),
        )

    def url(self) -> str:
        """Returns a SQLAlchemy URL. The password is intentionally omitted."""
        return f"mysql+pymysql://{self.user}:***@{self.host}:{self.port}/{self.database}"

    def connect_args(self) -> dict[str, Any]:
        args: dict[str, Any] = {"connect_timeout": self.connect_timeout}
        if self.ssl_mode:
            args["ssl"] = {"ssl_mode": self.ssl_mode}
        return args


_engine_cache: dict[str, Any] = {}


def _engine(config: MySQLConfig):
    """Creates (once) a pooled SQLAlchemy engine for this configuration."""
    from sqlalchemy import create_engine

    key = f"{config.host}:{config.port}/{config.database}"
    if key in _engine_cache:
        return _engine_cache[key]

    # Imported lazily so SQLite-only deployments need no MySQL driver.
    url = (
        f"mysql+pymysql://{config.user}:{config.password}"
        f"@{config.host}:{config.port}/{config.database}"
        "?charset=utf8mb4"
    )
    engine = create_engine(
        url,
        pool_size=config.pool_size,
        max_overflow=config.max_overflow,
        pool_timeout=config.pool_timeout,
        pool_pre_ping=True,
        connect_args=config.connect_args(),
        future=True,
    )
    _engine_cache[key] = engine
    return engine


def _query(config: MySQLConfig, sql: str, params: tuple = ()) -> Any:
    """Runs one query with a bounded retry, returning the first row."""
    from sqlalchemy import text

    engine = _engine(config)
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with engine.connect() as connection:
                return connection.execute(text(sql), params).fetchone()
        except Exception as exc:  # noqa: BLE001 - any driver error is a retryable DB failure
            last_error = exc
            if attempt < 2:
                time.sleep(0.25 * (attempt + 1))
    raise MySQLUnavailable(safe_error("MySQL query failed.", last_error))


def mysql_status() -> dict[str, Any]:
    """Reports whether MySQL is configured, reachable and usable."""
    try:
        config = MySQLConfig.from_env()
    except MySQLUnavailable as exc:
        return {"enabled": False, "status": "Not Available", "reason": safe_error("MySQL is not configured.", exc)}
    if config is None:
        return {
            "enabled": False,
            "status": "Not Available",
            "reason": "SQLite is the configured backend; MySQL is opt-in (SWA_DB_BACKEND=mysql).",
            "backend": "sqlite",
        }

    try:
        started = time.perf_counter()
        row = _query(config, "SELECT VERSION() AS v")
        latency = round((time.perf_counter() - started) * 1000, 2)
        return {
            "enabled": True,
            "status": "Operational",
            "version": row[0] if row else None,
            "endpoint": f"{config.host}:{config.port}/{config.database}",
            "pool_size": config.pool_size,
            "ssl_mode": config.ssl_mode or "disabled",
            "latency_ms": latency,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    except MySQLUnavailable as exc:
        return {"enabled": True, "status": "Failed", "reason": safe_error("MySQL status could not be determined.", exc)}


def mysql_health() -> bool:
    """A boolean health probe suitable for a dependency check."""
    return mysql_status().get("status") == "Operational"


def mysql_metrics() -> dict[str, Any]:
    """
    Reads real telemetry from MySQL's status and information_schema.

    Returns an explicit ``available: False`` payload when no server is
    configured -- never invented numbers.
    """
    status = mysql_status()
    if status.get("status") != "Operational":
        return {"available": False, "reason": status.get("reason", "MySQL not operational")}

    config = MySQLConfig.from_env()
    assert config is not None

    def scalar(sql: str, params: tuple = ()) -> Any:
        row = _query(config, sql, params)
        return row[0] if row else None

    try:
        return {
            "available": True,
            "server_version": status.get("version"),
            "active_connections": _status_value(config, "Threads_connected"),
            "database_size_bytes": scalar(
                "SELECT COALESCE(SUM(data_length + index_length), 0) "
                "FROM information_schema.TABLES WHERE table_schema = :db",
                (config.database,),
            ),
            "table_count": scalar(
                "SELECT COUNT(*) FROM information_schema.TABLES WHERE table_schema = :db",
                (config.database,),
            ),
            "slow_queries": _status_value(config, "Slow_queries"),
            "aborted_connects": _status_value(config, "Aborted_connects"),
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    except MySQLUnavailable as exc:
        return {"available": False, "reason": safe_error("MySQL metrics are unavailable.", exc)}


def _status_value(config: MySQLConfig, name: str) -> Any:
    """Reads one Server-status variable via information_schema (portable)."""
    from sqlalchemy import text

    engine = _engine(config)
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS "
                 "WHERE VARIABLE_NAME = :name"),
            {"name": name},
        ).fetchone()
    return row[0] if row else None
