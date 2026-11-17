"""
Alembic environment for the optional SNMK MySQL backend.

The database URL is built from MYSQL_* environment variables at runtime.
No password appears in a file, in a log, or in a migration script.

This environment refuses to run unless the operator has explicitly selected
the MySQL backend, so the working SQLite deployment cannot be affected by an
accidental `alembic upgrade`.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Alembic provides ``context.config`` only while it is running a migration.
# ``getattr`` keeps this file importable by tooling that walks every module.
config = getattr(context, "config", None)
if config is not None and config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _mysql_url() -> str:
    if os.environ.get("SWA_DB_BACKEND", "sqlite").lower() not in ("mysql", "mariadb"):
        raise SystemExit(
            "Refusing to migrate: SWA_DB_BACKEND is not 'mysql'. "
            "The SQLite deployment is untouched."
        )
    missing = [
        name for name in ("MYSQL_HOST", "MYSQL_USER", "MYSQL_PASSWORD")
        if not os.environ.get(name)
    ]
    if missing:
        raise SystemExit("Refusing to migrate: missing " + ", ".join(missing))
    host = os.environ["MYSQL_HOST"]
    port = os.environ.get("MYSQL_PORT", "3306")
    database = os.environ.get("MYSQL_DATABASE", "snmk")
    user = os.environ["MYSQL_USER"]
    password = os.environ["MYSQL_PASSWORD"]
    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}?charset=utf8mb4"


if config is not None:
    config.set_main_option("sqlalchemy.url", _mysql_url())


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting -- for operator review."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=None,
        literal_binds=False,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply reviewed migrations to the explicitly configured MySQL server."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=None, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


# Only run when Alembic is actually driving this environment.
if config is not None:
    if context.is_offline_mode():
        run_migrations_offline()
    else:
        run_migrations_online()
