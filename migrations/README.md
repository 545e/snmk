"""Alembic migration directory for the optional MySQL backend.

No migration is executed by the application. An operator must explicitly:
  1. set SWA_DB_BACKEND=mysql and the MYSQL_* variables,
  2. review the generated SQL with `alembic upgrade head --sql`,
  3. take a backup,
  4. then apply it with `alembic upgrade head`.

The working SQLite database is never modified by Alembic.
"""
