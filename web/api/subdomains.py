"""
SNMK Subdomain Discovery and EASM Drift API Router
Provides endpoints for querying, filtering, and exporting discovered subdomains and attack surfaces.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from fastapi import APIRouter

from core.database import db
from core.persistent_store import persistent_store

router = APIRouter(prefix="/subdomains", tags=["subdomains"])


@router.get("")
@router.get("/{scan_id}")
async def get_persisted_subdomains(
    scan_id: Optional[str] = None,
    root_domain: Optional[str] = None,
    discovery_type: Optional[str] = None,
    user_id: str = "operator",
    limit: int = 500,
    offset: int = 0,
) -> dict[str, Any]:
    """Retrieve persisted subdomains with optional filtering by scan, domain, or discovery mechanism."""
    rows = persistent_store.get_subdomains(scan_id) if scan_id else []
    if not scan_id:
        with db.get_connection() as conn:
            rows = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM subdomains ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                    (min(max(limit, 1), 5000), max(offset, 0)),
                ).fetchall()
            ]

    if root_domain:
        rows = [r for r in rows if r.get("root_domain") == root_domain]
    if discovery_type:
        rows = [r for r in rows if r.get("discovery_type") == discovery_type]
    rows = [r for r in rows if (r.get("user_id") or "operator") == user_id]

    for row in rows:
        for key in ("ip_addresses", "cname_records"):
            if isinstance(row.get(key), str):
                try:
                    row[key] = json.loads(row[key])
                except (TypeError, ValueError):
                    row[key] = []

    return {
        "scan_id": scan_id,
        "count": len(rows),
        "subdomains": rows[: min(max(limit, 1), 5000)],
        "source": "persistent_store",
    }
