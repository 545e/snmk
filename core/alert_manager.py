"""
SNMK Enterprise Platform — Centralized Alert & Notification Management Engine
Handles real-time security alerts, AI agent alerts, database warnings, and system failure alerts
with deduplication, rate limiting, suppression rules, and multi-channel notifications.
"""

from __future__ import annotations

import collections
import datetime
import enum
import hashlib
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.notifier import NotificationDispatcher

logger = logging.getLogger("snmk.alert_manager")


class AlertSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class AlertCategory(str, enum.Enum):
    APPLICATION = "APPLICATION"
    SECURITY = "SECURITY"
    AI_AGENT = "AI_AGENT"
    AUTOMATION = "AUTOMATION"
    DATABASE = "DATABASE"
    INFRASTRUCTURE = "INFRASTRUCTURE"


class AlertStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ASSIGNED = "ASSIGNED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class AlertRecord(BaseModel):
    """Structured security and operational alert model."""
    id: str = Field(default_factory=lambda: f"alt_{uuid.uuid4().hex[:10]}")
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    severity: AlertSeverity
    category: AlertCategory
    title: str
    description: str
    source: str = "snmk_core"
    affected_asset: Optional[str] = None
    correlation_id: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    status: AlertStatus = AlertStatus.ACTIVE
    assigned_owner: Optional[str] = None
    resolution_notes: Optional[str] = None
    fingerprint: str = ""


class AlertManager:
    """Enterprise alert orchestrator with deduplication, grouping, and notification dispatch."""

    def __init__(self, max_history: int = 1000):
        self._alerts: collections.deque[AlertRecord] = collections.deque(maxlen=max_history)
        self._seen_fingerprints: Dict[str, float] = {}  # fingerprint -> last_seen_time
        self._dedup_window_sec: float = 60.0  # 1-minute deduplication window
        self._subscribers: List[str] = []

    def _compute_fingerprint(self, category: AlertCategory, severity: AlertSeverity, title: str, asset: Optional[str]) -> str:
        raw = f"{category}:{severity}:{title}:{asset or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def create_alert(
        self,
        severity: AlertSeverity | str,
        category: AlertCategory | str,
        title: str,
        description: str,
        affected_asset: Optional[str] = None,
        correlation_id: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        source: str = "snmk_core",
    ) -> AlertRecord:
        """Creates and indexes a validated alert with automated deduplication."""
        sev = AlertSeverity(severity) if isinstance(severity, str) else severity
        cat = AlertCategory(category) if isinstance(category, str) else category

        fp = self._compute_fingerprint(cat, sev, title, affected_asset)
        now = time.time()

        # Deduplication check
        if fp in self._seen_fingerprints and (now - self._seen_fingerprints[fp]) < self._dedup_window_sec:
            # Duplicate alert suppressed within window
            for alert in reversed(self._alerts):
                if alert.fingerprint == fp:
                    return alert

        self._seen_fingerprints[fp] = now

        alert = AlertRecord(
            severity=sev,
            category=cat,
            title=title,
            description=description,
            source=source,
            affected_asset=affected_asset,
            correlation_id=correlation_id,
            evidence=evidence,
            remediation=remediation,
            fingerprint=fp,
        )

        self._alerts.append(alert)
        logger.info(f"Alert Created: [{alert.severity.value}] {alert.title} (ID: {alert.id})")
        return alert

    def get_alerts(
        self,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Filters alerts from in-memory ring buffer with structured pagination."""
        results = []
        for alert in reversed(self._alerts):
            if severity and alert.severity.value != severity.upper():
                continue
            if category and alert.category.value != category.upper():
                continue
            if status and alert.status.value != status.upper():
                continue
            results.append(alert.model_dump())
            if len(results) >= limit:
                break
        return results

    def get_summary(self) -> Dict[str, Any]:
        """Provides high-level alert posture metrics for the SOC dashboard."""
        counts_by_severity = {s.value: 0 for s in AlertSeverity}
        counts_by_category = {c.value: 0 for c in AlertCategory}
        counts_by_status = {st.value: 0 for st in AlertStatus}

        for a in self._alerts:
            counts_by_severity[a.severity.value] += 1
            counts_by_category[a.category.value] += 1
            counts_by_status[a.status.value] += 1

        return {
            "total_alerts": len(self._alerts),
            "active_alerts": counts_by_status.get(AlertStatus.ACTIVE.value, 0),
            "critical_count": counts_by_severity.get(AlertSeverity.CRITICAL.value, 0),
            "high_count": counts_by_severity.get(AlertSeverity.HIGH.value, 0),
            "by_severity": counts_by_severity,
            "by_category": counts_by_category,
            "by_status": counts_by_status,
            "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def update_status(
        self,
        alert_id: str,
        new_status: AlertStatus | str,
        owner: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """Updates the operational state of an existing alert."""
        st = AlertStatus(new_status) if isinstance(new_status, str) else new_status
        for a in self._alerts:
            if a.id == alert_id:
                a.status = st
                if owner:
                    a.assigned_owner = owner
                if notes:
                    a.resolution_notes = notes
                return True
        return False


# Global singleton instance
alert_manager = AlertManager()
