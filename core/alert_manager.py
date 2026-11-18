"""
SNMK Enterprise Cybersecurity Platform — Centralized Alert & Notification Management Engine
Unified implementation supporting both:
1. Real-time observed event alerting with channels, delivery confirmation, deduplication, and suppression.
2. Enterprise SOC alerting with categories, asset mapping, correlation IDs, and REST management.
"""

from __future__ import annotations

import builtins
import enum
import hashlib
import json
import logging
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("snmk.alert_manager")

ROOT = Path(__file__).resolve().parent.parent
ALERTS_PATH = ROOT / "data" / "alerts.json"
MAX_ALERTS = 2000


# --- Severity Enums ---
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


# --- Category Enum ---
class AlertCategory(str, enum.Enum):
    APPLICATION = "APPLICATION"
    SECURITY = "SECURITY"
    AI_AGENT = "AI_AGENT"
    AUTOMATION = "AUTOMATION"
    DATABASE = "DATABASE"
    INFRASTRUCTURE = "INFRASTRUCTURE"


# --- Status Enums ---
class AlertStatus(str, Enum):
    OPEN = "open"
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "acknowledged"
    ASSIGNED = "assigned"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"


# --- Alert Data Structures ---
@dataclass
class Alert:
    id: str
    title: str
    severity: Severity | AlertSeverity
    source: str
    component: str
    description: str
    evidence: str = ""
    related_id: str = ""
    remediation: str = ""
    owner: str = ""
    status: AlertStatus = AlertStatus.OPEN
    resolution: str = ""
    fingerprint: str = ""
    created_at: str = ""
    updated_at: str = ""
    delivery: dict[str, str] = field(default_factory=dict)
    category: str = "SECURITY"
    affected_asset: str = ""
    correlation_id: str = ""

    @property
    def assigned_owner(self) -> str:
        return self.owner

    @assigned_owner.setter
    def assigned_owner(self, val: str):
        self.owner = val

    @property
    def resolution_notes(self) -> str:
        return self.resolution

    @resolution_notes.setter
    def resolution_notes(self, val: str):
        self.resolution = val

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        sev_val = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        st_val = self.status.value if hasattr(self.status, "value") else str(self.status)
        data["severity"] = sev_val
        data["status"] = st_val
        data["assigned_owner"] = self.owner
        data["resolution_notes"] = self.resolution
        return data

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()


# Alias for backwards compatibility
AlertRecord = Alert


class AlertManager:
    """Thread-safe, bounded, deduplicating alert store for Enterprise SNMK & Platform Engineering."""

    def __init__(self, path: Path = ALERTS_PATH, max_alerts: int = MAX_ALERTS):
        self.path = Path(path)
        self.max_alerts = max_alerts
        self._lock = threading.RLock()
        self._alerts: list[Alert] = []
        self._suppressed: set = set()
        self._channels: dict[str, Callable[[Alert], bool]] = {}
        self._load()

    # -- persistence -------------------------------------------------------
    def _load(self) -> None:
        try:
            if not self.path.exists():
                return
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            for item in payload.get("alerts", [])[-self.max_alerts:]:
                sev_raw = item.get("severity", "info")
                try:
                    item["severity"] = Severity(sev_raw.lower())
                except ValueError:
                    item["severity"] = Severity.INFO
                st_raw = item.get("status", "open")
                try:
                    item["status"] = AlertStatus(st_raw.lower())
                except ValueError:
                    item["status"] = AlertStatus.OPEN
                self._alerts.append(Alert(**item))
            self._suppressed = set(payload.get("suppressed", []))
        except (OSError, ValueError, TypeError):
            self._alerts = []

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "alerts": [alert.to_dict() for alert in self._alerts[-self.max_alerts:]],
                "suppressed": sorted(self._suppressed),
            }
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    # -- deduplication -----------------------------------------------------
    @staticmethod
    def fingerprint(alert: Alert) -> str:
        sev_val = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        material = f"{alert.source}|{alert.component}|{alert.title}|{sev_val}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    # -- Platform Engineering creation method ------------------------------
    def create(
        self,
        title: str,
        severity: Severity | str,
        source: str,
        component: str,
        description: str = "",
        evidence: str = "",
        related_id: str = "",
        remediation: str = "",
        deduplicate: bool = True,
    ) -> Alert:
        now = datetime.now(UTC).isoformat()
        sev = Severity(severity) if isinstance(severity, str) else severity
        alert = Alert(
            id=f"ALT-{uuid.uuid4().hex[:12]}",
            title=title[:300],
            severity=sev,
            source=source[:120],
            component=component[:120],
            description=description[:2000],
            evidence=evidence[:4000],
            related_id=related_id[:120],
            remediation=remediation[:2000],
            created_at=now,
            updated_at=now,
        )
        alert.fingerprint = self.fingerprint(alert)
        if alert.fingerprint in self._suppressed:
            alert.status = AlertStatus.SUPPRESSED

        with self._lock:
            if deduplicate and alert.status != AlertStatus.SUPPRESSED:
                for existing in reversed(self._alerts):
                    if (
                        existing.fingerprint == alert.fingerprint
                        and existing.status != AlertStatus.RESOLVED
                    ):
                        return existing

            self._alerts.append(alert)
            if len(self._alerts) > self.max_alerts:
                self._alerts = self._alerts[-self.max_alerts:]
            self._save()
        return alert

    # -- Enterprise SOC creation method ------------------------------------
    def create_alert(
        self,
        severity: AlertSeverity | Severity | str,
        category: AlertCategory | str,
        title: str,
        description: str,
        source: str = "snmk_core",
        affected_asset: str | None = None,
        correlation_id: str | None = None,
        evidence: dict[str, Any] | str | None = None,
        remediation: str | None = None,
    ) -> Alert:
        now = datetime.now(UTC).isoformat()
        # Map severity
        if isinstance(severity, (AlertSeverity, Severity)):
            sev = severity
        elif str(severity).upper() in AlertSeverity.__members__:
            sev = AlertSeverity[str(severity).upper()]
        else:
            sev = AlertSeverity.INFORMATIONAL

        cat_str = category.value if hasattr(category, "value") else str(category)
        ev_str = json.dumps(evidence) if isinstance(evidence, dict) else (evidence or "")

        alert = Alert(
            id=f"alt_{uuid.uuid4().hex[:10]}",
            title=title[:300],
            severity=sev,
            source=source[:120],
            component=affected_asset or source[:120],
            description=description[:2000],
            evidence=ev_str[:4000],
            related_id=correlation_id or "",
            remediation=(remediation or "")[:2000],
            status=AlertStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            category=cat_str,
            affected_asset=affected_asset or "",
            correlation_id=correlation_id or "",
        )
        alert.fingerprint = self.fingerprint(alert)

        with self._lock:
            # Check deduplication within active alerts
            for existing in reversed(self._alerts):
                if (
                    existing.title == alert.title
                    and existing.affected_asset == alert.affected_asset
                    and existing.source == alert.source
                    and existing.status != AlertStatus.RESOLVED
                ):
                    return existing

            self._alerts.append(alert)
            if len(self._alerts) > self.max_alerts:
                self._alerts = self._alerts[-self.max_alerts:]
            self._save()
        return alert

    # -- lifecycle ---------------------------------------------------------
    def _find(self, alert_id: str) -> Alert | None:
        return next((a for a in self._alerts if a.id == alert_id), None)

    def acknowledge(self, alert_id: str) -> bool:
        with self._lock:
            alert = self._find(alert_id)
            if not alert or alert.status == AlertStatus.RESOLVED:
                return False
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.updated_at = datetime.now(UTC).isoformat()
            self._save()
            return True

    def assign(self, alert_id: str, owner: str) -> bool:
        with self._lock:
            alert = self._find(alert_id)
            if not alert or alert.status == AlertStatus.RESOLVED:
                return False
            alert.owner = owner[:120]
            alert.status = AlertStatus.ASSIGNED
            alert.updated_at = datetime.now(UTC).isoformat()
            self._save()
            return True

    def resolve(self, alert_id: str, resolution: str) -> bool:
        with self._lock:
            alert = self._find(alert_id)
            if not alert:
                return False
            alert.status = AlertStatus.RESOLVED
            alert.resolution = resolution[:1000]
            alert.updated_at = datetime.now(UTC).isoformat()
            self._save()
            return True

    def update_status(
        self,
        alert_id: str,
        new_status: AlertStatus | str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> bool:
        with self._lock:
            alert = self._find(alert_id)
            if not alert:
                return False
            if isinstance(new_status, str):
                try:
                    alert.status = AlertStatus(new_status.lower())
                except ValueError:
                    try:
                        alert.status = AlertStatus(new_status.upper())
                    except ValueError:
                        alert.status = AlertStatus.OPEN
            else:
                alert.status = new_status
            if owner:
                alert.owner = owner[:120]
            if notes:
                alert.resolution = notes[:1000]
            alert.updated_at = datetime.now(UTC).isoformat()
            self._save()
            return True

    def suppress(self, fingerprint: str) -> None:
        with self._lock:
            self._suppressed.add(fingerprint)
            self._save()

    def unsuppress(self, fingerprint: str) -> None:
        with self._lock:
            self._suppressed.discard(fingerprint)
            self._save()

    # -- notification ------------------------------------------------------
    def register_channel(self, name: str, sender: Callable[[Alert], bool]) -> None:
        """Registers a channel whose sender returns True only on confirmation."""
        self._channels[name] = sender

    def notify(self, alert_id: str, channels: builtins.list[str] | None = None) -> dict[str, str]:
        with self._lock:
            alert = self._find(alert_id)
        if not alert:
            return {}

        targets = channels or list(self._channels)
        results: dict[str, str] = {}
        if not targets:
            results["unconfigured"] = DeliveryStatus.NOT_CONFIGURED.value
            alert.delivery.update(results)
            self._save()
            return results
        for name in targets:
            sender = self._channels.get(name)
            if sender is None:
                results[name] = DeliveryStatus.NOT_CONFIGURED.value
                alert.delivery[name] = results[name]
                continue
            try:
                results[name] = (
                    DeliveryStatus.DELIVERED.value if sender(alert)
                    else DeliveryStatus.FAILED.value
                )
            except Exception:  # noqa: BLE001
                results[name] = DeliveryStatus.FAILED.value
            alert.delivery[name] = results[name]

        self._save()
        return results

    # -- query -------------------------------------------------------------
    def list(
        self,
        severity: str | None = None,
        status: str | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> builtins.list[dict[str, Any]]:
        with self._lock:
            items = list(reversed(self._alerts))
        if severity:
            items = [a for a in items if (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).lower() == severity.lower()]
        if status:
            items = [a for a in items if (a.status.value if hasattr(a.status, "value") else str(a.status)).lower() == status.lower()]
        if source:
            items = [a for a in items if a.source == source]
        return [a.to_dict() for a in items[:max(1, min(limit, 500))]]

    def get_alerts(
        self,
        severity: str | None = None,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> builtins.list[dict[str, Any]]:
        with self._lock:
            items = list(reversed(self._alerts))
        if severity:
            items = [a for a in items if (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).upper() == severity.upper()]
        if category:
            items = [a for a in items if a.category.upper() == category.upper()]
        if status:
            items = [a for a in items if (a.status.value if hasattr(a.status, "value") else str(a.status)).upper() == status.upper()]
        return [a.to_dict() for a in items[:max(1, min(limit, 500))]]

    def summary(self) -> dict[str, Any]:
        return self.get_summary()

    def get_summary(self) -> dict[str, Any]:
        """Provides high-level alert posture metrics for the SOC dashboard and Platform Engineering."""

        counts_by_severity = {s.value: 0 for s in AlertSeverity}
        counts_by_category = {c.value: 0 for c in AlertCategory}
        counts_by_status = {st.value: 0 for st in AlertStatus}

        with self._lock:
            items = list(self._alerts)

        for a in items:
            sev_u = (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).upper()
            if sev_u in counts_by_severity:
                counts_by_severity[sev_u] += 1
            cat_u = a.category.upper()
            if cat_u in counts_by_category:
                counts_by_category[cat_u] += 1
            st_u = (a.status.value if hasattr(a.status, "value") else str(a.status)).upper()
            if st_u in counts_by_status:
                counts_by_status[st_u] += 1

        total = len(items)
        active = sum(1 for a in items if a.status not in (AlertStatus.RESOLVED, AlertStatus.SUPPRESSED))

        return {
            "total": total,
            "total_alerts": total,
            "open": active,
            "active_alerts": active,
            "critical_count": counts_by_severity.get("CRITICAL", 0),
            "high_count": counts_by_severity.get("HIGH", 0),
            "by_severity": counts_by_severity,
            "by_category": counts_by_category,
            "by_status": counts_by_status,
            "suppression_rules": len(self._suppressed),
            "channels_configured": sorted(self._channels),
            "last_updated": datetime.now(UTC).isoformat(),
        }


# Global singleton instance exported as both `manager` and `alert_manager`
manager = AlertManager()
alert_manager = manager
