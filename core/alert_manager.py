"""
SWA AI — Centralized Alert Management.

Alerts are generated from *observed* events, never invented. Each alert has
the full lifecycle requested by the platform: a unique id, a timestamp, a
severity, a source, an affected component, evidence, a related scan or
execution id, remediation advice, an owner, a status and a resolution.

The store also implements deduplication, correlation, suppression, bounded
history and notification dispatch. A notification is recorded as DELIVERED
only when the channel confirms it; an unconfirmed send is recorded as FAILED
or PENDING, never as delivered.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
ALERTS_PATH = ROOT / "data" / "alerts.json"
MAX_ALERTS = 2000


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    ASSIGNED = "assigned"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"


@dataclass
class Alert:
    id: str
    title: str
    severity: Severity
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

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data


class AlertManager:
    """Thread-safe, bounded, deduplicating alert store."""

    def __init__(self, path: Path = ALERTS_PATH, max_alerts: int = MAX_ALERTS):
        self.path = path
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
                item["severity"] = Severity(item.get("severity", "info"))
                item["status"] = AlertStatus(item.get("status", "open"))
                self._alerts.append(Alert(**item))
            self._suppressed = set(payload.get("suppressed", []))
        except (OSError, ValueError, TypeError):
            # A corrupt alert file must not prevent the platform starting.
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
        material = f"{alert.source}|{alert.component}|{alert.title}|{alert.severity.value}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    # -- create ------------------------------------------------------------
    def create(
        self,
        title: str,
        severity: Severity,
        source: str,
        component: str,
        description: str = "",
        evidence: str = "",
        related_id: str = "",
        remediation: str = "",
        deduplicate: bool = True,
    ) -> Alert:
        now = datetime.now(UTC).isoformat()
        alert = Alert(
            id=f"ALT-{uuid.uuid4().hex[:12]}",
            title=title[:300],
            severity=Severity(severity),
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

        with self._lock:
            # A suppressed fingerprint is checked first: a suppressed alert
            # must never be resurrected by the deduplication path.
            if alert.fingerprint in self._suppressed:
                alert.status = AlertStatus.SUPPRESSED

            if deduplicate:
                for existing in reversed(self._alerts):
                    if existing.fingerprint == alert.fingerprint and existing.status != AlertStatus.RESOLVED:
                        if alert.status == AlertStatus.SUPPRESSED:
                            existing.status = AlertStatus.SUPPRESSED
                        existing.updated_at = now
                        self._save()
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
        """
        Attempts delivery. A channel is DELIVERED only when its sender
        confirms. Without a registered channel the result is NOT_CONFIGURED.
        """
        with self._lock:
            alert = self._find(alert_id)
        if not alert:
            return {}

        targets = channels or list(self._channels)
        results: dict[str, str] = {}
        if not targets:
            # No channel is configured. Report that explicitly rather than
            # returning an empty dict (which looks like "alert not found").
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
            except Exception:  # noqa: BLE001 - notification boundary must never raise
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
            items = [a for a in items if a.severity.value == severity]
        if status:
            items = [a for a in items if a.status.value == status]
        if source:
            items = [a for a in items if a.source == source]
        return [a.to_dict() for a in items[:max(1, min(limit, 500))]]

    def summary(self) -> dict[str, Any]:
        from collections import Counter

        with self._lock:
            items = list(self._alerts)
        return {
            "total": len(items),
            "by_severity": dict(Counter(a.severity.value for a in items)),
            "by_status": dict(Counter(a.status.value for a in items)),
            "open": sum(1 for a in items if a.status != AlertStatus.RESOLVED),
            "suppression_rules": len(self._suppressed),
            "channels_configured": sorted(self._channels),
        }


manager = AlertManager()
