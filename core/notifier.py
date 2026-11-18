"""
SWA AI Webhook & Notification Dispatcher
Sends real-time findings and scan completion events to Slack, Discord,
or custom HMAC-signed webhooks.
"""

import hashlib
import hmac
import json
import logging
import urllib.parse
from typing import Any

import httpx

from core.scope_policy import scope_policy

logger = logging.getLogger("snmk.notifier")


def _is_safe_webhook_url(url: str) -> bool:
    """SSRF guard: verifies webhook URL uses HTTP(S) and targets non-restricted hosts."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        is_restr, _ = scope_policy.is_private_or_restricted(parsed.hostname)
        return not is_restr
    except Exception:
        return False


class NotificationDispatcher:
    @staticmethod
    async def send_slack_alert(webhook_url: str, title: str, severity: str, endpoint: str, details: str) -> bool:
        """Sends a rich Slack block-kit alert for high/critical findings."""
        if not _is_safe_webhook_url(webhook_url):
            logger.warning("Rejected unsafe webhook URL for Slack alert")
            return False

        color_map = {
            "CRITICAL": "#f85149",
            "HIGH": "#f0883e",
            "MEDIUM": "#d29922",
            "LOW": "#58a6ff",
            "INFO": "#8b949e"
        }
        color = color_map.get(severity.upper(), "#6366f1")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"🚨 [{severity.upper()}] {title}",
                    "fields": [
                        {"title": "Target Endpoint", "value": f"`{endpoint}`", "short": False},
                        {"title": "Analysis / Impact", "value": details[:300], "short": False}
                    ],
                    "footer": "SWA AI Autonomous Cyber Auditor",
                    "ts": int(__import__("time").time())
                }
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(webhook_url, json=payload)
                return res.status_code == 200
        except Exception:
            return False

    @staticmethod
    async def send_custom_webhook(webhook_url: str, event_type: str, data: dict[str, Any], secret: str | None = None) -> bool:
        """Dispatches an HMAC-SHA256 signed JSON payload to an enterprise SIEM / SOAR endpoint."""
        if not _is_safe_webhook_url(webhook_url):
            logger.warning("Rejected unsafe webhook URL for custom webhook")
            return False

        payload_bytes = json.dumps(data, default=str).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-SWA-Event": event_type
        }
        if secret:
            sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
            headers["X-SWA-Signature"] = f"sha256={sig}"

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(webhook_url, content=payload_bytes, headers=headers)
                return res.status_code in [200, 201, 202, 204]
        except Exception:
            return False
