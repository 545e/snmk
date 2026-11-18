"""
SWA AI — Base Integration Adapter
Provides the foundational contract, validation, rate limiting, and connection testing interface
for all external tools, platforms, threat feeds, and cloud services.
"""

from __future__ import annotations

import abc
from typing import Any


class BaseIntegrationAdapter(abc.ABC):
    """Abstract base class for all third-party tool and API adapters."""

    provider_id: str
    display_name: str
    category: str  # threat_intel, siem_edr, vulnerability_scanner, cloud, ai_provider, ticketing
    description: str
    documentation_url: str
    required_permissions: list[str]
    setup_instructions: str

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abc.abstractmethod
    def get_credential_fields(self) -> list[dict[str, Any]]:
        """Returns metadata for credentials required by this provider."""

    @abc.abstractmethod
    async def test_connection(self, credentials: dict[str, str], endpoint_url: str | None = None) -> dict[str, Any]:
        """
        Executes a live health check or lightweight probe against the provider API.
        Returns:
            {
                "success": bool,
                "status": "CONNECTED" | "AUTHENTICATION_FAILED" | "UNREACHABLE" | "NOT_CONFIGURED",
                "message": str,
                "latency_ms": int,
                "details": dict
            }
        """
