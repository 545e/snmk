"""
SNMK Tool Integrations, Scanners, and Credentials API Router
Handles external cybersecurity tool discovery, health checks, third-party adapters, and credential lifecycle.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.integrations.registry import integration_registry
from core.scanner_integrations import ScannerIntegrations
from core.audit import audit
from core.error_sanitizer import safe_error

logger = logging.getLogger("snmk.api.integrations")
router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationConfigRequest(BaseModel):
    provider: str
    api_key: str
    base_url: Optional[str] = None
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.get("/summary")
async def get_integrations_summary() -> dict[str, Any]:
    """Return real-time health and KPI statistics across all third-party integrations."""
    return integration_registry.get_integrations_summary()


@router.get("")
async def list_integrations() -> dict[str, Any]:
    """List all configured integrations with masked credentials."""
    return {"integrations": integration_registry.list_configured_integrations()}


@router.get("/providers")
async def list_supported_providers() -> dict[str, Any]:
    """List all 23 supported threat intelligence, SIEM, and vulnerability management providers."""
    return {"providers": integration_registry.list_supported_providers()}


@router.get("/{integration_id}")
async def get_integration(integration_id: str) -> dict[str, Any]:
    """Get metadata and health status for an individual integration."""
    item = integration_registry.get_integration(integration_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Integration '{integration_id}' not found")
    return item


@router.post("/test-all")
async def test_all_integrations() -> dict[str, Any]:
    """Execute live connection checks across all configured integrations."""
    result = await integration_registry.test_all_integrations()
    audit.record("integration.test_all", "all", f"passed={result.get('passed')},failed={result.get('failed')}", "")
    return result


@router.post("/{integration_id}/test")
async def test_single_integration(integration_id: str) -> dict[str, Any]:
    """Run an isolated live probe against a specific third-party integration endpoint."""
    result = await integration_registry.test_integration(integration_id)
    return result


@router.post("/{integration_id}/toggle")
async def toggle_integration(integration_id: str) -> dict[str, Any]:
    """Enable or disable a specific third-party integration."""
    return integration_registry.toggle_integration(integration_id)
