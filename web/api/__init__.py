"""
SNMK Modular API Package
Exposes sub-routers for scans, subdomains, agents, findings, integrations, and reports.
"""

from fastapi import APIRouter

from web.api.scans import router as scans_router
from web.api.subdomains import router as subdomains_router
from web.api.agents import router as agents_router
from web.api.findings import router as findings_router
from web.api.integrations import router as integrations_router
from web.api.reports import router as reports_router

api_router = APIRouter(prefix="/api")
api_router.include_router(scans_router)
api_router.include_router(subdomains_router)
api_router.include_router(agents_router)
api_router.include_router(findings_router)
api_router.include_router(integrations_router)
api_router.include_router(reports_router)

__all__ = [
    "api_router",
    "scans_router",
    "subdomains_router",
    "agents_router",
    "findings_router",
    "integrations_router",
    "reports_router",
]
