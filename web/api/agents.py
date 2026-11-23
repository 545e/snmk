"""
SNMK Autonomous Cybersecurity Agent Workforce API Router
Exposes central agent inventory, capability matrices, task dispatching, and agent health.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core.agent_registry import AgentRegistry
from core.database import db
from core.error_sanitizer import safe_error

logger = logging.getLogger("snmk.api.agents")
router = APIRouter(prefix="/agents", tags=["agents"])
registry = AgentRegistry()


class AgentTaskRequest(BaseModel):
    task: str = Field(..., description="Action instruction for the designated agent")
    context: dict[str, Any] = Field(default_factory=dict, description="Execution parameters and scan targets")
    timeout_sec: int = Field(default=60, ge=5, le=300)


@router.get("/summary")
async def get_agents_summary() -> dict[str, Any]:
    """Retrieve operational tier distribution and capability summary across all registered agents."""
    return registry.get_summary()


@router.get("")
async def list_agents(
    tier: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
) -> dict[str, Any]:
    """List registered agents with optional filtering by tier, domain category, or status."""
    agents = registry.list_agents(tier=tier, category=category, status=status)
    return {
        "count": len(agents),
        "agents": [a.dict() if hasattr(a, "dict") else dict(a) for a in agents],
    }


@router.get("/{agent_id}")
async def get_agent(agent_id: str) -> dict[str, Any]:
    """Retrieve full manifest, input/output schemas, and permission boundaries for a specific agent."""
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in registry")
    return agent.dict() if hasattr(agent, "dict") else dict(agent)


@router.post("/{agent_id}/dispatch")
async def dispatch_agent_task(agent_id: str, req: AgentTaskRequest) -> dict[str, Any]:
    """Dispatch an autonomous task to an individual specialist agent with non-destructive guards."""
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in registry")

    try:
        result = await registry.dispatch_task(
            agent_id=agent_id,
            task=req.task,
            context=req.context,
            timeout_sec=req.timeout_sec,
        )
        return {
            "agent_id": agent_id,
            "status": "COMPLETED",
            "result": result,
        }
    except Exception as e:
        logger.error(f"Failed executing task on agent {agent_id}: {safe_error(e)}")
        raise HTTPException(status_code=500, detail="Agent task execution failed")
