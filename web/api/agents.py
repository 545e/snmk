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
    task: Optional[str] = Field(default=None, description="Action instruction for the designated agent")
    title: Optional[str] = Field(default=None, description="Task title or high-level objective")
    inputs: dict[str, Any] = Field(default_factory=dict, description="Input parameters for the agent execution")
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
    search: Optional[str] = None,
) -> dict[str, Any]:
    """List registered agents with optional filtering by tier, domain category, status, or search query."""
    agents = registry.list_manifests(category=category, tier=tier, status=status, search=search)
    manifest_dicts = [a.dict() if hasattr(a, "dict") else dict(a) for a in agents]
    return {
        "count": len(agents),
        "agents": manifest_dicts,
        "items": manifest_dicts,
    }


@router.get("/{agent_id}")
async def get_agent(agent_id: str) -> dict[str, Any]:
    """Retrieve full manifest, input/output schemas, and permission boundaries for a specific agent."""
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in registry")
    return agent.dict() if hasattr(agent, "dict") else dict(agent)


@router.post("/{agent_id}/dispatch")
@router.post("/{agent_id}/task")
async def dispatch_agent_task(agent_id: str, req: AgentTaskRequest) -> dict[str, Any]:
    """Dispatch an autonomous task to an individual specialist agent with non-destructive guards."""
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in registry")

    task_desc = req.task or req.title or f"Autonomous task for {agent.name}"
    merged_inputs = dict(req.context or {})
    merged_inputs.update(req.inputs or {})
    merged_inputs.setdefault("task", task_desc)

    try:
        result = await registry.dispatch_task(
            agent_id=agent_id,
            task=task_desc,
            context=merged_inputs,
            timeout_sec=req.timeout_sec,
        )
        return {
            "agent_id": agent.id,
            "role": agent.role,
            "status": "COMPLETED" if (result and result.get("status") != "FAILED") else "FAILED",
            "result": result,
            "outputs": result.get("outputs", {}) if isinstance(result, dict) else {},
            "duration_seconds": result.get("duration_seconds", 0) if isinstance(result, dict) else 0,
        }
    except Exception as e:
        logger.error(f"Failed executing task on agent {agent_id}: %s", safe_error("Agent task execution failed", e))
        raise HTTPException(status_code=500, detail="Agent task execution failed")
