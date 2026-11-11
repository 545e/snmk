import asyncio

from core.agent_registry import agent_registry


def _expected_agent_count() -> int:
    """The number of registered agents, derived from the registry.

    The agent catalogue is a living thing: the MAP / network-intelligence
    tier added 9 agents without updating the previously hard-coded "85"
    literal, which made this test fail for the wrong reason (a stale
    constant) rather than for the reason it exists (agents do not execute).
    """
    return agent_registry.get_summary()["total_discovered"]


def test_all_registered_agents_execute_and_complete():
    """Verify that every registered cybersecurity agent across every
    operational tier is dispatched and completes."""
    expected = _expected_agent_count()
    res = asyncio.run(agent_registry.execute_all_85_agents(
        scan_id="test_ci_all_agents",
        target="http://127.0.0.1:8000"
    ))

    assert res["total_agents"] == expected
    assert res["successful_agents"] + res["failed_agents"] == expected
    assert res["not_executable_agents"] == 0
    assert res["failed_agents"] == 0, (
        f"agents reported as failed: "
        f"{[a for a in res.get('agent_results', []) if a.get('status') == 'FAILED']}"
    )
    assert res["status"] == "COMPLETED"

    tiers = res["tiers"]
    assert len(tiers) >= 5
    for tier_name, tier_info in tiers.items():
        assert tier_info["status"] == "COMPLETED", f"Tier {tier_name} did not complete: {tier_info}"
        assert tier_info["count"] > 0


def test_tier_breakdown_matches_registry():
    """The tier buckets reported by a dispatch must cover every agent."""
    expected = _expected_agent_count()
    res = asyncio.run(agent_registry.execute_all_85_agents(
        scan_id="test_ci_tier_breakdown",
        target="http://127.0.0.1:8000"
    ))
    assert sum(t["count"] for t in res["tiers"].values()) == expected
