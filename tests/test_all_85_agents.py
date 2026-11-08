import asyncio
from core.agent_registry import agent_registry

def test_all_85_agents_execute_and_complete():
    """Verify that all 85 cybersecurity agents across all 5 operational tiers execute and complete."""
    res = asyncio.run(agent_registry.execute_all_85_agents(
        scan_id="test_ci_all_85",
        target="http://127.0.0.1:8000"
    ))
    
    assert res["total_agents"] == 85
    assert res["successful_agents"] == 85
    assert res["failed_agents"] == 0
    assert res["not_executable_agents"] == 0
    assert res["status"] == "COMPLETED"
    
    tiers = res["tiers"]
    assert len(tiers) == 5
    for tier_name, tier_info in tiers.items():
        assert tier_info["status"] == "COMPLETED", f"Tier {tier_name} did not complete: {tier_info}"
        assert tier_info["count"] > 0
