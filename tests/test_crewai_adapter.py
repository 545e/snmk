"""
Unit and Integration Tests for SNMK CrewAI Multi-Agent Architecture Adapter.
"""

import asyncio

from core.crewai_adapter import (
    CrewAIAgentConfig,
    CrewAIResult,
    CrewAITaskConfig,
    SNMKCrew,
    SNMKCrewAIAgent,
    create_cybersecurity_pentest_crew,
)


def test_crewai_agent_config_and_memory():
    cfg = CrewAIAgentConfig(
        role="Test Auditor",
        goal="Audit security headers",
        backstory="Security specialist",
        tools=["curl", "nmap"],
        memory=True
    )
    agent = SNMKCrewAIAgent(cfg)
    assert agent.role == "Test Auditor"
    assert agent.tools == ["curl", "nmap"]

    agent.add_to_memory({"event": "scanned_host", "host": "127.0.0.1"})
    assert len(agent._memory_store) == 1
    assert agent._memory_store[0]["event"] == "scanned_host"


def test_crewai_agent_task_execution():
    async def _test():
        cfg = CrewAIAgentConfig(
            role="Vulnerability Verifier",
            goal="Verify reported SQLi vector",
            backstory="Exploit analyst",
            tools=["sqli_tool"]
        )
        agent = SNMKCrewAIAgent(cfg)
        task = CrewAITaskConfig(
            description="Check if parameter 'id' is vulnerable to blind boolean injection",
            expected_output="Deterministic verification status",
            agent_role="Vulnerability Verifier"
        )

        result = await agent.execute_task(task)
        assert result["status"] == "COMPLETED"
        assert result["task_id"] == task.task_id
        assert result["agent_role"] == "Vulnerability Verifier"
        assert "tools_used" in result

    asyncio.run(_test())


def test_crewai_crew_orchestration():
    async def _test():
        agent1 = SNMKCrewAIAgent(CrewAIAgentConfig(
            role="Recon Specialist",
            goal="Enumerate targets",
            backstory="OSINT Analyst",
            tools=["subfinder"]
        ))
        agent2 = SNMKCrewAIAgent(CrewAIAgentConfig(
            role="Vuln Analyst",
            goal="Assess targets",
            backstory="AppSec Analyst",
            tools=["owasp_plugins"]
        ))

        tasks = [
            CrewAITaskConfig(
                description="Enumerate subdomains for test domain",
                expected_output="List of active hosts",
                agent_role="Recon Specialist"
            ),
            CrewAITaskConfig(
                description="Scan active hosts for exposed sensitive endpoints",
                expected_output="List of open endpoints",
                agent_role="Vuln Analyst"
            )
        ]

        crew = SNMKCrew(agents=[agent1, agent2], tasks=tasks, process="sequential")
        res = await crew.kickoff()

        assert isinstance(res, CrewAIResult)
        assert res.status == "COMPLETED"
        assert res.tasks_completed == 2
        assert res.total_tasks == 2
        assert len(res.task_results) == 2

    asyncio.run(_test())


def test_pentest_crew_factory_and_execution():
    async def _test():
        crew = create_cybersecurity_pentest_crew()
        assert len(crew.agents) == 3
        assert len(crew.tasks) == 3

        res = await crew.kickoff(inputs={"target": "api.example.internal"})
        assert res.status == "COMPLETED"
        assert res.tasks_completed == 3
        assert "Crew [" in res.output

    asyncio.run(_test())
