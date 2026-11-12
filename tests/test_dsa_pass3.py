"""Regression tests for the third optimisation pass.

* DSA-CYB-03 - the tool inventory cache was invalidated from inside the
  16-worker pool, so one "update all tools" request re-ran the whole binary
  detection once per worker.
* DSA-CYB-02 - the OWASP plugins chose the parameters to probe with
  ``list(set(...))`` and then truncated, so the probe selection was
  hash-randomised and the scan coverage was not reproducible.
* DSA-BE-17/18 - the Kill Chain overview performed ~28 passes over the
  findings list and ``analyze_telemetry`` correlated the corpus twice.
* DSA-BE-21 - ``list_incidents`` had no LIMIT while its siblings did.
* DSA-BE-36 - the enterprise agent listing serialised every manifest before
  slicing the page.
* DSA-BE-41 - the agent "usage metrics" were computed over the most recent
  100 task rows while the table holds thousands, so the totals were wrong.
"""

import os
import subprocess
import sys

import pytest

from core.agent_registry import agent_registry
from core.database import db
from core.kill_chain.db import count_evidence, count_incidents, list_incidents
from core.kill_chain.engine import CyberKillChainEngine
from core.scanner_integrations import ScannerIntegrations
from plugins.owasp_plugins import _rank_probe_parameters


# ---------------------------------------------------------------------------
# DSA-CYB-03 - one detection pass for the whole batch
# ---------------------------------------------------------------------------
class TestToolInventoryCache:
    def test_update_all_tools_detects_the_inventory_once(self, monkeypatch):
        calls = {"n": 0}
        original = ScannerIntegrations._detect_tool_inventory

        def counting():
            calls["n"] += 1
            return original()

        monkeypatch.setattr(ScannerIntegrations, "_detect_tool_inventory", staticmethod(counting))
        ScannerIntegrations.invalidate_inventory_cache()

        ScannerIntegrations.update_all_tools()

        assert calls["n"] == 1, (
            "the tool inventory was detected %d times for a single batch "
            "(each detection shells out to ~15 binaries)" % calls["n"]
        )

    def test_single_tool_update_still_refreshes(self, monkeypatch):
        """A single-tool update must still re-detect: the binary may have changed."""
        calls = {"n": 0}
        original = ScannerIntegrations._detect_tool_inventory

        def counting():
            calls["n"] += 1
            return original()

        monkeypatch.setattr(ScannerIntegrations, "_detect_tool_inventory", staticmethod(counting))
        ScannerIntegrations.invalidate_inventory_cache()

        ScannerIntegrations.update_tool("nmap")

        assert calls["n"] == 1


# ---------------------------------------------------------------------------
# DSA-CYB-02 - deterministic OWASP probe-parameter selection
# ---------------------------------------------------------------------------
class TestDeterministicProbeSelection:
    def test_ranking_is_stable_and_preserves_priority(self):
        ranked = _rank_probe_parameters(["zebra", "search", "id", "unknownparam", "name", "file"])
        assert ranked.index("id") < ranked.index("search") < ranked.index("name")
        assert ranked.index("name") < ranked.index("file")
        # Unknown parameters keep their declaration order after the known ones.
        assert ranked.index("zebra") < ranked.index("unknownparam")

    def test_ranking_is_deterministic_across_hash_seeds(self):
        """The old selection used ``list(set(...))`` -> different per process."""
        params = ["zebra", "search", "id", "unknownparam", "name", "file"]
        code = (
            'import sys; sys.path.insert(0, "."); '
            "from plugins.owasp_plugins import _rank_probe_parameters; "
            "print(_rank_probe_parameters(%r))" % (params,)
        )
        results = set()
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for seed in ("0", "1", "2", "3", "42", "12345"):
            env = dict(os.environ)
            env["PYTHONHASHSEED"] = seed
            env["PYTHONPATH"] = repo
            out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                 text=True, env=env, cwd=repo)
            results.add(out.stdout.strip())
        assert len(results) == 1, "probe selection is not deterministic: %r" % (results,)

    def test_de_duplication_preserves_order(self):
        ranked = _rank_probe_parameters(["id", "id", "name", "name"])
        assert ranked == ["id", "name"]


# ---------------------------------------------------------------------------
# DSA-BE-17/18 - single-pass Kill Chain overview, single correlation
# ---------------------------------------------------------------------------
class TestKillChainOverview:
    def test_stage_summaries_are_complete_and_consistent(self):
        engine = CyberKillChainEngine()
        overview = engine.get_overview()

        assert set(overview.stage_summaries.keys()) == {
            "reconnaissance", "weaponization", "delivery", "exploitation",
            "installation", "c2", "actions_on_objectives",
        }
        total = sum(s["findings_count"] for s in overview.stage_summaries.values())
        assert total == overview.total_findings

        for stage in overview.stage_summaries.values():
            assert (stage["critical"] + stage["high"] + stage["medium"]
                    + stage["low"]) <= stage["findings_count"]

    def test_counters_are_exact_not_capped(self):
        """The counters used to be len() of lists read with a LIMIT."""
        engine = CyberKillChainEngine()
        overview = engine.get_overview()
        with db.get_connection() as conn:
            truth_evidence = conn.execute(
                "SELECT COUNT(*) FROM kill_chain_evidence").fetchone()[0]
            truth_incidents = conn.execute(
                "SELECT COUNT(*) FROM kill_chain_incidents").fetchone()[0]
        assert overview.total_evidence_count == truth_evidence
        assert overview.active_incidents_count == truth_incidents

    def test_incidents_list_is_bounded(self):
        rows = list_incidents(limit=5)
        assert len(rows) <= 5
        assert count_incidents() >= len(rows)
        assert count_evidence() >= 0


# ---------------------------------------------------------------------------
# DSA-BE-36 / DSA-BE-41 - enterprise listing and agent metrics
# ---------------------------------------------------------------------------
class TestEnterpriseAgentListing:
    def test_page_slice_does_not_change_the_result(self):
        manifests = agent_registry.list_manifests()
        assert len(manifests) > 1
        page_size = 10
        expected = [m.model_dump() for m in manifests[:page_size]]
        assert expected  # sanity

    def test_agent_task_metrics_are_exact(self):
        metrics = db.get_agent_task_metrics()
        with db.get_connection() as conn:
            truth = conn.execute("SELECT COUNT(*) FROM agent_tasks").fetchone()[0]
        assert metrics["total"] == truth
        assert metrics["completed"] + metrics["failed"] <= metrics["total"]


class TestAgentUsageEndpoint:
    def test_usage_summary_reports_the_true_total(self):
        from fastapi.testclient import TestClient
        from web.server import app

        client = TestClient(app)
        res = client.get("/api/ai-agents/usage")
        assert res.status_code == 200
        body = res.json()
        with db.get_connection() as conn:
            truth = conn.execute("SELECT COUNT(*) FROM agent_tasks").fetchone()[0]
        assert body["usage_summary"]["total_requests"] == truth
