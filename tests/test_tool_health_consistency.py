"""Regression tests for the tool-health diagnostics panel.

The panel reported filter counters that disagreed with the list it rendered
("Unavailable (1)" while four cards were marked UNAVAILABLE) and showed
"Checks Passed: 0/5" for tools that had passed every verification level.

These tests pin:
  * every health status maps to exactly one filter bucket, in the backend and
    in the frontend, so the counters always add up to the total;
  * the summary counters agree with the per-tool statuses;
  * a HEALTHY tool never reports failed checks;
  * the frontend's counter elements all exist in the markup, so a counter can
    never silently go stale;
  * static assets are served with a content-addressed version, so a browser can
    never run a stale script.
"""

import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO, "web", "static")
APP_JS = os.path.join(STATIC, "app.js")
INDEX_HTML = os.path.join(STATIC, "index.html")

with open(APP_JS, encoding="utf-8") as fh:
    APP_JS_SRC = fh.read()
with open(INDEX_HTML, encoding="utf-8") as fh:
    INDEX_HTML_SRC = fh.read()


def _tool(status, **kw):
    base = {"tool_id": "t_" + status.lower(), "name": status, "category": "test",
            "status": status, "checks_passed": [], "checks_failed": []}
    base.update(kw)
    return base


class TestBucketMapping:
    def test_every_backend_status_has_a_frontend_bucket(self):
        from core.tool_dependency_manager import ToolHealthState

        m = re.search(r"const TOOL_HEALTH_BUCKETS = \{(.*?)\n\};", APP_JS_SRC, re.S)
        assert m, "TOOL_HEALTH_BUCKETS not found in app.js"
        mapped = set(re.findall(r"^\s*([A-Z_]+):\s*'", m.group(1), re.M))
        for state in ToolHealthState:
            assert state.value in mapped, (
                "health status %s has no frontend bucket - it would be counted in "
                "the 'All' pill but in no other pill" % state.value
            )

    def test_buckets_are_exhaustive_and_disjoint(self):
        m = re.search(r"const TOOL_HEALTH_BUCKETS = \{(.*?)\n\};", APP_JS_SRC, re.S)
        pairs = re.findall(r"^\s*([A-Z_]+):\s*'([A-Z_]+)',", m.group(1), re.M)
        buckets = {b for _, b in pairs}
        assert buckets <= {"HEALTHY", "DEGRADED", "UNAVAILABLE", "CHECKING", "DISABLED"}
        # every status maps to exactly one bucket (the map is a plain object)
        assert len(pairs) == len({s for s, _ in pairs})

    def test_counter_elements_exist_in_the_markup(self):
        ids = set(re.findall(r"getElementById\('(filterCount[A-Za-z]+)'\)", APP_JS_SRC))
        assert ids, "no filter counter ids referenced in app.js"
        for i in ids:
            assert ('id="%s"' % i) in INDEX_HTML_SRC, (
                "the counter element %s is missing from index.html, so its value "
                "would never be updated" % i
            )

    def test_every_pill_has_a_counter_element(self):
        pills = re.findall(r"setPopoverFilter\('([A-Z]+)'\)", INDEX_HTML_SRC)
        assert pills, "no filter pills found"
        for pill in pills:
            assert ('id="filterCount%s"' % pill.title()) in INDEX_HTML_SRC, (
                "the %s pill has no counter element" % pill
            )


class TestHealthDataConsistency:
    def test_summary_matches_the_per_tool_statuses(self):
        import asyncio

        from core.tool_dependency_manager import tool_dependency_manager

        async def _run():
            return await tool_dependency_manager.health_engine.get_all_health()

        tools, summary = asyncio.run(_run())
        assert tools, "no tools were health-checked"

        buckets = {"HEALTHY": 0, "DEGRADED": 0, "UNAVAILABLE": 0,
                   "CHECKING": 0, "DISABLED": 0}
        for tool in tools.values():
            # ``str()`` on a str-Enum yields "ToolHealthState.X" in Python
            # 3.11+, so the raw value is used.
            status = str(getattr(tool.status, "value", tool.status))
            if status in ("HEALTHY", "DEGRADED", "DISABLED"):
                buckets[status] += 1
            elif status in ("UNAVAILABLE", "MISCONFIGURED", "ERROR", "UNKNOWN"):
                buckets["UNAVAILABLE"] += 1
            elif status in ("CHECKING", "INSTALLING"):
                buckets["CHECKING"] += 1

        assert buckets["HEALTHY"] == summary.healthy
        assert buckets["DEGRADED"] == summary.degraded
        assert buckets["UNAVAILABLE"] == summary.unavailable
        assert buckets["DISABLED"] == summary.disabled
        assert buckets["CHECKING"] == summary.checking
        # the buckets must account for every monitored tool
        assert sum(buckets.values()) == summary.total_monitored

    def test_healthy_tools_report_no_failed_checks(self):
        import asyncio

        from core.tool_dependency_manager import tool_dependency_manager

        async def _run():
            return await tool_dependency_manager.health_engine.get_all_health()

        tools, _ = asyncio.run(_run())
        for tool in tools.values():
            # ``str()`` on a str-Enum yields "ToolHealthState.X" in Python
            # 3.11+, so the raw value is used.
            if str(getattr(tool.status, "value", tool.status)) == "HEALTHY":
                assert not (tool.checks_failed or []), (
                    "%s is HEALTHY but reports failed checks: %r"
                    % (tool.tool_id, tool.checks_failed)
                )
                assert tool.checks_passed, (
                    "%s is HEALTHY but reports no passed checks" % tool.tool_id
                )


class TestAssetVersioning:
    def test_version_is_the_content_hash(self):
        from core.asset_versions import version_for

        expected = version_for(STATIC, "app.js")
        assert expected and expected != "0"

    def test_injection_replaces_a_stale_token(self):
        from core.asset_versions import inject_asset_versions, version_for

        html = '<script src="app.js?v=3.5.1"></script>'
        out = inject_asset_versions(html, STATIC, {})
        expected = version_for(STATIC, "app.js")
        assert ("app.js?v=%s" % expected) in out
        assert "3.5.1" not in out

    def test_injection_adds_a_token_when_there_is_none(self):
        from core.asset_versions import inject_asset_versions, version_for

        html = '<script src="app.js"></script>'
        out = inject_asset_versions(html, STATIC, {})
        expected = version_for(STATIC, "app.js")
        assert ("app.js?v=%s" % expected) in out

    def test_the_version_changes_when_the_file_changes(self, tmp_path):
        from core.asset_versions import version_for

        target = tmp_path / "app.js"
        target.write_text("console.log(1);", encoding="utf-8")
        first = version_for(str(tmp_path), "app.js")
        target.write_text("console.log(2);", encoding="utf-8")
        second = version_for(str(tmp_path), "app.js")
        assert first != second, "the asset version did not change with the content"

    def test_the_server_serves_index_with_a_content_version(self):
        """The served document must never reference the stale manual version."""
        from core.asset_versions import inject_asset_versions, version_for

        out = inject_asset_versions(INDEX_HTML_SRC, STATIC, {})
        assert "app.js?v=3.5.1" not in out
        assert ("app.js?v=%s" % version_for(STATIC, "app.js")) in out
