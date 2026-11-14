"""
Regression tests for the honesty and determinism improvements applied in
this pass.

Covered areas:

1. Tool registry backend handlers resolve to real callables
   (DSA-AI-09: the declared ``backend_handler`` was never resolved and the
   execute endpoint reported "OPERATIONAL / Executed handler ..." without
   executing anything).
2. The tool execution endpoint reports an honest status instead of a
   fabricated success envelope.
3. REA analysis produces a stable metadata contract whether or not the
   optional REA CLI is installed on the host.
4. The OWASP injection plugin selects probe parameters deterministically
   (DSA-CYB-02: ``list(set(...))`` made coverage PYTHONHASHSEED-dependent).
5. Kill-chain correlation surfaces corpus truncation instead of silently
   computing attack paths from an incomplete stage set (DSA-BE-19).
6. The scope policy resolves a hostname once per validation, refuses a name
   that maps to *any* restricted address, and bounds the session allowlist
   (DSA-CYB-06 / DSA-CYB-20).
"""

import asyncio
import json
import os
import socket
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.tool_registry import tool_registry
from core.tool_handler_resolver import (
    HandlerNotExecutable,
    HandlerNotResolvable,
    describe_handler,
    invoke_handler,
    resolve_handler,
)


class TestToolHandlerResolution(unittest.TestCase):
    """Every declared handler must point at something that actually exists."""

    def test_01_every_registered_handler_resolves(self):
        broken = []
        for tool in tool_registry.list_all():
            description = describe_handler(tool.backend_handler)
            if not description["resolved"]:
                broken.append((tool.id, tool.backend_handler, description["error"]))
        self.assertEqual(
            broken, [],
            f"Tool registry handlers that do not resolve to a callable: {broken}"
        )

    def test_02_resolve_handler_rejects_garbage(self):
        with self.assertRaises(HandlerNotResolvable):
            resolve_handler("not_a_module:whatever")
        with self.assertRaises(HandlerNotResolvable):
            resolve_handler("core.tool_registry:does_not_exist")
        # A resolvable but non-callable attribute is not a valid handler.
        with self.assertRaises(HandlerNotResolvable):
            resolve_handler("core.tool_registry:tool_registry._tools")
        # A missing "module:attribute" separator is rejected.
        with self.assertRaises(HandlerNotResolvable):
            resolve_handler("core.tool_registry.list_all")

    def test_03_describe_handler_never_raises(self):
        description = describe_handler("core.nope:nope")
        self.assertFalse(description["resolved"])
        self.assertIsNotNone(description["error"])

    def test_04_invoke_handler_binds_available_arguments(self):
        result = asyncio.run(
            invoke_handler(
                "core.tool_handler_resolver:_candidates_for",
                payload={"param_name": "target"},
            )
        )
        self.assertIn("target", result)

    def test_05_invoke_handler_reports_missing_arguments(self):
        with self.assertRaises(HandlerNotExecutable):
            asyncio.run(
                invoke_handler(
                    "core.kill_chain.db:save_finding",
                    payload={},
                )
            )

    def test_06_scanner_tools_are_executable_not_declarative(self):
        """The scanner registry entries must name a real execution method."""
        for tool in tool_registry.list_all():
            if tool.id.startswith("scanner_"):
                self.assertIn(
                    "ScannerIntegrations.",
                    tool.backend_handler,
                    f"{tool.id} does not point at a ScannerIntegrations method"
                )
                self.assertTrue(
                    describe_handler(tool.backend_handler)["resolved"],
                    f"{tool.id} handler does not resolve"
                )


class TestToolExecutionHonesty(unittest.TestCase):
    """The execute endpoint must not claim success for work it did not do."""

    def setUp(self):
        from fastapi.testclient import TestClient
        from web.server import app
        self.client = TestClient(app)

    def test_01_unknown_tool_is_rejected(self):
        resp = self.client.post(
            "/api/tools/definitely_not_a_tool_xyz/execute",
            json={"target": "127.0.0.1"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_02_execute_returns_a_status_field(self):
        """A registry-fallback tool must report an explicit status."""
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "sample.db"
            conn = sqlite3.connect(artifact)
            conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
            conn.commit()
            conn.close()

            resp = self.client.post(
                "/api/tools/websec_rea_engine/execute",
                json={
                    "target": str(artifact),
                    "options": {
                        "target_path": str(artifact),
                        "target_type": "sqlite",
                        "authorized": True,
                    },
                },
            )

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["status"], "COMPLETED")
        result = payload["result"]
        self.assertIn("status", result)
        self.assertIn("executed", result)
        # A completed execution must actually have run something.
        self.assertTrue(result["executed"])
        self.assertEqual(result["status"], "COMPLETED")
        # The handler really produced the artifact's contents.
        self.assertIn("users", result["result"]["metadata"]["tables"])

    def test_03_unresolvable_handler_is_reported_honestly(self):
        """A handler that cannot be resolved yields NOT_IMPLEMENTED."""
        from web.server import _execute_registry_handler

        class FakeMeta:
            id = "fake_tool"
            name = "Fake Tool"
            category = "soc"
            purpose = "testing"
            backend_handler = "core.does_not_exist:nope"

        result = asyncio.run(
            _execute_registry_handler(FakeMeta(), "127.0.0.1", {})
        )
        self.assertEqual(result["status"], "NOT_IMPLEMENTED")
        self.assertFalse(result["executed"])
        self.assertIn("reason", result)

    def test_04_missing_argument_is_reported_honestly(self):
        """A handler that needs more input yields NOT_EXECUTABLE."""
        from web.server import _execute_registry_handler

        meta = tool_registry.get("soc_report_generator")
        self.assertIsNotNone(meta)

        result = asyncio.run(
            _execute_registry_handler(meta, "127.0.0.1", {})
        )
        self.assertEqual(result["status"], "NOT_EXECUTABLE")
        self.assertFalse(result["executed"])
        self.assertIn("scan_id", result["reason"])

    def test_05_outer_status_reflects_inner_status(self):
        """The response envelope must not claim success for a failed tool."""
        resp = self.client.post(
            "/api/tools/soc_report_generator/execute",
            json={"target": "127.0.0.1", "options": {}},
        )
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["status"], "NOT_EXECUTABLE")
        self.assertEqual(payload["result"]["status"], "NOT_EXECUTABLE")
        self.assertFalse(payload["result"]["executed"])

    def test_06_registry_catalog_reports_handler_resolution(self):
        resp = self.client.get("/api/tools/registry")
        self.assertEqual(resp.status_code, 200)
        tools = resp.json()["tools"]
        self.assertGreater(len(tools), 0)
        for tool in tools:
            self.assertIn("handler_resolution", tool)
            self.assertTrue(
                tool["handler_resolution"]["resolved"],
                f"{tool['id']} declares an unresolvable handler",
            )


class TestREAStableContract(unittest.TestCase):
    """REA metadata must not depend on whether an external CLI is installed."""

    def setUp(self):
        from core.rea_engine import REAEngine
        self.engine = REAEngine()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _make_sqlite(self):
        path = os.path.join(self.temp_dir.name, "contract.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
        conn.execute("CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, action TEXT)")
        conn.commit()
        conn.close()
        return path

    def test_01_sqlite_contract_holds_without_the_cli(self):
        path = self._make_sqlite()
        with patch.object(self.engine, "get_binary_path", return_value=None):
            result = asyncio.run(
                self.engine.analyze(path, target_type="sqlite", authorized=True)
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "COMPLETED")
        metadata = result["metadata"]
        self.assertIn("tables", metadata)
        self.assertIn("users", metadata["tables"])
        self.assertIn("audit_logs", metadata["tables"])
        self.assertEqual(metadata["table_count"], 2)

    def test_02_sqlite_contract_holds_with_the_cli(self):
        """A present (or failing) CLI must not remove documented fields."""
        path = self._make_sqlite()

        # Simulate a CLI that is present but unusable for this target.
        with patch.object(self.engine, "get_binary_path", return_value="/nonexistent/rea"):
            result = asyncio.run(
                self.engine.analyze(path, target_type="sqlite", authorized=True)
            )

        self.assertTrue(result["success"], "A CLI failure must not fail the analysis")
        metadata = result["metadata"]
        self.assertIn("tables", metadata)
        self.assertIn("users", metadata["tables"])
        self.assertEqual(metadata["table_count"], 2)
        self.assertIn("rea_cli", metadata)
        self.assertEqual(metadata["rea_cli"]["status"], "UNAVAILABLE")

    def test_03_cli_result_is_merged_not_substituted(self):
        """CLI evidence is additive and never overwrites the native baseline."""
        path = self._make_sqlite()
        cli_payload = {
            "subject": {"digest": {"sha256": "deadbeef"}, "architecture": "x64"},
            "normalized_result": {
                "engine": {"name": "SQLite", "version": "3.54.0"},
                "schema": {
                    "tables": [{"name": "users"}],
                    "indexes": [],
                    "views": [],
                },
            },
        }

        async def fake_cli(*args, **kwargs):
            return cli_payload, None

        with patch.object(self.engine, "get_binary_path", return_value="/fake/rea"):
            with patch.object(self.engine, "_run_rea_cli", side_effect=fake_cli):
                result = asyncio.run(
                    self.engine.analyze(path, target_type="sqlite", authorized=True)
                )

        metadata = result["metadata"]
        self.assertEqual(metadata["table_count"], 2)
        self.assertIn("audit_logs", metadata["tables"])
        self.assertEqual(metadata["rea_cli"]["status"], "OK")
        self.assertEqual(metadata["rea_cli"]["result"], cli_payload)

    def test_04_cli_json_parser_handles_progress_lines(self):
        from core.rea_engine import REAEngine

        noise = '{"rea_progress":{"phase":"analyze","completed":0,"total":1}}\n'
        payload = '{"evidence_id":"ev_1","normalized_result":{}}\n'
        parsed = REAEngine._parse_cli_json(noise + payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["evidence_id"], "ev_1")

        self.assertIsNone(REAEngine._parse_cli_json("not json at all"))
        self.assertIsNone(REAEngine._parse_cli_json(""))

    def test_05_javascript_exports_are_extracted(self):
        """CommonJS ``module.exports = {...}`` symbols must be discovered."""
        js_path = os.path.join(self.temp_dir.name, "bundle.js")
        with open(js_path, "w", encoding="utf-8") as handle:
            handle.write(
                "const API_KEY = 'dummy';\n"
                "function authenticateUser(t) { return t; }\n"
                "module.exports = { authenticateUser, openAdminShell };\n"
            )

        with patch.object(self.engine, "get_binary_path", return_value=None):
            result = asyncio.run(
                self.engine.analyze(js_path, target_type="javascript", authorized=True)
            )

        metadata = result["metadata"]
        self.assertIn("authenticateUser", metadata["exported_symbols"])
        self.assertIn("openAdminShell", metadata["exported_symbols"])


class TestOWASPProbeDeterminism(unittest.TestCase):
    """Probe parameter selection must not depend on PYTHONHASHSEED."""

    def test_01_ranking_is_deterministic_and_order_preserving(self):
        from plugins.owasp_plugins import _rank_probe_parameters

        params = ["zeta", "id", "alpha", "id", "search"]
        ranked = _rank_probe_parameters(params)
        self.assertEqual(len(ranked), len(set(ranked)), "duplicates must be removed")
        self.assertEqual(ranked[0], "id", "highest-priority parameter comes first")
        self.assertEqual(ranked[1], "search")
        # Equal-ranked / unknown parameters keep their declaration order.
        self.assertLess(ranked.index("zeta"), ranked.index("alpha"))
        self.assertEqual(_rank_probe_parameters(params), ranked)

    def test_02_selection_is_independent_of_input_hash_order(self):
        from plugins.owasp_plugins import _rank_probe_parameters

        a = ["id", "q", "search", "page"]
        b = list(reversed(a))
        self.assertEqual(_rank_probe_parameters(a), _rank_probe_parameters(b))

    def test_03_ranking_covers_known_priority_names(self):
        from plugins.owasp_plugins import _PROBE_PARAMETER_PRIORITY, _rank_probe_parameters

        ranked = _rank_probe_parameters(list(_PROBE_PARAMETER_PRIORITY))
        self.assertEqual(ranked, list(_PROBE_PARAMETER_PRIORITY))


class TestKillChainTruncation(unittest.TestCase):
    """Correlating a truncated corpus must be visible, not silent."""

    def test_01_count_findings_is_available(self):
        from core.kill_chain.db import count_findings

        total = count_findings()
        self.assertIsInstance(total, int)
        self.assertGreaterEqual(total, 0)

    def test_02_corpus_loader_reports_truncation(self):
        from core.kill_chain.engine import kill_chain_engine

        corpus = kill_chain_engine.load_correlation_corpus()
        self.assertIn("findings", corpus)
        self.assertIn("truncation", corpus)
        self.assertIn("loaded", corpus["truncation"]["findings"])
        self.assertIn("total", corpus["truncation"]["findings"])
        self.assertIn("truncated", corpus["truncation"]["findings"])
        self.assertFalse(
            corpus["any_truncated"],
            "A small test corpus must not be reported as truncated"
        )

    def test_03_correlate_endpoint_sets_truncation_header_when_truncated(self):
        from fastapi.testclient import TestClient
        from web.server import app
        from core.kill_chain.engine import kill_chain_engine

        client = TestClient(app)

        original = kill_chain_engine.load_correlation_corpus

        def truncated_corpus():
            corpus = original()
            corpus["truncation"]["findings"]["truncated"] = True
            corpus["any_truncated"] = True
            return corpus

        with patch.object(
            kill_chain_engine, "load_correlation_corpus", side_effect=truncated_corpus
        ):
            resp = client.post("/api/kill-chain/correlate")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("x-snmk-correlation-truncated"), "true")
        self.assertIn("x-snmk-correlation-findings-total", resp.headers)


class TestScopePolicyHardening(unittest.TestCase):
    """Scope enforcement must be strict, single-resolution and bounded."""

    def test_01_hostname_is_resolved_once_per_validation(self):
        from core import scope_policy as sp

        calls = []
        real = socket_getaddrinfo = sp.socket.getaddrinfo

        def counting_getaddrinfo(*args, **kwargs):
            calls.append(args[0] if args else kwargs.get("host"))
            return real(*args, **kwargs)

        with patch.object(sp.socket, "getaddrinfo", counting_getaddrinfo):
            sp.validate_tool_target(
                "example.com", tool_id="ports"
            )

        # The hostname must not be resolved twice for one validation.
        self.assertLessEqual(
            len(calls), 1,
            f"Expected at most one DNS resolution, got {len(calls)}: {calls}"
        )

    def test_02_every_resolved_address_is_checked(self):
        """A name resolving to a private IP must be refused, whichever order."""
        from core import scope_policy as sp

        fake = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        with patch.object(sp.socket, "getaddrinfo", return_value=fake):
            reason = sp._restricted_reason("rebind.example")
        self.assertIsNotNone(
            reason,
            "A name with a private address among its answers must be refused"
        )

    def test_03_session_allowlist_is_bounded(self):
        from core.scope_policy import ScopePolicy

        policy = ScopePolicy()
        policy.allowed_domains = {"example.com"}
        policy._session_domains.clear()

        for index in range(ScopePolicy.MAX_SESSION_DOMAINS + 50):
            policy._add_session_domain(f"host{index}.example.com")

        self.assertLessEqual(
            len(policy._session_domains), ScopePolicy.MAX_SESSION_DOMAINS
        )
        # The most recent entry must survive.
        self.assertIn(
            f"host{ScopePolicy.MAX_SESSION_DOMAINS + 49}.example.com",
            policy._session_domains,
        )
        # The oldest must have been evicted.
        self.assertNotIn("host0.example.com", policy._session_domains)

    def test_04_session_domains_do_not_leak_into_the_persisted_allowlist(self):
        from core.scope_policy import ScopePolicy

        policy = ScopePolicy()
        policy.allowed_domains = {"example.com"}
        policy._session_domains.clear()
        policy._add_session_domain("session-only.example.com")

        self.assertNotIn("session-only.example.com", policy.allowed_domains)
        self.assertTrue(policy._matches_allowlist("session-only.example.com"))

    def test_05_unresolvable_hostname_is_refused_not_passed(self):
        """A name that does not resolve must fail closed."""
        from core import scope_policy as sp

        def failing_getaddrinfo(*args, **kwargs):
            raise socket.gaierror("name does not resolve")

        with patch.object(sp.socket, "getaddrinfo", failing_getaddrinfo):
            result = sp.scope_policy.validate_target("definitely-not-a-real-host.invalid")

        self.assertFalse(
            result.is_allowed,
            "An unresolvable target must not be treated as validated"
        )
        self.assertEqual(result.error_code, "DNS_RESOLUTION_FAILURE")

    def test_06_pre_resolved_addresses_are_reused(self):
        """Supplied addresses are used instead of a second resolution."""
        from core import scope_policy as sp
        from core.scope_policy import ScopePolicy

        policy = ScopePolicy()
        policy.allowed_domains = {"example.com"}

        with patch.object(
            sp.socket,
            "getaddrinfo",
            side_effect=AssertionError("hostname was resolved twice"),
        ) as mocked:
            result = policy.validate_target(
                "example.com",
                resolved_ips=["93.184.216.34"],
            )

        self.assertTrue(result.is_allowed)
        self.assertEqual(mocked.call_count, 0)


if __name__ == "__main__":
    unittest.main()
