# TESTING AND VERIFICATION MATRIX
## Audited by execution — 2026-11-07, re-verified 2026-11-09

> **Currency note:** numbers below were re-measured by running the suite, not copied from prior documentation. Claims of "100% coverage" elsewhere in this repository's docs are marketing, not measurement.

### 1. Test Suite Summary (re-measured 2026-11-09)

- **Test files:** 32 (31 `test_*.py` + `tests/e2e/rt_harness.mjs` Node harness not run by pytest) + `tests/test_all_85_agents.py` added by a concurrent session (2026-11-08).
- **Total collected:** 239 items.
- **2026-11-09 run 1:** **1 failed, 238 passed** (455 s). Failure: `tests/test_all_85_agents.py::test_all_85_agents_execute_and_complete` — `assert 84 == 85` (`fuzzer_agent` exceeded the 60 s per-agent dispatch timeout under suite load; standalone dispatch takes ~36 s).
- **Fix:** per-agent dispatch timeout in `core/agent_registry.execute_all_85_agents` raised 60 s → 120 s (dispatch logic otherwise unchanged). Targeted re-run of the failing test: **PASS in 89 s**.
- **2026-11-09 run 3 (full suite, authoritative):** **239 passed, 0 failed (488.7 s)**. Note the live KEV/EPSS tests now exercise the real feeds; losing egress will fail those two rather than return canned data.
- **Warnings:** 1 (Starlette TestClient deprecation).

### 2. What the tests actually prove (and what they don't)

PASS here means "assertions executed successfully on this machine", not "production-certified". Notably:
- `test_all_85_agents` asserts every manifest completes a dispatch — dispatch completeness is **not** proof that any agent performed meaningful LLM reasoning. Tier-4 handlers report canned-but-honest engine states; tier-1 specialists compute DB aggregates; no LLM round trip occurs without a provider key.
- Threat-intel tests now hit the **live** CISA KEV JSON feed (verified 2026-11-09: catalog 2026.11.06, 1769 entries) and the **live** FIRST EPSS API (CVE-2021-44228: epss 0.99999). If this machine loses egress, these two tests fail rather than return canned data.
- `test_03_execute_workflow_on_authorized_target` was updated by us (2026-11-07) to assert the **honest** `COMPLETED_PARTIAL` status and real per-step statuses (scope_check SUCCESS, risk_analysis SUCCESS×2, report_gen NOT_EXECUTED) instead of the previous fake `COMPLETED`. The seeded workflow's `agent_id`s were also corrected to registered agents.

### 3. Test Modules (as collected by pytest)

| Test Module | Focus | Status |
|---|---|---|
| test_ai_automation_and_operations | Workflow engine (honest statuses) | 6 PASS |
| test_ai_training_and_evaluation | Training-simulation + regex classifier eval | 5 PASS |
| test_all_85_agents | 85-agent bounded dispatch completes | FAIL→PASS (timeout fix) |
| test_all_tools_integration | Multi-tool pipeline against lab target | 3 PASS |
| test_api_and_dashboard | Dashboard/settings/tools API | 8 PASS |
| test_api_key_management_suite | Vault, rotation, masking | 8 PASS |
| test_cyber_deploy | Deployment lifecycle | 4 PASS |
| test_cyber_export | SARIF/PDF/HTML exports | 6 PASS |
| test_cyber_kill_chain_suite | Kill-chain correlation/incidents | 20 PASS |
| test_cyber_test | Synthetic vectors | 4 PASS |
| test_data_management | Backups, WAL | 5 PASS |
| test_deployment_readiness | Acceptance checklist | 5 PASS |
| test_e2e_local_scan | Spawns app on :8000, self-scan, report formats | 2 PASS |
| test_enterprise_platform | Enterprise API incl. report engine | 9 PASS |
| test_expanded_cyber_coverage | Multi-vector probes | 17 PASS |
| test_gen3_navigation_acceptance | SPA view isolation | 10 PASS |
| test_generation2_security_and_integrity | SSRF/scope/sanitization | 10 PASS |
| test_integrations_and_ai_models | Adapters, model registry | 5 PASS |
| test_llm_security_testing | 12-vector LLM harness | 3 PASS |
| test_owasp_plugins | Plugin logic | 3 PASS |
| test_owasp_plugins_execution | Plugin execution | 5 PASS |
| test_rag_and_memory_engine | BM25 RAG + memory store | 4 PASS |
| test_rea_engine | REA native path | 7 PASS |
| test_report_engine | Report compiler | 16 PASS |
| test_scanner_integrations | Tool adapters (detection truth) | 9 PASS |
| test_scope_policy | Allowlist/SSRF/lab | 10 PASS |
| test_subdomain_engine | DNS/TLS SAN | 10 PASS |
| test_system_status | Health/status endpoints | 12 PASS |
| test_tool_registry | Tool metadata | 5 PASS |
| test_v1_api_suite | /api/v1 routes (KEV/EPSS live) | 11 PASS |
| test_vulnerabilities_and_findings | Finding lifecycle | 16 PASS |

### 4. CI Pipeline (GitHub Actions — `.github/workflows/ci.yml`)

- Not executed from this audit (no workflow runs triggered by us).
- CI runs `pytest tests/ -v` on Ubuntu 3.10/3.11/3.12, macOS 3.12, Windows 3.12. Note: the live-feed threat-intel tests will depend on runner egress there.

### 5. Browser / HTTP verification

Performed by direct HTTP probes against the running app and by Playwright (Chromium) — see `docs/IMPLEMENTATION_REPORT.md § L` and § H for measured results.
