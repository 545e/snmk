# TESTING AND VERIFICATION MATRIX
## Measured 2026-11-07 (re-verified 2026-11-09/11 after the `51116f4` revert and reapplication)

> **Low-quality prior claims in this file (before this header) are superseded.** Only measured results appear below.

### 1. Test suite summary

- **Runner:** pytest, Python 3.12 (3.10/3.11 also available in CI config).
- **2026-11-09 full run (pre-revert tree):** 239 collected — **1 failed / 238 passed**. `test_all_85_agents` lost `fuzzer_agent` to a 60 s dispatch timeout under CPU starvation; dispatch timeout raised to 120 s → that test re-verified in isolation (PASS, 89 s); full re-run → **239 passed / 0 failed** (488.7 s).
- **2026-11-11 full run (post-revert, re-applied fixes):** `tests/test_e2e_local_scan::test_02_e2e_authorized_scan_execution` exceeded its fixed 52.5 s polling window under CPU starvation — **PASSED in isolation (55.3 s)**; the polling window was widened 35→90 iterations (same assertions) and the test re-run as part of the suite below.
- **Warnings:** 1 (Starlette TestClient deprecation).
- **What the suite proves and what it does not** is itemized in `docs/COMPLETE_AI_SYSTEM_INVENTORY.md` and `docs/IMPLEMENTATION_REPORT.md`. Dispatch completion (85/85) ≠ capability; no LLM round trip occurs without a provider key.

### 2. Key suites actually run here

| Test Module | Focus | Status |
|---|---|---|
| test_all_85_agents | 85-agent bounded dispatch completes | PASS (89 s) |
| test_ai_automation_and_operations | Workflow engine; honest `COMPLETED_PARTIAL` + real step statuses | PASS |
| test_cyber_kill_chain_suite | Kill chain correlation | PASS |
| test_v1_api_suite | /api/v1 incl. **live** CISA KEV / FIRST EPSS (verified reachable; 503 on failure) | PASS (11/11) |
| test_api_key_management_suite | Vault, rotation, masking | PASS |
| test_scope_policy | Allowlist/SSRF/lab/session-scoped dynamic authorization | PASS |
| test_system_status | Health endpoints report honest counts | PASS |
| test_e2e_local_scan | Spawns app on :8000, self-scan, report formats | PASS (tolerates slow hosts) |
| test_owasp_plugins_execution | OWASP plugin probes | PASS |
| test_rag_and_memory_engine | BM25 RAG + memory | PASS |
| test_vulnerabilities_and_findings | Finding lifecycle | PASS |

### 3. Known test-environment caveats
- This machine is CPU-starved; the suite takes 8–10 minutes. Time-sensitive tests use explicit margins; no assertions were weakened to achieve green.
- Live-feed tests (`cisa-kev`, `first-epss`) require outbound HTTPS; they assert schema/value sanity, not exact market data.
- The suite mutates the real `swa_data.db` (resets/creates some rows). A pre-audit backup is preserved at `backups/swa_data_preaudit_20261106.db`.

### 4. CI (GitHub Actions — `.github/workflows/ci.yml`)
Not executed from this machine. Workflow runs `pytest tests/ -v` on Ubuntu 3.10/3.11/3.12, macOS, Windows. Live-feed tests will depend on runner egress.

### 5. Browser / HTTP verification
Direct HTTP probes against the running app were executed (2026-11-09): `/health`, `/api/system/status` (honest HEALTHY/NOT_CONFIGURED counts), `/api/ai/status` (NOT_CONFIGURED, heuristic_fallback), `/api/ai-agents/usage` (real DB counts), `/api/agents/summary` (85 registered across 5 tiers), `/api/settings` (has_api_key:false, no plain-text secret), `/api/v1/ai/models/status` (HEURISTIC_FALLBACK), `/api/tools/registry`. Playwright+Chromium are installed but a headed/headless UI walkthrough was not executed this cycle.
