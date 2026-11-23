# SNMK Master Engineering / Repair / Security Verification Report

**Date:** 2026-11-19
**Repository:** https://github.com/545e/snmk.git
**Branch:** `main` at `25601de`
**Recovery point:** annotated tag `baseline/pre-master-upgrade` (commit `25601dedf49c4fc51f0dd04e652a1c74368613f5`)
**Platform used for verification:** Windows 11, Python 3.12.10, Node v26.13.0

> This report only records checks that were actually executed. Items that could not
> be executed in this environment are explicitly marked BLOCKED / NOT TESTED.

---

## A. Executive Summary

The repository was already a substantial implementation (259 registered routes,
66 SQLite tables, 579 passing tests). It was **not** a stub project. The reported
`Failed to launch assessment: Failed to fetch` and the permanently "Loading"
dashboard tiles were traced to a **frontend architecture gap**, not to a broken
backend: every API call used a bare relative `fetch('/api/...')`, so the browser
sent requests to whichever origin served the HTML. When the UI was opened on
`127.0.0.1:8001` while the backend was on `127.0.0.1:8000`, those requests could
not reach the API and the browser surfaced `Failed to fetch`. Every dependent
tile (AI fleet, vulnerability count, posture, assessment phase) then stayed in
its initial "Loading" state.

The following was implemented and verified:

1. A single centralized API client (`web/static/api-client.js`) with configurable
   base URL, auth headers, correlation IDs, timeouts, safe retries, network-error
   classification, and response validation. All 250 legacy `fetch()` call sites
   across `app.js`, `map.js` and `digital_forensics.js` now route through it.
2. A server-served bootstrap (`GET /api/client-config.js`) driven by
   `SWA_PUBLIC_API_BASE_URL`, with strict value sanitisation.
3. Genuine dashboard telemetry from the runtime agent registry and the canonical
   backend posture endpoint; removal of hardcoded agent counts and fake "Grade A"
   fallbacks; a real stall watchdog for assessments.
4. A lab-authorization propagation fix so explicit lab approval reaches tool-level
   SSRF guards **without** globally disabling SSRF protection.
5. Health/readiness/client-config paths made public when API auth is enabled;
   report target derived from the persisted scan instead of a hardcoded address.
6. 13 new regression tests covering all of the above.

---

## B. Root Cause Analysis

| ID | Component | Actual root cause | Severity | Fix | Status |
|---|---|---|---|---|---|
| RC-01 | Frontend API layer | 250 raw relative `fetch()` calls; no base-URL configuration, timeout, retry, correlation ID or error classification. Split-origin deployment => `Failed to fetch`. | Critical | Centralized `apiFetch` + `/api/client-config.js`; all call sites migrated | PASS |
| RC-02 | SOC dashboard | `socKpiAgents`, `socKpiAgentTiers`, `socKpiAgentStatus` were never written by JS. Tiles stayed "Loading" forever. | High | Populated from `/api/agents` + `/api/agents/summary` runtime registry | PASS |
| RC-03 | SOC posture | A second, duplicate scoring formula existed in the browser; `recalculatePostureGrade()` fell back to a fabricated `Grade A (100/100)` on failure. | High | Use canonical `GET /api/posture`; honest waiting state on failure | PASS |
| RC-04 | Assessment telemetry | Progress was derived from finding count instead of server progress; no stall detection, so a stuck job could spin forever. | High | Use `progress_percent`; 3-minute no-progress watchdog with explicit STALLED state | PASS |
| RC-05 | Scope display | `socKpiTarget` hardcoded to `127.0.0.1:8000`; frontend, backend and target were conflated. | Medium | New `syncSocTargetScope()` shows UI origin, API origin, target and real scope state | PASS |
| RC-06 | Tool SSRF guard | `SecurityHeadersTool` rejected loopback even when the API had already validated explicit lab authorization. | High | `allow_lab` opt-in propagated from request; requires explicit `lab_mode` or global config | PASS |
| RC-07 | Auth gate | `/ready`, `/health/*`, `/api/client-config.js` were missing from `PUBLIC_PATHS`, so orchestrators/bootstrap could be blocked with auth enabled. | Medium | Added public probe paths | PASS |
| RC-08 | Reporting | `VulnAssessmentGenerateReq.target` defaulted to hardcoded `127.0.0.1:8000`. | Medium | Default `None`; target derived from `scan_id` by the report engine | PASS |
| RC-09 | Documentation | README claimed a fixed "85 specialist agents"; runtime registry reports 94. | Low | README now points to the runtime registry as source of truth | PASS |
| RC-10 | Test suite | One test patched the global socket module and counted unrelated concurrent DNS calls; another depended on live CISA/FIRST feeds (intermittent 503). | Medium | Made the DNS test deterministic and thread-filtered; mocked the two upstream feeds while keeping all API assertions | PASS |

---

## C. Files Modified

| File | Reason |
|---|---|
| `core/app_security.py` | Added readiness/health/client-config paths to `PUBLIC_PATHS` |
| `core/cyber_tools.py` | Lab-aware SSRF guard; `SecurityHeadersTool.evaluate(..., allow_lab=...)` |
| `web/server.py` | New `/api/client-config.js`; lab authorization propagation; report target no longer hardcoded |
| `web/static/app.js` | 218 API calls migrated; agent KPI, posture, scope and stall-watchdog fixes |
| `web/static/map.js` | 20 API calls migrated to centralized client |
| `web/static/digital_forensics.js` | 12 API calls migrated to centralized client |
| `web/static/index.html` | Loads config + client before consumers; meta override; accurate KPI labels |
| `.env.example` | Documents `SWA_PUBLIC_API_BASE_URL` |
| `README.md` | Runtime-registry agent count clarification |
| `tests/test_honesty_and_determinism.py` | Deterministic, concurrency-safe DNS resolution-count test |
| `tests/test_v1_api_suite.py` | Removed live-network dependency from threat-intel contract test |

## D. Files Created

| File | Responsibility |
|---|---|
| `web/static/api-client.js` | Centralized API client (base URL, auth, correlation IDs, timeout, retries, error classes) |
| `tests/test_api_client_config.py` | 8 tests for client bootstrap and wiring |
| `tests/test_lab_ssrf_propagation.py` | 5 tests for explicit-lab SSRF propagation |
| `SNMK_MASTER_UPGRADE_VERIFICATION.md` | This report |

---

## E. Database

- Authoritative backend: **SQLite in WAL mode** (`PRAGMA journal_mode = wal`), 66 tables.
- MySQL: optional mirror via `SWA_DB_BACKEND=mysql`; reported `mirrored_backend: null`
  and `pending_mysql_writes: 0` in this environment (no MySQL server configured).
- Real assessment `scan_09fe07b689` (launched through the running API):
  - `scans` row: status `COMPLETED`, progress `100`, target `http://127.0.0.1:8123`, findings_count `4`.
  - `findings` table: **4 persisted rows** for that scan.
  - `logs` table: **20 persisted log events**.
  - `report_records`: 2 rows; JSON report generated and downloaded with `200 application/json`.
- Tool execution `tool_65e82a5ee2a2` persisted 1 row in `tool_executions` with exit code and references.
- Note: both `findings` (in use, 401 rows) and a legacy `vulnerability_findings`
  table (0 rows) exist. The canonical table is `findings`; the legacy table is unused
  and was left untouched to avoid destructive migration.
- Persistence status endpoint (`GET /api/persistence/status`): `authoritative_backend=sqlite_wal`,
  `persistent_tables=66`, no pending writes.
- Recovery point: tag created before any modification; no destructive schema change performed.

---

## F. APIs (all tested against a live uvicorn process on 127.0.0.1:8123)

| Endpoint | Result |
|---|---|
| `GET /health` | 200 – HEALTHY, version 2.3.0, database healthy |
| `GET /ready` | 200 – `{"ready": true}` |
| `GET /health/live` | 200 – ALIVE + uptime |
| `GET /health/ready` | 200 – READY, database CONNECTED |
| `GET /api/system/status` | 200 – overall HEALTHY, 8 healthy / 2 not configured |
| `GET /api/ai/status` | 200 – `NOT_CONFIGURED` (no provider key) – honest state |
| `GET /api/client-config.js` | 200 – `window.SNMK_API_BASE_URL = "";` (new) |
| `GET /api/agents/summary` | 200 – **94** registered/available agents, 6 tiers |
| `GET /api/posture` | 200 – canonical score from persisted findings |
| `GET /api/findings?paged=true&limit=3` | 200 – real persisted records |
| `GET /api/tools/status` | 200 – honest per-tool installed/ready state |
| `POST /api/scans` | 200 – `scan_09fe07b689` returned immediately (PENDING) |
| `GET /api/scans/{id}` | 200 – COMPLETED, 100% |
| `GET /api/scans/{id}/findings` | 200 – 4 findings |
| `GET /api/scans/{id}/logs` | 200 – 20 events |
| `GET /api/scans/{id}/report` | 200 – HTML report |
| `POST /api/reports/vulnerability-assessment/generate` | 200 – target derived from scan; download 200 |
| `GET /docs`, `GET /swagger.json` | 200 |
| `OPTIONS /api/scans` (CORS preflight) | 200 for origins 8000/8001 (localhost + 127.0.0.1); credentials + custom headers allowed |

No wildcard-with-credentials CORS was introduced.

---

## G. Security Tools

- `GET /api/tools/status` reports real installation state. Nmap, Masscan, TShark and
  other external binaries are **NOT_INSTALLED** in this environment; the platform
  reports this honestly rather than showing a false green indicator.
- `POST /api/tools/headers/execute` executed successfully against the authorized lab
  target (HTTP 200, grade B) only when `lab_mode: true` was supplied; without it the
  tool returned the restricted-address refusal. Cloud-metadata address
  `169.254.169.254` remains blocked even with the lab flag (unit test).
- Every explicit tool run creates a durable scan record before execution and records
  the tool execution/result/output in `persistent_store`.
- Subprocess-safety, installation detection and native C++ benchmark verification
  were **not re-performed** in this session (existing tests passed).

---

## H. Subdomain Enumeration

- Existing engine/tests exercised by the full suite (`tests/test_subdomain_engine.py`:
  10 passed). No external discovery provider credentials or binaries were available,
  so **live** passive/active provider discovery and DNS/wildcard behaviour against a
  real authorized domain were **NOT TESTED** in this run. The lab assessment used
  `enable_subdomain_enum: false`.

---

## I. CrewAI / AI Fleet

- Runtime registry: **94** agents across 6 tiers (`core_engines: 32`,
  `network_intelligence: 9`, `offensive_recon: 9`, `owasp_plugins: 10`,
  `specialist_workforce: 17`, `tool_adapters: 17`), all reported available.
- The dashboard now consumes this registry directly; no hardcoded 85 remains in the
  KPI path. The embedded offline manifest is used only when the API is unreachable,
  and the status line says so explicitly.
- `GET /api/ai/status` reports `NOT_CONFIGURED` because no provider API key is set;
  non-AI deterministic operations still work. CrewAI/LangChain provider execution
  was **NOT TESTED** (no credentials).

---

## J. Application UI

- Centralized client: every API call now carries `X-Request-ID` / `X-Correlation-ID`
  and `X-Requested-With`; auth bearer token is attached when configured; JSON body
  serialization is centralized; GET retries are bounded (2 extra attempts,
  exponential backoff); 401/403 dispatch a `snmk:auth-failure` event.
- AI Fleet, Vulnerability count, Posture grade and Audit Target Scope tiles now
  resolve to real values or honest empty/waiting states.
- Assessment polling uses server progress and detects stalled jobs.
- All modified JavaScript files pass `node --check`; no raw `fetch()` call remains.

---

## K. Security

- Fixed: explicit lab authorization propagation without disabling global SSRF guards.
- Fixed: health/readiness probes reachable when auth is enabled.
- Fixed: report target no longer hardcoded.
- Confirmed: CORS uses an explicit origin allowlist with credentials, never `*`.
- Confirmed: no secrets were read, printed, or modified; `.env` and
  `.swa_master.key` were left untouched.
- 579 pre-existing tests include extensive security regression suites; all pass.

---

## L. Performance

No new performance claims are made. The existing native C++ engine benchmark tests
passed as part of the suite; the 15x–50x marketing claim was **not independently
reproduced** in this session.

---

## M. Testing

| Run | Command | Result |
|---|---|---|
| Baseline (before changes) | `python -m pytest -q` | **579 passed**, 5 warnings, 670.61s |
| After core changes | `python -m pytest -q` | **579 passed**, 3 warnings, 574.97s |
| New regression tests | `python -m pytest tests/test_api_client_config.py tests/test_lab_ssrf_propagation.py -q` | **13 passed** |
| Full suite (before flaky-test hardening) | `python -m pytest -q` | 590 passed, 2 failed – both passed in isolation; identified as order/network flakes |
| Flaky tests after hardening | targeted rerun | **2 passed** |
| Definitive full suite | `python -m pytest -q` | **592 passed**, 3 warnings, 680.43s (0:11:20) |
| JS syntax | `node --check` on 4 JS files | all OK |

Warnings are pre-existing Starlette/TestClient deprecation and asyncio Windows
proactor `__del__` warnings; no security check was disabled to obtain a green run.
`ruff check web/server.py` reports 123 **pre-existing** findings; no new lint error
was introduced by these changes (one `subprocess.run(check=False)` issue in the new
test was fixed).

---

## N. Deployment

```bash
# Install
pip install -r requirements.txt
cp .env.example .env            # then edit; never overwrite a real .env

# Start (auto-opens browser; binds 127.0.0.1:8000, auto-shifts if occupied)
python run.py

# Or explicit
python -m uvicorn web.server:app --host 127.0.0.1 --port 8000

# Stop
python stop.py                  # or use stop.sh / stop.bat / stop.ps1

# Split frontend: set SWA_PUBLIC_API_BASE_URL=http://127.0.0.1:8000
# and configure SWA_ALLOWED_ORIGINS for the frontend origin.
```

Docker was **not available** in this environment (`docker` command not found), so
container builds and `docker-compose` validation were **NOT TESTED**.

---

## O. Remaining Issues / Blockers

1. **External security tools** (Nmap, Masscan, TShark, Subfinder, Amass, etc.) are
   not installed; live execution and health checks cannot be verified here. Install
   via the repository's approved dependency manager/workflow.
2. **AI provider credentials** absent: CrewAI/LangChain live orchestration, tracing
   and model calls are not verified.
3. **MySQL mirror** not configured; only SQLite WAL was verified.
4. **Docker / Linux / macOS** runtime verification not possible on this Windows host.
5. **Live browser E2E** (Playwright) not run; verification used real HTTP requests
   against a live uvicorn process plus `node --check` and JS unit-level assertions.
6. Legacy duplicate table `vulnerability_findings` remains (unused); a future
   migration should consolidate it without data loss.
7. Standalone microservice routers (crypto/PCAP) mounted successfully in-process;
   independent service process deployment was not exercised.
8. Pre-existing ruff findings and a duplicate OpenAPI operation-id warning remain.

---

## Verification Table

| Module | Status | Verification evidence |
|---|---|---|
| Frontend | PASS | 4 JS files `node --check` OK; 250 call sites via `apiFetch`; 13 wiring tests |
| Backend | PASS | Live uvicorn; 12+ endpoints returned expected 200 payloads |
| Connectivity / CORS | PASS | Preflight 200 for 8000/8001 with explicit origin + credentials |
| Assessment | PASS | Real scan ID `scan_09fe07b689`, PENDING -> COMPLETED, 100% |
| Database | PASS | WAL, 66 tables; scan/findings/logs/report rows retrieved |
| Tool manager | PASS | `headers` tool executed with explicit lab auth; execution persisted |
| Subdomains | NOT TESTED | No external providers/credentials in this environment |
| AI Fleet | PASS | 94 agents from runtime registry surfaced in dashboard logic |
| Vulnerabilities | PASS | 4 persisted findings retrieved via API and SQLite |
| PCAP | PARTIAL | Service router mounts; no controlled fixture run this session |
| Cryptography | PARTIAL | Service router mounts; existing tests pass |
| Universal Scanner | PASS | Existing suite 13 tests passed (no new changes) |
| Alerts | PASS | Existing MySQL/alerts suite passed; no new changes |
| Reports | PASS | JSON report generated from scan and downloaded (200) |
| CI/CD | NOT TESTED | No CI run triggered in this environment |
