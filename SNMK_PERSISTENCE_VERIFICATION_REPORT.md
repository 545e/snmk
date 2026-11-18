# SNMK — Persistence, Discovery & Honesty Remediation Report

Date: 2026-11-18
Branch: `enterprise/platform-master-pass`
Scope: repository audit + targeted repair of the three non-negotiable requirements
(permanent storage, multi-source subdomain discovery, real tool execution
monitoring) plus removal of fabricated data.

---

## 1. Repository audit (summary)

The repository is **not** a React/Vite application. It is a FastAPI application
(`web/server.py`, ~9k lines) serving a vanilla-ES6 single-page app
(`web/static/index.html` + `app.js`) with ~400 backend routes across 7 routers.

| Area | Actual state found |
|---|---|
| Primary database | **SQLite WAL** (`core/database.py`, 36 tables). Real persistence. |
| MySQL | Opt-in telemetry only (`core/mysql_adapter.py`, `core/mysql_database.py`). **No data-write methods** in `mysql_database.py`. No server configured. |
| Alembic | Scaffolding only — `migrations/env.py` existed, **no revision scripts**. |
| Subdomain engine | Real implementation (`agents/amass_engine.py`): 10 passive OSINT feeds, DNS wordlists, AltDNS, native C++ prober. BUT the REST endpoint returned two **hardcoded fake** subdomains for loopback and **never persisted anything**. |
| Tool monitoring | Four separate registries with inconsistent state models; tool execute endpoint did not persist execution records. |
| CrewAI | Two adapters: an honest `crew_coordinator` (direct mode) and a `crewai_adapter` that returned fabricated `"Executed task successfully"` output with no tool invocation. CrewAI package not installed. |
| Frontend | Mostly real API calls, but static KPIs (434 findings, 85 agents, 186 scans, 4 ms latency, a public IP) were fabricated; two dead handlers; one dead report-export endpoint. |
| Tests | 559 collected at baseline. Historical reports claimed 55/79/151/159/465/485 passes — all inconsistent with the code. |

### Root causes

1. **No durable write path for subdomain/tool results** — the endpoint returned data to the browser and dropped it.
2. **MySQL was designed as telemetry, not storage** — no writes, no outbox, no truthful failure signalling.
3. **Fabrication paths** — loopback subdomains, synthetic CrewAI output, hardcoded LLM fallback, no-op universal-scanner "CrewAI assessment", invented dashboard statistics.
4. **Pre-existing test failures (22)** — chiefly a `datetime` import defect in `core/alert_manager.py` that surfaced only in full-suite order, and invalid `ScanProfile` values.

---

## 2. Changes made

### Created

| File | Purpose |
|---|---|
| `core/persistent_store.py` | Durable write layer: short idempotent transactions, parameterized SQL, SQLite-authoritative + optional MySQL mirror, `PERSISTED`/`LOCAL_ONLY`/`PENDING`/`FAILED` states, durable outbox with retry, retrieval APIs. |
| `tests/test_persistent_store.py` | 12 tests covering schema, dedup, first/last-seen preservation, all record types, MySQL failure → PENDING, outbox recovery, restart-equivalent reads, singleton, no fake loopback data, measured table count. |
| `migrations/versions/0001_durable_persistence_schema.py` | Alembic revision creating the MySQL mirror tables and extending `scans`. |
| `requirements-enterprise.txt` | Optional SQLAlchemy / PyMySQL / Alembic dependencies (default deployment needs none). |
| `SNMK_PERSISTENCE_VERIFICATION_REPORT.md` | This report. |

### Modified (core behaviour)

- `web/server.py`
  - `/api/tools/subdomains` and `/api/recon/amass`: removed fabricated loopback assets; IP literals now return an honest zero-result no-op with a `note`, and are still persisted. Real domains persist each discovered subdomain with source, type, DNS status, IP, CNAME, confidence and verification timestamp; persist tool execution, result, report reference, status and audit events.
  - `/api/tools/{tool_id}/execute`: creates a scan record before execution, records real status/exit code/start/end/arguments, and records `FAILED` + error on exceptions.
  - Added read APIs: `GET /api/subdomains[/{scan_id}]`, `GET /api/scans/{scan_id}/results|/tools|/reports`, `GET /api/persistence/status`, `POST /api/persistence/outbox/flush`, `GET /api/reports/export` (JSON/CSV from persisted data).
  - `/api/database/status`: table count measured from `sqlite_master` instead of hardcoded 54; `primary_database` truthfully reported as `sqlite_wal`.
- `core/crewai_adapter.py`: task results now explicitly state `execution_mode: synthetic_planning`, `evidence: none; no tool invocation`, `tools_executed: []` — no fabricated tool output.
- `core/langchain_adapter.py`: LLM failure returns an explicit no-analysis message instead of invented "Zero credentials exposed, Latency: 42ms".
- `core/universal_scanner.py`: removed the no-op `crew.kickoff` that claimed an assessment never performed; stage now "Correlating findings from scanner evidence".
- `web/static/index.html` + `app.js`: removed fabricated KPI values (404 findings, 85 agents, 186 scans, 4 ms, public IP) in favour of `—`/loading placeholders; wired previously undefined `switchProject` and `addDataSourceModal` handlers.
- `tests/test_mysql_and_alerts.py`: table-count assertion now compares against the live schema instead of the fabricated literal 54.

---

## 3. Verification evidence

### Commands actually executed

- `python -m pytest tests/ -q --ignore=tests/e2e_map_browser_test.py` (baseline): **537 passed / 22 failed**.
- Same command with datetime probe after repairs: **569 passed / 0 failed / 3 warnings** (7m42s).
- Targeted: `pytest tests/test_persistent_store.py` → **12 passed**.
- Targeted: `pytest tests/test_mysql_and_alerts.py tests/test_platform_engineering.py tests/test_universal_scanner.py tests/test_route_health.py` → **39 passed** (all previously failing tests).
- `python -m py_compile` on all changed Python files + `node --check web/static/app.js` → OK.

### Live end-to-end evidence

`POST /api/tools/subdomains` for `example.com` (real OSINT, not fixtures):

```
discovered 7
sources ['ApexRoot', 'CertSpotter', 'HackerTarget', 'URLScan', 'crt.sh']
persistence ['LOCAL_ONLY']
persisted subdomains 7
  dev.example.com          | crt.sh                  | unresolved
  emudhra-lab.example.com  | CertSpotter, crt.sh     | unresolved
  example.com              | ApexRoot, CertSpotter, URLScan, crt.sh | confirmed
  m.example.com            | crt.sh                  | unresolved
```

`POST /api/tools/subdomains` for `127.0.0.1`: `subdomains: []`, `discovery_mode: not_applicable`, explanatory note, scan ID created and no-op persisted — no invented assets.

`POST /api/tools/run/dns`: `status COMPLETED`, `scan_id tool_c46a2a2e195e`, `persistence LOCAL_ONLY`; `GET /api/scans/{id}/tools` returned 1 execution record with `exit_code 0`.

### Honest verification table

| Module | Expected | Actual status | Evidence |
|---|---|---|---|
| Security tools | Real execution + records | **PASS** (tool-exec endpoint) / **BLOCKED** (external binaries) | Live DNS run: execution row, exit code 0. nmap/subfinder/amass not installed on host. |
| Subdomain engine | Multi-source discovery | **PASS** | 7 real `example.com` subdomains from 5 sources; persisted. |
| DNS engine | Correct resolution | **PASS** | Apex `confirmed`, others `unresolved` recorded with DNS status. |
| MySQL | Permanent persistence | **BLOCKED** | No MySQL server on 127.0.0.1:3306 and no approval to install one. Code path + fake-driver tests pass; live restart test not possible. |
| Tool monitoring | Execution lifecycle | **PASS** | `/api/scans/{id}/tools` returns real status/exit code. |
| Universal scanner | Real analysis | **PASS (existing)** | 13 tests pass; persistence already present in SQLite + optional MySQL. |
| CrewAI | Actual orchestration | **BLOCKED / HONEST FALLBACK** | `crewai` not installed; API reports direct mode. Fabrication removed. |
| Alerts | Persisted notifications | **PASS** | Alert lifecycle tests pass (39-test targeted run). |
| Reports | Downloadable reports | **PASS (JSON/CSV)** / **NOT TESTED (PDF)** | `/api/reports/export` returns persisted data; PDF generation not exercised here. |
| Test suite | Regression clean | **PASS** | 569 passed, 0 failed. |

---

## 4. Remaining limitations (not completed in this pass)

1. **Live MySQL verification is BLOCKED**: no server and no authorisation to install one. The implementation is covered by unit tests with a fake driver and by the outbox recovery test, but no real MySQL restart test was performed.
2. **Native tool integration remains unverified**: `nmap`, `subfinder`, `amass`, `assetfinder`, `findomain`, `dnsx`, `massdns`, `tshark`, `nikto` are absent. Bundled tools (`nuclei`, `trivy`, `gitleaks`, `bandit`, `semgrep`, `sqlmap`, `snmk_fast_scan`) exist but were not individually executed end-to-end here.
3. **CrewAI/LangChain native execution NOT TESTED** (packages not installed). The honest `direct` fallback is what runs.
4. **Full 18-agent CrewAI fleet, PDF/DOCX/image analysis deep verification, browser E2E, Redis queue**: not implemented or not exercised in this pass. Existing tests cover parts of the universal scanner; browser E2E (`e2e_map_browser_test.py`) remains excluded by CI.
5. **Frontend KPI population**: placeholders were introduced, but a complete pass to bind every dashboard metric to real API fields was not completed (many legacy fallbacks remain in `app.js`).
6. **Durable outbox is tested with a fake driver only**; a real MySQL interruption test is blocked by the same constraint as (1).
7. **Alembic migration was authored but not executed** (`alembic` not installed, no MySQL server). Syntax is valid Python; SQL matches the `MYSQL_DDL` used at runtime.

---

## 5. Deployment / operator instructions

Default (SQLite, no extra packages):

```powershell
cd C:\Users\krish\snmk
python run.py
```

Optional MySQL mirror (requires a server you control):

```powershell
pip install -r requirements-enterprise.txt
$env:SWA_DB_BACKEND = "mysql"
$env:MYSQL_HOST = "YOUR_HOST"; $env:MYSQL_USER = "YOUR_USER"; $env:MYSQL_PASSWORD = "YOUR_SECRET"
alembic upgrade head            # review first with: alembic upgrade head --sql
```

No credentials are committed. If MySQL is unreachable, writes are marked
`PENDING` in `persistence_outbox`; retry with:

```
POST /api/persistence/outbox/flush
```

SQLite remains the authoritative store in every configuration; the API never
reports MySQL persistence as successful unless the write actually committed.
