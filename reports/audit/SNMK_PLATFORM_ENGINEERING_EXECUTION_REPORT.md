# SNMK — Platform Engineering Execution Report

| | |
|---|---|
| **Repository** | `https://github.com/545e/snmk.git` |
| **Branch / revision** | `main` / work in progress on 2026-11-17 |
| **Mission** | 15-phase audit, repair, MySQL integration, CrewAI orchestration, security tooling, alerts, observability and self-healing |
| **Rule** | Nothing is claimed as completed without execution evidence. Blocked items are named, not silently skipped. |

---

## 0. Status legend

| Status | Meaning |
|---|---|
| ✅ **Completed and verified** | Implemented and exercised with a test or a live command in this session |
| 🟡 **Implemented, not verified** | Code exists, but the external resource it needs was unavailable |
| 🔒 **Blocked** | Needs a credential, administrator privilege, paid service or an explicit decision |
| ⬜ **Not implemented** | Not done in this session; no claim of completion |
| ❌ **Failed** | Attempted and did not succeed |

---

## 1. Phase-by-phase result

| Phase | Status | Evidence |
|---|---|---|
| 1 — Repository audit | ✅ Completed and verified | 597 tracked files enumerated; 177 Python modules; 0 C/C++ sources; 4 JS, 3 CSS, 2 HTML; no `package.json`. The 27 earlier audit reports were refreshed with the new modules. |
| 2 — CrewAI orchestration | 🟡 Implemented, not verified | `core/crew_coordinator.py`: 22 declared roles, bounded threads, retries, file-conflict guards, history. `crewai 0.203.2` is installed and imports. **Mode is `direct`, not `crewai`**, because `SWA_CREWAI_ENABLED` is off and no provider key is configured. The API reports `crewai_executed: false` — it does not pretend otherwise. |
| 3 — Development tool installation | ✅ Completed and verified partly; 🔒 blocked partly | A measured registry of 28 tools (`core/dev_tool_registry.py`) reports 7 Operational, 7 Configured, 14 Not Available. Installed into the venv: SQLAlchemy, Alembic, PyMySQL, prometheus-client, OpenTelemetry SDK, Ruff, Black, Mypy, CrewAI. Semgrep 1.185.0 was installed **in a separate venv** because it pins OTel ~=1.37 while FastAPI needs >=1.44. `pip check` in the main venv: **No broken requirements found**. Blocked: MySQL server, Docker, Grafana/Prometheus server, Wireshark/Zeek/Suricata, Snyk, OWASP ZAP — no administrator rights or credentials. |
| 4 — MySQL integration | 🟡 Implemented, not verified | `core/mysql_adapter.py`: opt-in backend, pooled connections, retries, TLS setting, real telemetry queries, no hardcoded credentials. Alembic scaffolding in `alembic.ini`, `migrations/env.py` refuses to run unless `SWA_DB_BACKEND=mysql`. **SQLite remains primary** — replacing a working 43-table store needs assessment and approval. No MySQL server on this host, so status is `Not Available`, not `Operational`. |
| 5 — Application error repair | ✅ Completed and verified | Three `assert` invariants replaced with explicit checks; the orchestrator's encrypted-key bug fixed; prior passes fixed the auth bypass, SSRF paths and REA contract. |
| 6 — Cybersecurity integration | ✅ Completed and verified (prior passes) | SonarQube, Bandit, pip-audit, gitleaks, Trivy, and the platform's own 15 scanner adapters. Semgrep now isolated and runnable. |
| 7 — AI agent upgrade | 🟡 Partial | 22-role coordinator added. LangChain, LangSmith and Giskard are **not installed** and not claimed as used. No prompt registry, no evaluation dataset, no training. |
| 8 — Alert management | ✅ Completed and verified | `core/alert_manager.py`: unique IDs, timestamps, severity, source, component, evidence, related ID, remediation, owner, status, resolution, deduplication, suppression, lifecycle actions. Delivery is `DELIVERED` only on channel confirmation; otherwise `NOT_CONFIGURED`/`FAILED`. 8 API endpoints. |
| 9 — Self-healing | ⬜ Not implemented | Requires approval policy for destructive changes and a reviewed rollback design. Not claimed. |
| 10 — Observability | ✅ Completed and verified | `core/observability.py`: Prometheus counters/gauges/histograms, `GET /metrics`, correlation IDs on every response, OTEL status endpoint. Tracing itself is **disabled** (`SWA_OTEL_ENABLED` unset), and the API says so. No Grafana/Loki/Tempo/Alertmanager. |
| 11 — Dashboard | ✅ Completed and verified | New "Platform Engineering" view with a sidebar entry and 5 panels (CrewAI, MySQL, Observability, Alerts, Tools) reading only from live APIs. `node --check` passes; navigation tests pass. Original logo/branding untouched. |
| 12 — Reporting and logs | ✅ Completed and verified (existing) | Existing JSON/CSV/HTML/Markdown/SARIF exports and the audit-log tables were verified in the earlier audit. |
| 13 — CI/CD | ✅ Completed and verified | New `.github/workflows/platform-engineering.yml`: least-privilege permissions, Ruff blocking only on the new modules (advisory on the legacy tree), Black advisory, mypy advisory, Bandit, pip-audit, gitleaks, Trivy config scan, platform tests, Node syntax check. No deploy or push steps. |
| 14 — Test and repair loop | ✅ Completed and verified | **485 tests pass, 0 failed**. New: `test_platform_engineering.py` (20), `test_post_audit_hardening.py` (11). |
| 15 — Documentation and report | ✅ This document | Honest status for every phase. |

---

## 2. What changed in this session

### New modules

| File | Purpose |
|---|---|
| `core/dev_tool_registry.py` | 28-tool registry with six measured statuses |
| `core/crew_coordinator.py` | 22-role Coordinator with direct fallback, bounded execution and history |
| `core/mysql_adapter.py` | Opt-in MySQL backend with real telemetry |
| `core/alert_manager.py` | Centralized alert lifecycle, deduplication and honest delivery reporting |
| `core/observability.py` | Prometheus metrics and correlation IDs |
| `migrations/env.py`, `alembic.ini`, `migrations/README.md` | Reviewable Alembic scaffolding, never auto-executed |
| `.gitleaks.toml` (added in the previous pass) | Documents the nine known false positives |
| `tests/test_platform_engineering.py`, `tests/test_post_audit_hardening.py` | 31 new tests |

### New API endpoints

```
GET  /api/dev-tools                 measured tool statuses
GET  /api/dev-tools/{id}            one tool
GET  /api/crew/status               orchestration mode and execution history
GET  /api/crew/roles                22 declared roles
GET  /api/crew/history              recorded task outcomes
POST /api/crew/tasks                submit a bounded specialist task
GET  /api/crew/tasks/{id}           one task
GET  /api/mysql/status              real MySQL readiness
GET  /api/mysql/metrics             real MySQL telemetry or explicit unavailable
GET  /api/alerts                    filtered alerts
GET  /api/alerts/summary            alert summary
POST /api/alerts                    create from an observed event
POST /api/alerts/{id}/acknowledge   lifecycle
POST /api/alerts/{id}/assign        lifecycle
POST /api/alerts/{id}/resolve       lifecycle
POST /api/alerts/{id}/notify        delivery only on confirmation
GET  /metrics                       Prometheus exposition
GET  /api/observability             telemetry state
```

### Tooling installed

| Tool | Version | Location | Status |
|---|---|---|---|
| SQLAlchemy | 2.1.9 | main venv | ✅ usable |
| Alembic | 1.20.1 | main venv | ✅ usable |
| PyMySQL | 1.2.4 | main venv | ✅ usable |
| prometheus-client | 0.26.0 | main venv | ✅ usable |
| OpenTelemetry SDK | 1.45.2 | main venv | ✅ usable |
| Ruff | 0.17.5 | main venv | ✅ usable |
| Black | 25.12.0 | main venv | ✅ usable |
| Mypy | 1.20.2 | main venv | ✅ usable |
| CrewAI | 0.203.2 | main venv | ✅ imports; not executing without key |
| Semgrep | 1.185.0 | **isolated venv** | ✅ usable |
| Bandit / pip-audit / gitleaks / Trivy | existing | system / temp tools | ✅ usable |

**One dependency conflict found and repaired:** CrewAI pulled OpenTelemetry 1.37, below FastAPI's >=1.44 requirement, and Semgrep pins ~=1.37. I restored OTel 1.45 in the main venv and moved Semgrep to its own venv. `pip check` reports no broken requirements.

---

## 3. Repairs made during this session

| Finding | Root cause | Fix |
|---|---|---|
| Crew coordinator reported success without executing | N/A — new module | Results are recorded only after a handler returns; mode is honestly `direct` |
| MySQL metrics could have been fabricated | N/A — new module | Explicit `available: false` when no server; all numbers from real queries |
| Alert delivery could be reported as sent | N/A — new module | `DELIVERED` only when the channel returns true |
| `mysql_metrics` had an unused conditional | Copy artefact | Removed |
| `observability` middleware leaked an exception pattern | Local var in `finally` | Rewritten with a single `status` variable |
| `Path` import shadowed FastAPI's `Path` in the kill-chain router | `from pathlib import Path` collided with `from fastapi import ... Path` | Aliased to `FilesystemPath` |
| Security-header test asserted a removed header | The X-XSS-Protection header was intentionally removed | Test now asserts the header is absent |
| Ruff flagged 92 issues in the new modules | Modern typing/style defaults | 86 auto-fixed; 6 intentional error boundaries annotated with justification |
| Alert dedup returned a resolved-state alert | Suppression checked after dedup | Reordered; returned alert status updated |

Two regressions from my own changes were caught by the full suite and fixed before commit.

---

## 4. Test results

```
pytest -q -p no:cacheprovider
485 passed in ~4m40s
```

| Suite | Tests |
|---|---|
| `test_platform_engineering.py` | 20 |
| `test_post_audit_hardening.py` | 11 |
| `test_auth_hardening.py` | 12 |
| All pre-existing suites | 442 |

`node --check web/static/app.js` passes.
`ruff check` on the new modules: **All checks passed**.
`pip check`: **No broken requirements found**.
`gitleaks detect` with the allowlist: **no leaks found**.

---

## 5. Blocked items (need a decision, credential or privilege)

| Item | Why blocked |
|---|---|
| **MySQL server install and live verification** | No MySQL/MariaDB binary, no administrator rights. The adapter is implemented but cannot be exercised here. |
| **Switching the primary database from SQLite** | Would require a reviewed migration of 43 tables and real user data. Explicitly out of scope without approval. |
| **CrewAI actually executing through an LLM** | `SWA_CREWAI_ENABLED` is off and no provider key is configured. The coordinator honestly runs in `direct` mode. |
| **LangChain / LangSmith / Giskard** | Adding them risks another dependency conflict (CrewAI already brings an LLM stack) and there is no evaluation dataset or LangSmith key. Not installed; not claimed. |
| **Grafana / Prometheus server / Loki / Tempo / Alertmanager** | Not installed; no Docker daemon. Only the client-side metrics layer was implemented. |
| **OWASP ZAP, Snyk, Wireshark/Zeek/Suricata** | Require installation, a licence or administrator rights. |
| **C/C++ toolchain work** | **Not applicable**: the repository contains zero C/C++ source files and no build system. |
| **Frontend build (Vite/Webpack)** | **Not applicable**: there is no `package.json`. The frontend is served as static ES modules. |
| **RBAC, authentication defaults, approval gate, coverage gate** | Left unchanged by explicit instruction in the previous turn. |

---

## 6. What was *not* implemented

* **Phase 9 (self-healing)** — needs an approval policy and a rollback design.
* **Prompt registry, evaluation datasets, model training** — Phase 7 is partial.
* **Grafana dashboards, Loki log aggregation, Tempo tracing, Alertmanager routing** — only the instrumentation side exists.
* **A live DAST run** — no ZAP and no authorized lab target.
* **A MySQL backup/restore drill** — no MySQL server.
* **A full React/Vite/Webpack audit** — those technologies are not present.

---

## 7. Honest final status

| Area | Status |
|---|---|
| Application stability | **Stable** — 485 tests pass, no dependency conflicts |
| Security posture | Prior audit: 0 Critical, 0 SonarQube bugs/vulnerabilities; open High findings are RBAC and policy defaults that were left untouched by instruction |
| Database | SQLite primary and working; MySQL adapter implemented but **unverified** (no server) |
| AI orchestration | Coordinator implemented and tested; **CrewAI is installed but not executing** — the API states this plainly |
| Observability | Metrics and correlation IDs live; tracing disabled; no dashboards |
| Alerts | Implemented and tested; no external channel configured, so delivery reports `not_configured` |
| Dashboard | New Platform Engineering view reads real data; no simulated telemetry |
| CI/CD | New quality gates added; no deployment or force-push |
| Self-healing | **Not implemented** |
| Production readiness | Unchanged from the previous assessment: **DEVELOPMENT READY** |

---

## 8. Recommended next steps

| # | Action | Why |
|---|---|---|
| 1 | Decide the RBAC role matrix and apply `require_role()` | Largest remaining authorisation gap |
| 2 | Decide whether to enforce the approval gate and the scope allowlist by default | Both exist and neither is applied |
| 3 | Provide a MySQL server (or a container runtime) to verify the adapter | Turns `Implemented, not verified` into `Operational` |
| 4 | Configure a CrewAI provider key and `SWA_CREWAI_ENABLED=1` if real CrewAI execution is wanted | Otherwise the honest mode remains `direct` |
| 5 | Add an alert channel and confirm delivery | Turns `not_configured` into `delivered` with evidence |
| 6 | Add Grafana/Alertmanager and enable OTLP export | Completes the observability stack |
| 7 | Design the self-healing approval and rollback policy | Required before Phase 9 can be implemented safely |
