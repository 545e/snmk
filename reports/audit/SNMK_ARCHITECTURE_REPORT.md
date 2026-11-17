# SNMK — Architecture Report

| | |
|---|---|
| **Revision** | `39f441b` (branch `main`) |
| **Method** | Static analysis of the full import graph, AST-based function and module metrics, route enumeration against a live application instance |
| **Recommendation** | No rewrite. The layering is sound; the problems are concentration and duplication, both of which are addressable incrementally. |

---

## 1. The shape of the system

SNMK is a **monolith with clean seams**, not a layered application with
leaking layers. The seams are:

```
  run.py / swa_cli.py / install.sh        entry points
        │
        ▼
  web/server.py        (8 139 lines)  the FastAPI application
  web/enterprise_api.py                the /api/agents + control plane
  web/network_api.py                   the network-intelligence API
  web/forensics_api.py                 the forensics API
  web/ai_agent_api.py                   the AI-agent API
  web/v1/router.py                     the versioned API
  web/kill_chain_router.py             the kill-chain API
        │
        ▼
  core/                                the engines
        database.py (10 319)  scope_policy.py  app_security.py
        js_intelligence.py  scanner_integrations.py  tool_registry.py
        llm_client.py  credentials.py  approval_engine.py  ...
        │
        ▼
  agents/                              the 94 agent adapters
  plugins/                             the 10 OWASP plugins
  reports/                             the report generators
  tools/                               external binary management
        │
        ▼
  SQLite (WAL)                         swa_data.db + snmk_evidence.db
```

The rule the project follows well: **routes live in `web/`, engines live in
`core/`, and `web/` does not contain scanning logic.** The orchestration
itself (`core/automation_engine.py`) is in `core/`, not in a route handler.

---

## 2. Measured shape

| Metric | Value |
|---|---|
| Git-tracked files | 565 |
| Python modules | 174 (75 253 lines) |
| JavaScript / CSS / HTML | 4 / 3 / 2 files (18 296 / 7 691 / 8 073 lines) |
| Markdown documents | 290 files (14 941 lines) |
| FastAPI routes | 197 (176 under `/api`) |
| Python tables | 36 (`core/database.py`) + 7 (`core/kill_chain/db.py`) |
| `CREATE INDEX` statements | 66 |
| `FOREIGN KEY` declarations | 4 |
| Import cycles | 4 |
| Functions over 100 lines | 96 |
| Functions over 200 lines | 26 |
| Modules over 1 000 lines | 13 |
| Coverage | 64 % |

---

## 3. The three structural weaknesses

### ARC-01 — `core/database.py` and `web/server.py` are concentration risks
**Severity:** High · **Status:** Open

`core/database.py` holds **36 tables, 66 indexes and every query in the
product** in 10 319 lines. `init_db()` alone is **3 173 lines** — a single
function that creates the schema, migrates it and seeds it.

`web/server.py` holds **176 of the 197 routes** in 8 139 lines, plus
`execute_tool_endpoint()` at 328 lines and `run_all_tools_endpoint()` at
304 lines.

This is not a correctness problem today — it works — but it is the reason the
codebase has 135 cognitive-complexity findings and 26 functions over 200
lines. Every change to the data model touches one 10 000-line file, and every
review of the API touches one 8 000-line file.

**Incremental path.** `init_db()` splits cleanly into one function per table
with no behaviour change; the schema is a list of DDL blocks. `web/server.py`
splits by resource into `web/<domain>_api.py` routers, which is the pattern
the project already uses for `network_api`, `forensics_api` and
`ai_agent_api` — the v1 and enterprise routers were extracted this way
already, so the pattern is established and the migration is mechanical.

**Risk:** low if the schema is moved verbatim and covered by the existing
454 tests. **Benefit:** the two largest concentration risks in the codebase
disappear without an architectural change.

### ARC-02 — Four import cycles
**Severity:** Medium · **Status:** Open

Measured with an AST import-graph walk:

| Cycle | Cause |
|---|---|
| `agents.orchestrator` ↔ `core.agent_registry` | The orchestrator reads the registry; the registry names the orchestrator's class |
| `core.ai_training` ↔ `core.database` | The training engine saves jobs through the database; the database imports the training models |
| `core.data_management` ↔ `core.database` | The dataset manager stores records; the database imports the dataset models |
| `web.server` ↔ `web.v1.router` | The v1 router is mounted by the server and imports it back for the shared helpers |

The last three are **type-only cycles**: the import is needed for a Pydantic
model or a mount, and the runtime dependency does not exist. They are
resolved by moving the shared models into a `core/models.py` (which already
exists) or by using `TYPE_CHECKING` imports. The first is a genuine
architectural cycle and needs the registry to expose the orchestrator through
a registration hook instead of an import.

**Impact:** import-time cost, and the reason `import web.server` takes
**3.6 seconds**.

### ARC-03 — Duplicated implementations of the same concern
**Severity:** Medium · **Status:** Open

SonarQube measures **2.8 % duplicated lines**, and the duplication is
concentrated:

* **85 duplicated blocks in `web/static/app.js`** (a 16 468-line single file).
* **44 duplicated blocks in Python** (`python:S3358`).
* **Four report generators** exist side by side: `reports/generator.py`,
  `reports/nessus_report_engine.py`, `reports/vulnerability_reports.py` and
  `reports/enterprise_reports.py`. They overlap substantially in the HTML,
  PDF, JSON and CSV rendering.
* **Three tool registries** coexist: `core/tool_registry.py` (the catalogue),
  `core/scanner_integrations.py` (the external binaries) and
  `core/tool_dependency_manager.py` (the installer). They describe the same
  tools from three angles, and each keeps its own view of "installed".

**Impact:** a fix to a finding's HTML rendering has to be applied in more
than one place, and it is easy to miss one.

---

## 4. What is done well

* **The scope policy is a genuine choke point.** `core/scope_policy.py`
  centralises hostname normalisation, the SSRF address guard, the allowlist
  and the lab-mode concept. Every tool that reaches the network is
  *supposed* to route through it — and the audit found the handful that did
  not, which is exactly the value of having a choke point.
* **The TLS policy is now centralised too** (`core/tls_policy.py`).
* **The tool registry is declarative and machine-resolvable.** Every entry
  names a real callable, and `core/tool_handler_resolver.py` resolves it —
  the registry is load-bearing rather than decorative.
* **The kill-chain corpus loader reports its own truncation** instead of
  silently correlating an incomplete set.
* **The agent registry derives its count at runtime**, so the "94 agents"
  figure in the dashboard and the documentation cannot drift apart.
* **The database is parameterised throughout.** No string-formatted SQL
  carries user input (see `SNMK_SECURITY_AUDIT_REPORT.md` §5).

---

## 5. Dependency injection

The project uses **module-level singletons** rather than a DI container:
`db`, `scope_policy`, `tool_registry`, `queue_manager`, `storage_inspector`,
`photorec_carver`. This is a deliberate and defensible choice for a
single-process tool: it keeps the code simple, and the singletons are
process-local state rather than shared resources.

The cost is **test isolation**, which is visible: `tests/test_auth_hardening.py`
has to patch the configuration attributes of `core.app_security` rather
than inject a double, because the module reads them at call time.

**Recommendation:** keep the singletons. Introduce a factory only where a
test actually needs a different instance — the two cases that matter today
are the scope policy (for the allowlist) and the credential store (for the
master key).

---

## 6. Error propagation and resource management

| Concern | State |
|---|---|
| Custom exception classes | `ScopeViolation` (`core/scope_policy.py:360`), `EndpointPolicyError` (new), `HandlerNotResolvable` / `HandlerNotExecutable` |
| Global exception handlers | Present in `web/server.py` |
| Background-task failures | Recorded in `core/automation_engine.py` with a `workflow_executions` row per execution |
| Timeouts | Present on the network calls; **35 HTTP requests have no explicit timeout** (bandit B113) |
| Retries | Bounded in the scanner adapters; the rate limiter is per-process and in-memory |
| Graceful shutdown | `run.py` handles `KeyboardInterrupt`; the WebSocket loop has a 15-second heartbeat timeout |
| Connection leaks | SQLite uses a thread-local connection (`core/database.py:103`); no leak was observed |

**The notable gap** is the 35 timeout-less HTTP requests: a hung upstream
holds a worker for the client's default timeout instead of a bounded one.

---

## 7. Scalability

| Dimension | Current limit | Consequence |
|---|---|---|
| Concurrent scans | Unbounded | Each scan spawns a full multi-agent orchestration. The DSA report estimates 20 concurrent scans ⇒ ~1 880 agent dispatches. |
| Findings per response | Unbounded `limit` on most list endpoints | One request can return the whole findings table |
| Per-process state | In-memory rate limiter, session store, subscriber queues | Not shared between workers or replicas |
| SQLite | Single writer | Fine for one operator; a bottleneck for a team |

**These are single-operator-tool limits, not enterprise-scale limits.** The
product positions itself as an operator console. The recommendation is to
document the supported concurrency rather than to build for scale that is not
claimed.

---

## 8. Recommendations

| # | Action | Benefit | Risk | Effort |
|---|---|---|---|---|
| 1 | Split `init_db()` into one function per table | Removes the single largest function | Very low — mechanical | Low |
| 2 | Extract the v1, enterprise, network, forensics and AI-agent routers' remaining siblings out of `web/server.py` | Halves the largest route module | Low — the pattern is established | Medium |
| 3 | Resolve the three type-only import cycles with `TYPE_CHECKING` | Removes import-time cost | Very low | Low |
| 4 | Consolidate the four report generators onto one rendering core | Removes ~44 duplicated blocks | Medium — the HTML differs per report | High |
| 5 | Split `web/static/app.js` into ES modules | Removes the 85 duplicated blocks and makes the frontend reviewable | Medium — no bundler is configured | High |
| 6 | Add the missing timeouts to the 35 HTTP calls | Bounds worker occupancy | Very low | Low |

Items 1, 3 and 6 are mechanical and can be done in one pass. Item 2 is the
highest-value structural change. Items 4 and 5 are large projects and should
be scheduled, not rushed.
