# SNMK — Database Audit Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Engine** | SQLite 3, WAL journal mode |
| **Databases** | `swa_data.db` (the operational database, 19.62 MB on the audit host), `snmk_evidence.db` (the evidence ledger) |
| **Schema source** | `core/database.py` (36 tables, 66 indexes) and `core/kill_chain/db.py` (7 tables) |

---

## 1. The schema

### `core/database.py` — 36 tables

| Domain | Tables |
|---|---|
| **Scanning** | `scans`, `findings`, `finding_status_history`, `logs` |
| **Assets** | `assets`, `cloud_assets`, `container_assets`, `asset_drift_events`, `security_events`, `detection_rules` |
| **Projects** | `projects`, `workspaces`, `global_contexts`, `incidents` |
| **Agents** | `agents_inventory`, `agent_tasks`, `ai_agents`, `ai_evaluations`, `ai_training_jobs` |
| **Remediation** | `remediation_tickets`, `approval_requests`, `threat_indicators` |
| **Reporting** | `report_records`, `vulnerability_assessment_reports`, `cyber_exports`, `cyber_audit_logs` |
| **Cyber tooling** | `cyber_test_runs`, `cyber_test_results`, `cyber_deployments`, `datasets` |
| **Knowledge** | `knowledge_nodes`, `knowledge_edges` |
| **Operations** | `settings`, `tool_health_snapshots`, `tool_install_jobs`, `llm_security_tests` |

### `core/kill_chain/db.py` — 7 tables

`kill_chain_findings`, `kill_chain_evidence`, `kill_chain_indicators`,
`kill_chain_incidents`, `kill_chain_audit`, `kill_chain_controls`,
`kill_chain_reports`.

---

## 2. Connection management

```python
# core/database.py:92
self._local = threading.local()
# core/database.py:119
conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
```

| Property | State |
|---|---|
| Journal mode | **WAL** — set as a persistent, database-level pragma, re-issued if the connection is a fresh one |
| Connection scope | Thread-local — each worker thread gets its own connection |
| `check_same_thread` | `False`, which is correct given the thread-local design |
| Busy timeout | 30 s — a writer waits rather than failing immediately |
| Pooling | **None.** A connection is created per thread and never explicitly closed. |
| Leak risk | Bounded by the thread count, but a thread that dies takes its connection with it rather than returning it to a pool. |

**Finding DB-01 (Low, open): there is no connection pool and no explicit
close.** The `db.get_connection()` context manager closes the connection,
but the thread-local cache means a connection is created per thread and
retained. For a single-process operator tool this is fine; it would not be
for a multi-worker deployment.

---

## 3. Indexing

**66 `CREATE INDEX IF NOT EXISTS` statements** across 36 tables.

| Property | State |
|---|---|
| The findings table is indexed | ✔ — on `scan_id`, `severity`, `cvss_score`, `verified`, the status columns and the creation time |
| The assets table is indexed | ✔ — on the asset key, the type and the last-seen time |
| The scans table is indexed | ✔ — on the status and the creation time |
| The kill-chain findings table is indexed | ✔ — on the stage, the severity and the risk score |
| Every foreign key is indexed | **No.** There are only 4 `FOREIGN KEY` declarations across 36 tables, so there is little to index. |
| Composite indexes match the query patterns | Mostly — the ordering `risk_score DESC, created_at DESC` used by the kill-chain query has a matching index |

**Finding DB-02 (Medium, open): the referential integrity is enforced by
the application, not by the database.** With 4 foreign keys across 43
tables, an orphaned finding or a deleted scan's findings are possible if a
code path forgets to clean up.

**Recommendation:** this is a deliberate and common choice for SQLite — the
foreign-key pragma costs write performance — but it means the application
*must* clean up. The kill-chain `save_finding` does not cascade.

---

## 4. Query patterns

### N+1 queries

**Finding DB-03 (Medium, open): the kill-chain overview performs ~28 passes
over the findings list** and correlates twice per request. The DSA report
records that the single-pass bucketing and the pre-loaded data were fixed;
the residual is the pass count.

**Finding DB-04 (Medium, open): `list_findings_advanced()` takes 11
parameters** and builds its filter dynamically. It is the widest query
interface in the codebase and the most likely place for a query-plan
regression.

### Full-table reads

**Finding DB-05 (High, open): `GET /api/findings` with the default
parameters returns the entire findings table**, including the evidence
blobs. 1 046 findings and a 19.6 MB database make this a memory problem
as well as a disclosure one.

### The unbounded `limit`

**Finding DB-06 (High, open): most list endpoints accept an unbounded
`limit`.** `limit=100000000` and negative values are accepted. The
`/api/assets` endpoint does it correctly (`Query(default=100, ge=1, le=500)`),
which shows the pattern is known.

### Synchronous SQLite inside `async def`

**Finding DB-07 (Medium, open): 43 route handlers call a synchronous
database function directly from an `async def`.** Every one of them blocks
the event loop for the duration of the query. The DSA report has tracked
this as DSA-BE-25 since an earlier pass.

The fix is mechanical: change `async def` to `def` for the database-only
handlers and Starlette runs them in the threadpool.

---

## 5. Write amplification

**Finding DB-08 (Medium, open): `add_finding()` performs 3 transactions
plus a `GROUP BY` recompute per finding.** A scan that produces 200
findings performs 800 transactions and 200 recomputes. This is O(N²) write
amplification per scan.

**Fix:** fold the status columns into the `INSERT` and recompute the
counters once per scan rather than once per finding.

---

## 6. Migrations

**Finding DB-09 (Medium, open): there is no migration framework.** The
schema is created by `init_db()` — **3 173 lines**, the longest function in
the codebase — which creates the tables, adds the missing columns with
`ALTER TABLE`, and seeds the defaults.

The `ALTER TABLE` statements use a fixed column list and are guarded by a
"does this column exist" check, so the migration is idempotent. It works.

But it has three consequences:

1. The function cannot be read; it is 3 173 lines of DDL.
2. There is no schema version, so a migration cannot be skipped or rolled
   back.
3. Every start-up runs 66 `CREATE INDEX IF NOT EXISTS` statements and a
   column-existence check on every table.

**Fix:** split `init_db()` into one function per table (the data is already
grouped that way) and add a `schema_version` row to `settings`.

---

## 7. The evidence database

`snmk_evidence.db` is a separate, append-only chain-of-custody ledger
(`core/chain_of_custody` / `core/digital_forensics.py`).

| Property | State |
|---|---|
| Immutability | ✔ The ledger records a hash chain |
| The record count | Small on the audit host (0.01 MB) |
| Backup | **None** — it is a file, and nothing copies it |
| Retention | Undefined |

**Finding DB-10 (Medium, open): there is no backup or retention policy
for either database.** The Compose file declares a named volume, and a
volume without a backup is a single point of failure.

---

## 8. The report content

**Finding DB-11 (Medium, open): `report_records.content` stores the
rendered report body.** The DSA report measured **9.06 MB** of rendered
report bodies in a table whose rows also exist as files on disk. The
content is stored twice.

**Fix:** store the path and the metadata, and keep the rendered body on
disk only — or the reverse.

---

## 9. Secrets in the database

| Check | State |
|---|---|
| The API key vault | `core/credentials.py` encrypts with Fernet before writing to `settings`; the plaintext is never returned over HTTP |
| The orchestration read path | **A defect** — `agents/orchestrator.py:32` reads the raw `ai_api_key` setting, so the encrypted envelope `enc:v1:...` is sent to the provider as the bearer token. **Open** (SEC-23). |
| Evidence blobs | Redacted before they are written (`core/database.py:3870`) |
| The session store | In-memory, never persisted |

---

## 10. Concurrency

| Concern | State |
|---|---|
| Writers | SQLite serialises them; the 30 s busy timeout absorbs the contention |
| Readers | WAL mode allows them to proceed during a write |
| Cross-thread access | Each thread has its own connection |
| The database file | On a local volume; **not** on a network filesystem, where SQLite's locking does not work |

**Finding DB-12 (Low, open):** nothing prevents the database path from
being placed on a network share, where SQLite's locking model does not hold.
A start-up check that the path is on a local filesystem would be cheap.

---

## 11. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| DB-01 | No connection pool and no explicit close | Low | **Open** |
| DB-02 | 4 foreign keys across 43 tables — integrity is application-enforced | Medium | **Open** |
| DB-03 | The kill-chain overview still makes ~28 passes over the findings | Medium | **Open** |
| DB-04 | `list_findings_advanced()` takes 11 parameters | Medium | **Open** |
| DB-05 | `GET /api/findings` returns the whole table by default | High | **Open** |
| DB-06 | Most list endpoints accept an unbounded `limit` | High | **Open** |
| DB-07 | 43 handlers call synchronous SQLite from `async def` | Medium | **Open** |
| DB-08 | `add_finding()` does 3 transactions + a recompute per finding | Medium | **Open** |
| DB-09 | No migration framework; `init_db()` is 3 173 lines | Medium | **Open** |
| DB-10 | No backup or retention policy for either database | Medium | **Open** |
| DB-11 | The rendered report body is stored twice — in the database and on disk | Medium | **Open** |
| DB-12 | Nothing prevents the database from being placed on a network filesystem | Low | **Open** |
| DB-13 | The orchestrator sends the encrypted credential envelope to the provider | Medium | **Open** (SEC-23) |

---

## 12. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Convert the database-only handlers from `async def` to `def` so Starlette runs them in the threadpool | Medium | DB-07 |
| 2 | Bound every `limit` parameter and page `/api/findings` by default | Low | DB-05, DB-06 |
| 3 | Split `init_db()` into one function per table and add a `schema_version` row | Medium | DB-09 |
| 4 | Fold the status columns into the `INSERT` and recompute the counters once per scan | Medium | DB-08 |
| 5 | Store the report path and the metadata, not the rendered body | Medium | DB-11 |
| 6 | Add a backup script for the named volume and document the restore procedure | Medium | DB-10 |
| 7 | Add the missing foreign keys, or document the cascade rules the application enforces | Medium | DB-02 |
| 8 | Route the orchestrator's key read through `_get_stored_ai_key()` | Low | DB-13 |
| 9 | Reduce the kill-chain overview to a single bucketing pass | Medium | DB-03 |
| 10 | Check at start-up that the database path is on a local filesystem | Low | DB-12 |
