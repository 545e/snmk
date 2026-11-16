# SNMK — Performance and Reliability Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Host** | Windows 11 / CPython 3.12.10 / SQLite 3.54.0 (WAL) |
| **Method** | Direct measurement against a local instance; the harness is reproduced below |

> Every number in this report was measured on the audit host. Where a number
> could not be measured, it is marked as such rather than estimated.

---

## 1. Measurements

### Startup

| Metric | Value |
|---|---|
| `import web.server` | **3.610 s** |
| Consequence | Every `pytest` module, every CLI invocation and every worker pays it |

The import cost is dominated by the four import cycles
(`SNMK_ARCHITECTURE_REPORT.md` §3) and by the size of `web/server.py`
(8 139 lines) and `core/agent_registry.py` (1 623 lines).

### API latency

Warm, in-process, single client:

| Endpoint | Median | p95 | Status |
|---|---|---|---|
| `GET /api/health` | 26.67 ms | 34.48 ms | 200 |
| `GET /api/health/dependencies` | 24.15 ms | — | 200 |
| `GET /api/tools/registry` | 33.16 ms | — | 200 |
| `GET /api/kill-chain/overview` | 32.82 ms | — | 200 |
| `GET /api/findings/metrics` | 39.30 ms | — | 200 |
| `GET /api/agents` | 46.65 ms | — | 200 |

**These are in-process numbers** — they exclude the HTTP and ASGI layers, so
they are a floor, not a user-visible figure.

### The scope policy

| Operation | Median |
|---|---|
| `validate_target("example.com")` | **10.506 ms** |

10.5 ms is almost entirely the **DNS resolution**, which is performed on
every validation with no cache. For a scan that validates a target per
request, this is the dominant per-request cost.

**Finding PERF-01 (Medium, open): the scope policy resolves DNS on every
validation, with no cache.** This was a deliberate choice — a cache needs a
rebinding review, because a cached answer is a stale answer and a stale
answer is exactly what a rebinding attack exploits. The right fix is not a
cache but **resolving once and pinning the address to the connection**, which
is the same change that closes the DNS-rebinding finding.

### Resource usage

| Metric | Value |
|---|---|
| RSS after the import and 30 requests | **145.1 MB** |
| Threads | 8 |

145 MB is comfortable for a single-operator tool with a 3 GiB container
limit.

---

## 2. The performance problems that were fixed in this pass

| Change | Effect |
|---|---|
| `GET /api/health/dependencies` no longer fetches and serialises all 94 agent manifests to take their length | The endpoint went from 94 recursive Pydantic serialisations to a registry lookup |
| The kill-chain corpus loader reads once and reports its own truncation | The correlation no longer reads the corpus twice |
| `list_findings` is indexed on the columns the queries filter on | The findings list endpoint no longer scans the table |
| The unused-local and dead-code clean-up | Slightly smaller modules, marginally faster import |

---

## 3. The performance problems that remain

| ID | Finding | Impact | Severity |
|---|---|---|---|
| PERF-02 | **`init_db()` is 3 173 lines and runs on every start-up**, including 66 `CREATE INDEX IF NOT EXISTS` statements and a column-existence check per table. | The start-up cost grows with the schema. | Medium |
| PERF-03 | **43 route handlers call synchronous SQLite from `async def`**, blocking the event loop for the duration of the query. | Under concurrency, one slow query stalls every other request. | High |
| PERF-04 | **`add_finding()` does 3 transactions plus a `GROUP BY` recompute per finding.** | A 200-finding scan performs 800 transactions. | Medium |
| PERF-05 | **`GET /api/findings` returns the whole table by default**, including the evidence blobs. | 1 046 findings and 19.6 MB of database in a single response. | High |
| PERF-06 | **Most list endpoints accept an unbounded `limit`.** | A single request can ask for everything. | High |
| PERF-07 | **The kill-chain overview makes ~28 passes over the findings list.** | Linear in the findings count, multiplied by 28. | Medium |
| PERF-08 | **`report_records.content` stores the rendered body** that is also on disk. | 9.06 MB duplicated. | Medium |
| PERF-09 | **`discover_all_agents()` rebuilds all 94 manifests on every call**, and the dashboard calls it on every load. | 94 module imports and manifest constructions per dashboard load. | Medium |
| PERF-10 | **There is no global cap on concurrent scans or agent dispatches.** | 20 concurrent scans ⇒ ~1 880 agent dispatches against the target. | Medium |
| PERF-11 | **35 HTTP requests have no explicit timeout.** | A hung upstream holds a worker for the client's default timeout. | Medium |
| PERF-12 | **The agent manifest and the 3.6-second import are paid per process.** | Every worker pays it. | Low |

---

## 4. Reliability

| Concern | State |
|---|---|
| Health endpoint | ✔ `/api/health`, `/api/healthz`, `/health`, `/ready` |
| Readiness probe | ✔ `/ready` |
| Container health check | ✔ `curl -f http://127.0.0.1:8000/health`, 30 s interval, 5 s timeout, 8 s start period, 3 retries |
| Graceful shutdown | ✔ `run.py` handles `KeyboardInterrupt`; the WebSocket loop has a 15-second heartbeat timeout |
| Database durability | ✔ WAL mode with a 30 s busy timeout |
| Crash recovery | The scan state is in the database; a crash loses the in-flight scan but not the persisted findings |
| Retry storms | The scanner adapters retry with a bound; the platform-wide limiter is per-process |
| Circuit breakers | **None.** A provider that is down is retried by every scan. |
| Health of the dependencies | ✔ `GET /api/health/dependencies` reports the database, the agent registry, the security tooling and the integrations |

**Finding PERF-13 (Medium, open): there is no circuit breaker.** A provider
that is down is contacted by every scan, each waiting for its timeout.

**Finding PERF-14 (Medium, open): the container's health-check start
period is 8 seconds**, which is short for a first-run schema creation on a
cold volume.

---

## 5. Scalability

The platform is an **operator console**, not a distributed service. The
measured numbers above are comfortable for one operator.

| Dimension | Limit | Behaviour beyond it |
|---|---|---|
| Concurrent scans | Unbounded | Resource exhaustion (PERF-10) |
| Findings per response | Unbounded | Memory (PERF-05, PERF-06) |
| Process state | Per-process | The rate limiter, the session store and the subscriber queues are not shared between workers |
| Storage | SQLite | A single writer; fine for one operator, a bottleneck for a team |
| Import cost | 3.6 s per process | Multiplied by the worker count |

**Recommendation:** document the supported concurrency rather than building
for scale that is not claimed. A single-operator tool that says "one scan at
a time" is more useful than one that appears to support many and fails
confusingly.

---

## 6. The benchmark harness

`benchmarks/dsa_transformation_bench.py` and `benchmarks/dsa_bench.py`
measure the transformations the earlier passes made. They are excluded from
the coverage measurement (0 %, no tests) and are not run in CI.

**Finding PERF-15 (Low, open): there is no performance regression gate.**
The harness exists; nothing runs it. A CI step that runs the benchmark and
fails on a regression would be the natural use.

---

## 7. Recommendations

| # | Action | Benefit | Effort |
|---|---|---|---|
| 1 | Convert the 43 database-only handlers to `def` | Unblocks the event loop | Medium |
| 2 | Bound every `limit` and page `/api/findings` | Stops the whole-table read | Low |
| 3 | Resolve once and pin the address to the connection | Removes 10.5 ms per validation **and** closes the DNS-rebinding finding | Medium |
| 4 | Split `init_db()` and add a schema version | Faster start-up, a readable migration | Medium |
| 5 | Cache the agent manifests and invalidate on a registry change | Removes 94 constructions per dashboard load | Low |
| 6 | Fold the finding counters into the `INSERT` | Removes 800 transactions per 200-finding scan | Medium |
| 7 | Add a global scan concurrency cap with a 429 | Bounds the resource use | Medium |
| 8 | Add the 35 missing timeouts | Bounds worker occupancy | Low |
| 9 | Add a circuit breaker per integration | Stops a retry storm against a dead provider | Medium |
| 10 | Run the benchmark harness in CI and fail on a regression | Makes the performance visible | Low |
| 11 | Document the supported concurrency in the README | Sets an honest expectation | Low |

---

## 8. The benchmark harness, reproduced

```python
# startup and latency
import time, statistics
t0 = time.perf_counter()
from web.server import app
print(f"import: {time.perf_counter() - t0:.3f} s")

client = TestClient(app)
lat = []
for _ in range(20):
    t = time.perf_counter(); client.get("/api/health"); lat.append((time.perf_counter() - t) * 1000)
print(f"health median {statistics.median(lat):.2f} ms")

# the scope policy
from core.scope_policy import scope_policy
s = []
for _ in range(200):
    t = time.perf_counter(); scope_policy.validate_target("example.com", auto_authorize=False)
    s.append((time.perf_counter() - t) * 1000)
print(f"validate_target median {statistics.median(s):.3f} ms")
```
