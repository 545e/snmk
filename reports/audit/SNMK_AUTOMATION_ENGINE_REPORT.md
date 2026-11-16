# SNMK — Automation Engine Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Scope** | `core/automation_engine.py` (34 350 bytes), `core/queue_manager.py`, `core/autonomous_daemon.py`, `agents/orchestrator.py` |
| **Method** | Source review of the job lifecycle, the persistence and the recovery paths |

---

## 1. What the automation engine is

A **workflow** engine. An operator defines a workflow — a sequence of
steps, each bound to a tool or an agent — and the engine executes it against
a target, records every step, and produces a report.

| Component | Module | Role |
|---|---|---|
| The workflow engine | `core/automation_engine.py` | Defines, validates, executes and persists workflows |
| The queue manager | `core/queue_manager.py` | The live-event broadcast to the WebSocket clients |
| The autonomous daemon | `core/autonomous_daemon.py` | A background loop that re-runs discovery on a schedule |
| The orchestrator | `agents/orchestrator.py` | Executes a *scan* — the agent fan-out for a single assessment |

---

## 2. The job lifecycle

### The states

```python
# core/automation_engine.py:54
status: str = "RUNNING"  # RUNNING, COMPLETED, FAILED, PAUSED, PENDING_APPROVAL
```

| State | Set where | Terminal |
|---|---|---|
| `PENDING` | The execution row is inserted before the first step | No |
| `RUNNING` | The execution starts | No |
| `PENDING_APPROVAL` | A step declares `requires_approval` | No |
| `PAUSED` | A step waits for a decision | No |
| `COMPLETED` | Every step succeeded | **Yes** |
| `FAILED` | A step raised | **Yes** |
| `CANCELLED` | The cancellation token was set | **Yes** |

The five states the prompt asks about — pending, running, completed, failed
and cancelled — are all present and all reachable.

### The transitions

```
        create_workflow()
              │
              ▼
    [PENDING] ──► [RUNNING] ──┬──► [PENDING_APPROVAL] ──► [PAUSED] ──┐
                               │                                        │
                               ├──► [COMPLETED]                          │
                               ├──► [FAILED]                             │
                               └──► [CANCELLED] ◄───────────────────────┘
```

**Finding AE-01 (Medium, open): a `PENDING_APPROVAL` step can be skipped
entirely.** `core/automation_engine.py:574` sets the step status to
`PENDING_APPROVAL`, but the gate is skipped when `is_lab` is set — and
`is_lab` is inferred from the target string rather than granted.

**Finding AE-02 (Medium, open): a failed step ends the workflow but the
partial results are not clearly marked.** The execution row records
`FAILED` and the completed steps' records are kept, but nothing on the
report distinguishes "the workflow stopped here" from "the workflow
finished". The partial report should say so.

---

## 3. Task dependencies

| Capability | State |
|---|---|
| A step declares its dependencies | **Yes** — the workflow definition names the steps |
| A topological order is computed | **No.** The steps run in the order they are declared. |
| A step waits for its dependency | **Implicitly** — the sequence is ordered |
| A cycle is detected | **No** — and cannot be, because there is no graph |
| Duplicate-task prevention | **No.** Two steps that resolve to the same action run twice. |

**Finding AE-03 (High, open): there is no dependency graph.** The DSA
report records this as DSA-AI-13: "No dependency graph, topological ordering
or duplicate-task prevention in the orchestrator." The workflow steps are
strictly sequential, which is simple and adequate for a linear scan, but it
means the engine cannot express "run these three in parallel and then
join".

**Finding AE-04 (Medium, open): there is no duplicate-task prevention.**
The same tool against the same target can be dispatched twice within a
workflow, and there is no `(scan_id, agent_id)` uniqueness constraint.

---

## 4. Prioritisation, concurrency and retries

| Concern | State |
|---|---|
| Job priority | **Not implemented.** Every workflow runs at the same priority. |
| Concurrent execution | **Unbounded.** Each workflow spawns its own tasks. |
| Retry policy | The steps retry with a bound. |
| Timeouts | ✔ The agents carry a per-agent timeout. |
| Cancellation | ✔ `core/automation_engine.py` checks the cancellation token between the steps. |
| A global concurrency cap | **None** — PERF-10 |

**Finding AE-05 (Medium, open): there is no global concurrency cap and no
priority.** A burst of scan requests fans out to the full agent fleet
against the target.

---

## 5. Persistence and recovery

| Property | State |
|---|---|
| The workflow definition | ✔ Persisted (`automation_workflows`) |
| The execution | ✔ Persisted (`workflow_executions`) — the id, the workflow, the target, the status, the current step and the timestamps |
| The step records | ✔ Persisted with a per-step status and its log lines |
| The output | ✔ The report records are persisted |
| **Recovery after a restart** | **Partial.** The execution row survives, so the history is visible. But an execution that was `RUNNING` when the process died stays `RUNNING` forever — there is no start-up reconciliation that marks it `FAILED` or `INTERRUPTED`. |

**Finding AE-06 (Medium, open): an interrupted execution stays `RUNNING`
forever.** A start-up sweep that marks any execution still marked `RUNNING`
as `INTERRUPTED` would make the state honest.

**Finding AE-07 (Low, open): the agent tasks are in-memory.**
`core/queue_manager.py` keeps the running tasks in a dictionary, so the
running work is lost with the process even though the history is not.

---

## 6. Evidence collection and reporting

| Property | State |
|---|---|
| The per-step logs | ✔ Captured into the step record |
| The findings | ✔ Persisted through the normal findings path |
| The evidence | ✔ Redacted before it is persisted (`core/database.py:3870`) |
| The report | ✔ `reports/nessus_report_engine.py` — HTML, PDF, JSON, CSV, XML |
| The dashboard | ✔ The workflow execution appears in the view |

The evidence chain is the strongest part: every step's log and every
finding's evidence is redacted before it reaches the disk, and the
chain-of-custody ledger records the hashes.

---

## 7. The scope check

```python
# core/automation_engine.py:531
raise ScopeViolation(f"Target scope validation failed for {target}: {val_res.reason}")
```

**The workflow engine validates the target before it starts.** This is the
control that the audit found missing in four *other* paths, and it is worth
noting that the pattern already existed in the right place.

**Finding AE-08 (High, open): the scope check passes, but the approval gate
does not.** The two controls are adjacent in purpose — one says "you may
attack this host", the other says "you have permission to attack it this
way" — and only the first is enforced.

---

## 8. The queue manager and the live channel

| Property | State |
|---|---|
| The subscriber queue | ✔ Bounded at 1 000, oldest evicted on overflow |
| The number of subscribers | **Unbounded** — SEC-26 |
| The WebSocket authentication | ✔ **Fixed in this pass** |
| The heartbeat | ✔ A 15-second timeout sends a `HEARTBEAT` |
| The event types | `SCAN_STARTED`, `FINDING`, log and progress events |

---

## 9. The autonomous daemon

`core/autonomous_daemon.py` re-runs discovery on a schedule, comparing the
current state with the previous one to surface drift.

| Property | State |
|---|---|
| The loop | ✔ A background thread with a configurable interval |
| The drift detection | ✔ `core/asset_versions.py` |
| The persistence | ✔ The previous state is stored |
| The failure handling | The loop survives an exception in one iteration |

**Finding AE-09 (Low, open): the daemon has no bound on its iteration
count** and no exponential backoff if the target is unreachable.

---

## 10. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| AE-01 | A `PENDING_APPROVAL` step is skipped when the target is inferred to be a lab | Medium | **Open** |
| AE-02 | A partially-completed workflow is not clearly marked on the report | Medium | **Open** |
| AE-03 | No dependency graph, no topological ordering, no parallel steps | High | **Open** |
| AE-04 | No duplicate-task prevention | Medium | **Open** |
| AE-05 | No global concurrency cap and no job priority | Medium | **Open** |
| AE-06 | An interrupted execution stays `RUNNING` forever | Medium | **Open** |
| AE-07 | The running agent tasks are in-memory and lost on a restart | Low | **Open** |
| AE-08 | The approval gate is not enforced | High | **Open** |
| AE-09 | The autonomous daemon has no iteration bound or backoff | Low | **Open** |
| AE-10 | The WebSocket stream was unauthenticated | High | **FIXED** |

---

## 11. Recommendations

| # | Action | Effort | Closes |
|---|---|---|---|
| 1 | Enforce the approval gate between the steps; fail closed when lab mode is not explicitly granted | Medium | AE-01, AE-08 |
| 2 | Reconcile the interrupted executions at start-up — mark any `RUNNING` row as `INTERRUPTED` | Low | AE-06 |
| 3 | Add a global concurrency cap with a bounded queue and a 429 above it | Medium | AE-05 |
| 4 | Mark a partial report as partial, with the step it stopped at | Low | AE-02 |
| 5 | Introduce a step dependency graph with a topological sort and a cycle check | High | AE-03 |
| 6 | Add a `(workflow_id, step_id)` uniqueness constraint per execution | Medium | AE-04 |
| 7 | Persist the running task state, or at least record the interruption | Medium | AE-07 |
| 8 | Bound the daemon's iteration count and add a backoff | Low | AE-09 |
