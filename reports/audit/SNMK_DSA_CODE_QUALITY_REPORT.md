# SNMK — Data Structures, Algorithms and Code-Quality Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Method** | SonarQube 24.12 (complexity, duplication, dead code), Bandit 1.7.10 (security-relevant patterns), and a targeted review of the algorithmic hot spots |

---

## 1. The measured picture

| Metric | Value |
|---|---|
| Lines of code (ncloc) | 74 532 |
| Lines (with comments and blanks) | 100 605 |
| Coverage | 64.0 % |
| Duplicated lines | 2.8 % |
| **Cognitive complexity** | **12 096** |
| Bugs | **0** |
| Vulnerabilities | **0** |
| Code smells | 719 |
| Security hotspots | 118 |
| Functions over 100 lines | 96 |
| Functions over 200 lines | 26 |
| Modules over 1 000 lines | 13 |
| Import cycles | 4 |

---

## 2. The complexity distribution

| Rule | Count | Where |
|---|---|---|
| `python:S3776` | 135 | Cognitive complexity |
| `python:S1192` | 100 | Duplicated string literals |
| `javascript:S3358` | 85 | Duplicated blocks in `app.js` |
| `python:S3358` | 44 | Duplicated blocks in Python |
| `python:S5869` | 25 | Duplicated string literals (Python variant) |
| `python:S6353` | 11 | Comprehension complexity |
| `python:S1172` | 19 | Unused method arguments |

### The largest functions

| Lines | Location | Function |
|---|---|---|
| **3 173** | `core/database.py:222` | `init_db()` |
| 763 | `core/agent_registry.py:87` | `discover_all_agents()` |
| 526 | `core/agent_registry.py:975` | `dispatch_agent_by_id()` |
| 454 | `reports/generator.py:304` | `generate_html()` |
| 436 | `swa_cli.py:137` | `main()` |
| 357 | `web/server.py:2597` | `get_scan_forensic_profile()` |
| 335 | `reports/nessus_report_engine.py:963` | `generate_html()` |
| 333 | `core/scanner_integrations.py:119` | `_detect_tool_inventory()` |
| 328 | `web/server.py:4368` | `execute_tool_endpoint()` |
| 323 | `reports/nessus_report_engine.py:572` | `generate_pdf()` |
| 304 | `web/server.py:4710` | `run_all_tools_endpoint()` |

`init_db()` alone accounts for **26 % of the codebase's cognitive
complexity findings**. It creates 36 tables, adds missing columns with
`ALTER TABLE`, seeds the defaults and runs 66 `CREATE INDEX IF NOT EXISTS`
statements — in one function.

**Finding DSA-01 (Medium, open): `init_db()` should be split into one
function per table.** The data is already grouped that way; it is the
indentation that is the problem. This is a mechanical change with a
measurable outcome: the function disappears from the top-25 list and the
start-up cost stops growing with the schema.

---

## 3. The algorithms that matter

### 3.1 The kill-chain correlation

`core/kill_chain/correlation.py` — `correlate()`.

| Property | Value |
|---|---|
| Purpose | Group findings by asset and by stage, then compute a composite risk and confidence per asset |
| Algorithm | Two passes: deduplicate by `(stage, title, endpoint, host)`, then group by asset |
| Time | O(n) in the findings, with a sort |
| Space | O(n) |
| Correctness | The deduplication key includes the stage, so the same title on two stages is two findings — deliberate, and correct for a kill chain |
| Edge cases | An asset with no findings contributes nothing; an asset with one finding produces a path with a single stage and a `progression_percentage` of 14.3 — the code says "Multi-stage intrusion chain" for a single stage, which is misleading |
| Bottleneck | The **caller**: the overview makes ~28 passes over the same list |

**Finding DSA-02 (Medium, open): the overview still makes ~28 passes over
the findings list** and correlates twice per request. The DSA report records
that the single-pass bucketing and the pre-loaded data were fixed; the
residual is the pass count.

**Finding DSA-03 (Low, open): a single-stage path is described as a
"multi-stage intrusion chain".** The wording should adapt to the number of
stages detected.

### 3.2 The scope-policy matching

`core/scope_policy.py` — `_matches_allowlist()`.

| Property | Value |
|---|---|
| Purpose | Decide whether a hostname is covered by the allowlist |
| Algorithm | An exact set lookup, then a suffix sweep over the configured domains and the session domains |
| Time | O(n) in the allowlist, where n is the configured set plus up to 256 session entries |
| Space | O(n) |
| Correctness | The suffix sweep is `hostname.endswith("." + domain)`, which correctly matches a subdomain but not `evil-example.com` against `example.com` — the dot is what makes it safe |
| Edge cases | An empty domain in the set would match everything; the set is built from `_normalize_hostname()`, so an empty entry is possible in principle |
| Bottleneck | The suffix sweep, which is why the session set is capped |

**The dotted suffix is the important detail.** `hostname.endswith(".example.com")`
does not match `notexample.com`, and a naive `endswith("example.com")`
would. The implementation gets this right.

**Finding DSA-04 (Low, open): an empty string in the allowlist would match
every hostname.** The set is built from normalised hostnames, so an empty
entry is unlikely but not impossible. A one-line guard would remove the
possibility.

### 3.3 The signature matcher

`core/signature_matching.py` — the 150+ GhostJS signatures.

| Property | Value |
|---|---|
| Purpose | Find secrets and suspicious patterns in JavaScript bundles |
| Algorithm | A required-literal prefilter followed by a line-partitioned regex scan |
| Time | Linear in the corpus size, per signature |
| Space | O(1) per signature |
| Correctness | The DSA report records a **differential harness over a 434-entry corpus with 0 mismatches** |
| Bottleneck | Resolved |

**This was a live quadratic-backtracking defect** — 27 seconds on a 64 KB
response body. It was fixed with the prefilter and the line partition, and
the fix is protected by a differential harness. It is the best-quality
piece of engineering in the repository.

### 3.4 The RAG retrieval

`core/rag_engine.py`.

| Property | Value |
|---|---|
| Purpose | Retrieve the chunks that answer a question |
| Algorithm | BM25 with a per-chunk term-frequency vector persisted at ingest |
| Time | O(corpus) per query — two full-corpus passes, one for the document frequencies and one for the scoring |
| Space | O(corpus) |
| Correctness | The DSA report records a golden test requirement for the inverted-index rewrite |
| Bottleneck | The two passes |

**Finding DSA-05 (Medium, open): the RAG engine performs two full-corpus
passes per query.** The DSA report has tracked this as DSA-BE-06 since an
earlier pass. The fix is an inverted index built at ingest time, with the
scoring preserved bit-for-bit against a golden test.

### 3.5 The tool inventory detection

`core/scanner_integrations.py` — `_detect_tool_inventory()`.

| Property | Value |
|---|---|
| Purpose | Find the installed security binaries and their versions |
| Algorithm | `shutil.which` plus a registry of extra paths, then a version probe per tool |
| Time | O(tools × probe latency), 15 tools |
| Space | O(tools) |
| Correctness | The results are cached with a 60-second TTL |
| Bottleneck | The version probes spawn a process each |

**Finding DSA-06 (Medium, open): the inventory detection spawns 15
subprocesses.** With the 60-second cache that is 15 processes per minute
per consumer. The DSA report records that the invalidation was hoisted out
of the worker pool, which fixed the quadratic behaviour; the remaining cost
is the probes themselves.

### 3.6 The scope-policy DNS resolution

| Property | Value |
|---|---|
| Purpose | Resolve a hostname and classify every address |
| Algorithm | `socket.getaddrinfo` |
| Time | **10.5 ms median**, measured |
| Space | O(addresses) |
| Correctness | Every address is classified, not just the first |
| Bottleneck | **The resolution itself** — there is no cache, deliberately |

**The absence of a cache is a security decision, not an oversight.** A
cached answer is a stale answer, and a stale answer is exactly what a
rebinding attack exploits. The right fix is to resolve once and pin the
address to the connection, which is the same change that closes the
DNS-rebinding finding.

---

## 4. Dead code and unused symbols

| Rule | Count | State |
|---|---|---|
| `python:S1481` | 47 | **Fixed** — the dead stores were removed, or the unused element of a tuple unpacking was renamed to `_`. Class attributes and chained assignments were explicitly excluded from the transformation. |
| `python:S1172` | 19 | **Open** — unused method arguments |
| `javascript:S1854` | 21 | **Open** — useless assignments in `app.js` |
| `javascript:S1481` | 15 | **Open** — unused JS variables |
| `python:S6353` | 11 | **Open** — comprehension complexity |

The f-string cleanup removed **121 pointless `f` prefixes** across the
tree. It was verified mechanically: every string literal in the repository
is byte-identical before and after.

---

## 5. Duplication

| Rule | Count | Where |
|---|---|---|
| `javascript:S3358` | 85 | `web/static/app.js` — a 16 468-line single file |
| `python:S3358` | 44 | Four report generators that overlap in their HTML, PDF, JSON and CSV rendering |
| `python:S1192` / `S5869` | 125 | Duplicated string literals — mostly severity names, SQL fragments and the repeated metadata keys |

**Finding DSA-07 (Medium, open): the four report generators should share a
rendering core.** `reports/generator.py`, `reports/nessus_report_engine.py`,
`reports/vulnerability_reports.py` and `reports/enterprise_reports.py` each
render HTML, PDF, JSON and CSV. A fix to one has to be applied in four
places.

**Finding DSA-08 (Medium, open): the frontend's duplication is a
single-file problem.** The 85 duplicated blocks are the symptom; the cause
is 16 468 lines in one scope. ES modules solve it without a bundler.

---

## 6. Bandit's security-relevant patterns

290 findings. The full breakdown is in
`SNMK_SAST_SCA_SECRET_SCAN_REPORT.md` §3. The three that carry real
weight:

| Rule | Finding | Assessment |
|---|---|---|
| **B113** | 35 requests without a timeout | **Real.** A hung upstream holds a worker for the client's default timeout. |
| **B104** | The bind address is hard-coded | **Real in one place.** `SWA_HOST` is read by `run.py` but `web/server.py` hard-codes `0.0.0.0` on some paths. |
| **B607** | External binaries resolved through `PATH` | **Real.** A poisoned `PATH` substitutes the binary. |

The three `assert` statements (B101) were in `core/pattern_gating.py`
and `core/signature_matching.py` — not the plugin layer, as first recorded.
They have been replaced with explicit checks: an `assert` is stripped under
`python -O`, so a check could silently disappear in an optimised deployment.

---

## 7. Data structures

| Structure | Where | Assessment |
|---|---|---|
| The findings list | `core/database.py` | The table is indexed on `scan_id`, `severity`, `cvss_score`, `verified`, the status columns and the creation time — the filter and sort patterns are covered |
| The assets table | `core/database.py` | Indexed on the asset key, the type and the last-seen time |
| The kill-chain findings | `core/kill_chain/db.py` | Indexed on the stage, the severity and the risk score; the query orders by `risk_score DESC, created_at DESC`, which matches |
| The allowlist | `core/scope_policy.py` | A `set` for the exact lookups plus a bounded ordered dict for the session entries — correct for both lookup and eviction |
| The tool inventory | `core/scanner_integrations.py` | A class-level dict with a 60-second TTL — correct, and the invalidation is hoisted out of the worker pool |
| The subscriber queues | `core/queue_manager.py` | Bounded at 1 000 with oldest-first eviction |
| The sessions | `core/app_security.py` | An in-memory dict with a TTL check on read — the expired entries are removed on access, so there is no sweeper |
| The agent manifests | `core/agent_registry.py` | Rebuilt on every call — DSA-02 / PERF-09 |

**Finding DSA-09 (Low, open): the session store has no sweeper.** An
expired session is removed when it is presented, but a session that is
never presented again stays in the dictionary for the life of the process.
A periodic sweep would bound it.

---

## 8. Concurrency and memory

| Concern | State |
|---|---|
| The thread-local database connection | ✔ Each thread gets its own |
| The tool-install lock | ✔ A lock per tool, so two installs cannot race |
| The cancellation tokens | ✔ Checked between the steps |
| The background task registry | ✔ `queue_manager.active_tasks` |
| A global concurrency cap on the scans | **None** — PERF-10 |
| A global concurrency cap on the agent dispatch | **None** — AI-08 |
| Unnecessary data copies | The findings are loaded, then filtered in Python, in several endpoints — PERF-05 |
| The measured RSS | 145.1 MB after the import and 30 requests — comfortable |

---

## 9. Findings

| ID | Finding | Severity | Status |
|---|---|---|---|
| DSA-01 | `init_db()` is 3 173 lines and accounts for 26 % of the complexity findings | Medium | **Open** |
| DSA-02 | The kill-chain overview makes ~28 passes over the findings | Medium | **Open** |
| DSA-03 | A single-stage path is described as a "multi-stage intrusion chain" | Low | **Open** |
| DSA-04 | An empty allowlist entry would match every hostname | Low | **Open** |
| DSA-05 | The RAG engine performs two full-corpus passes per query | Medium | **Open** |
| DSA-06 | The inventory detection spawns 15 subprocesses | Medium | **Open** |
| DSA-07 | The four report generators duplicate each other | Medium | **Open** |
| DSA-08 | The frontend's 85 duplicated blocks come from a single-file design | Medium | **Open** |
| DSA-09 | The session store has no sweeper for the unpresented expired sessions | Low | **Open** |
| DSA-10 | 35 requests without a timeout | Medium | **Open** |
| DSA-11 | The bind address is hard-coded on some paths | Low | **Open** |
| DSA-12 | The external binaries are resolved through `PATH` | Medium | **Open** |
| DSA-13 | Three `assert` invariants are stripped under `python -O` (in `pattern_gating.py` and `signature_matching.py`, not the plugin layer) | Medium | **FIXED** — replaced with explicit checks |
| DSA-14 | 47 unused local variables | Low | **FIXED** |
| DSA-15 | 121 pointless `f` prefixes | Low | **FIXED** |
| DSA-16 | 2 abstract classes are instantiated | Medium | **Open** |
| DSA-17 | 19 unused method arguments | Low | **Open** |
| DSA-18 | 21 useless assignments and 15 unused JS variables | Low | **Open** |

---

## 10. Recommendations

| # | Action | Benefit | Effort |
|---|---|---|---|
| 1 | Split `init_db()` into one function per table, and add a `schema_version` row | Removes the largest complexity finding and makes the migration readable | Medium |
| 2 | Split `web/static/app.js` into ES modules | Removes the 85 duplicated blocks, the 51 complexity findings and the 21 useless assignments in one move | High |
| 3 | Consolidate the four report generators onto one rendering core | Removes the 44 duplicated Python blocks | High |
| 4 | Build the RAG inverted index at ingest time, with a golden test | Removes the double corpus pass | Medium |
| 5 | Reduce the kill-chain overview to a single bucketing pass | Removes the ~28 passes | Medium |
| 6 | Cache the agent manifests and invalidate on a registry change | Removes the 94 constructions per dashboard load | Low |
| 7 | Add the 35 missing timeouts | Bounds worker occupancy | Low |
| 8 | Replace the two `assert` statements in the plugin layer with explicit checks | Survives `python -O` | Low |
| 9 | Resolve the external binaries once and record the absolute path | Closes the `PATH` substitution | Low |
| 10 | Make the bind address configurable in `web/server.py` | Removes the hard-coded `0.0.0.0` | Low |
| 11 | Add a session-store sweeper | Bounds the in-memory growth | Low |
| 12 | Guard the allowlist against an empty entry | Removes the edge case | Low |

---

## 11. Assessment

**The algorithms are sound. The structure is the problem.**

Nothing in this audit found a correctness defect in the platform's data
structures or algorithms. The signature matcher is the best-engineered
piece of code in the repository and it carries a differential harness. The
scope policy's dotted-suffix matching is exactly right. The correlation is
linear and its deduplication key is deliberate and correct.

What the audit found instead is **concentration**: 3 173 lines in one
function, 10 319 in one module, 8 139 in another, 16 468 in a third. The
complexity findings are a symptom of that, and the duplicated blocks are a
symptom of that.

**Two changes would remove most of the debt:** split `init_db()` and split
`app.js`. Neither is a redesign. Both are mechanical. Neither is urgent in
the way the authentication bypass was — which is exactly why they can wait
for a scheduled piece of work rather than a security patch.
