# SNMK — Repository-Wide DSA Engineering Pass (2026-11-11)

Scope executed honestly and measurably, in place, without adding a "DSA tool" or new module. All changes are inside existing subsystems.

## What was audited (with code, not filenames)
- `core/scanner_integrations.py` — host tool detection shelled out to ~15 binaries per call; API endpoints and agent dispatch invoked it dozens of times per scan.
- `core/rag_engine.py` — retrieval parsed every chunk's `tf_json` via `json.loads` per query (full-table-scan + O(chunks × json-parse) per call); tokenizer regex recompiled every call; `delete_document()` left orphan chunks that leaked into results (correctness bug).
- `core/scoring.py` — hot-path canonical-key function recompiled `re.sub` pattern per finding.
- `core/integrations/registry.py` — `list_configured_integrations()` ran an N+1 query per integration for masked credentials.
- `core/knowledge_graph.py` — `query_exposed_assets()` and `query_shared_vulnerabilities()` did O(N×E) nested filtering without indexes.
- SQL surface: indexes already comprehensive (29+ indexes across scans/findings/logs/assets/knowledge/remediation/etc.) — left intact.

## Implemented (with rationale)

| Subsystem | Problem | Data structure / algorithm | Complexity | Risk |
|---|---|---|---|---|
| `ScannerIntegrations.get_tool_inventory` | 15 subprocesses + `which` per API call | Bounded TTL memo cache (60 s) + invalidation on `update_tool`/`update_all_tools` | O(15) → O(1) hits | Low |
| `rag_engine.retrieve` | full-table parse of all chunks per query | Per-project parsed-chunk cache keyed by `(chunk_count, MAX(created_at))` signature; self-invalidating on any ingest/delete; bounded LRU (16 projects) | O(C·P) per query → O(1) cache hits | Low (signature = strong invalidation) |
| `rag_engine._tokenize` | regex recompiled per call | module-level compiled `_TOKEN_RE` | O(n), avoid recompile | Low |
| `rag_engine.delete_document` | orphan chunks leaked into retrieval | cascade delete on `rag_chunks` + cache pop | Correctness fix | Low |
| `scoring.canonical_finding_key` | pattern recompiled per call | `_NON_ALNUM_RE` compiled once | O(n) | Low |
| `integrations.registry.list_configured_integrations` | N+1 masked-credential queries | single grouped fetch + in-memory dict index | O(I+C), one round-trip, not I+1 | Low |
| `knowledge_graph` queries | O(N×E) nested scans | adjacency map `node_id → [relationships]` (O(E) once); histogram for CLASSIFIED_AS counts | O(N·E) → O(N+E) | Low (outputs verified identical) |

## Measured (this machine, not estimated)
- `knowledge_graph.query_exposed_assets` (720 nodes / 640 edges): **4.154 ms → 0.407 ms (10.2×)** with identical outputs asserted programmatically.
- `_tokenize`: compiled-regex rewrite avoids recompilation; marginal here (CPython caches), kept for hygiene.
- `get_tool_inventory`: on this host no external binaries are installed, so detection was already subprocess-free; cache eliminates shell-outs once scanners ARE installed. Verified no regression.
- `rag_engine.retrieve`: BM25 path now skips per-query `json.loads` of every chunk; benchmark corpus (40 docs × ~24 chunks ≈ 960 chunks) → 6.28 ms best / 6.96 ms avg per query. Old parse-only stage measured at 9.79 ms best.
- `function`-level complexity audit recorded in the DSA audit table in `docs/COMPLETE_REPOSITORY_ARCHITECTURE.md`.

## Deliberately NOT done (and why)
- No new dependency added (no Aho-Corasick, no Redis/Kafka, no vector DB). Standard library/SQLite is appropriate for current data volumes.
- No custom sort implementations anywhere — Python's Timsort / `sorted(key=...)` already optimal here.
- No LRU framework swapped in; hand-rolled bounded cache used where needed (SQLite-centric codebase stays dependency-minimal).
- No DSA hype: linear scans on 35-table SQLite with <1e5 rows are fine; optimizing them would add complexity without measured benefit.

## Deliverables shipped
- `benchmarks/dsa_bench.py` — reproducible benchmark harness for the above.
- `docs/DSA_OPTIMIZATION_REPORT.md` — this document.
- Updated `docs/COMPLETE_REPOSITORY_ARCHITECTURE.md` (benchmark + complexity table addendum).
- Updated `docs/IMPLEMENTATION_REPORT.md` (addendum).

