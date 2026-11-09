# COMPLETE AI SYSTEM INVENTORY & CAPABILITY MATRIX
## SNMK / SWA AI — Audited 2026-11-06/07 (post-remediation)

Legend for **Integration**: where the component is actually wired. Legend for **Test status**: PASS / FAIL / BLOCKED / NOT TESTED.
Statuses use: IMPLEMENTED AND VERIFIED, IMPLEMENTED BUT NOT VERIFIED, PARTIALLY IMPLEMENTED, NOT IMPLEMENTED, BLOCKED.

| AI component | Exists | Implementation | Integration | Test status | Required action / final status |
|---|---|---|---|---|---|
| LLM providers | YES | 5 real httpx probes: OpenAI, Anthropic, Gemini, OpenRouter, Ollama (`core/integrations/ai_providers.py`); Anthropic Messages API, Gemini generateContent, OpenAI-compatible chat completions in `core/llm_client.py` | Settings UI + integrations vault; env-var fallback | PASS (probe tests) / BLOCKED for live keys | PARTIALLY IMPLEMENTED. Live model round-trips BLOCKED (no real API keys configured; `.env` holds placeholders). |
| Model registry | YES | Central `ai_models` table, seed defaults, fallback chain field (`core/ai_models.py`); static `KNOWN_PROVIDER_MODELS` catalog | `/api/ai/models*` read/CRUD/test endpoints | PASS | PARTIALLY IMPLEMENTED. Static catalogs only; no dynamic `/models` sync into DB; `fallback_model_id` chain is stored but never consumed by the client. |
| API key management | YES | Fernet AES-128 + PBKDF2HMAC vault (`core/credentials.py`), per-value salt, key outside DB (env `SWA_ENCRYPTION_KEY` or `.swa_master.key`), masked display | `/api/integrations/*`, `/api/ai-agents*`, legacy `ai_api_key` setting now encrypted-at-rest with lazy migration | PASS | IMPLEMENTED AND VERIFIED (unit tests). Vault test/probe flow verified; zero-leakage responses confirmed by code review + tests. |
| Local inference (Ollama) | YES | `OllamaLocalAdapter` + `/api/tags` probe; `ollama` provider branch in `SWALLMClient` | Settings → integrations | NOT TESTED (no local runtime) | PARTIALLY IMPLEMENTED. Adapter exists; untested without a running Ollama daemon. |
| Embeddings | NO | None found anywhere in the codebase | — | NOT APPLICABLE | NOT IMPLEMENTED. |
| Vector storage | NO | None (no faiss/chroma/pinecone/qdrant; SQLite only) | — | NOT APPLICABLE | NOT IMPLEMENTED. |
| RAG | YES (BM25) | Hybrid keyword/BM25 engine, word-overlap chunking, phrase boost, citations, tenant `project_id` isolation (`core/rag_engine.py`) | Wired into `llm_client.reason()` with `use_rag=True`; exposed to API (`/api/ai/rag/*` referenced in docs — see `web/server.py`) | PASS (unit tests) | PARTIALLY IMPLEMENTED. Real but sparse retrieval; no dense embeddings; BM25 only. |
| Document ingestion | YES | Ingestion into `rag_documents`/`rag_chunks` via `rag_engine` API | Same as RAG | PASS | IMPLEMENTED AND VERIFIED for text ingestion. Binary/PDF extraction not implemented. |
| Multimodal AI | NO | None. No image/audio/video processing anywhere | — | NOT APPLICABLE | NOT IMPLEMENTED. (No use case present in repo.) |
| Agent registry | YES | 85 agents, 5 tiers, pydantic manifests with permission boundaries and timeouts (`core/agent_registry.py`, `agents/*`) | `/api/agents`, `/api/enterprise/agents/*`, dispatch pipeline | PASS | IMPLEMENTED AND VERIFIED for registry; execution honesty fixed 2026-11-07 (see below). |
| Agent runtime | YES | Tier-1 timeout-wrapped dispatch with DB persistence (`agents/agent_workforce.py`); tiers 2–5 dispatch in `core/agent_registry.py::dispatch_agent_by_id` | Orchestrator pipeline | PASS | PARTIALLY IMPLEMENTED. Tier 1 specialists are DB-summary tasks (not LLM/tool users). Tiers without handlers now report `NOT_EXECUTABLE` instead of fake success. |
| Agent memory | YES | Working/episodic/semantic SQLite `agent_memory_records`, secret-scrubbing regexes, token budgeting (`core/agent_memory.py`) | Wired into `llm_client.reason()` session memory (session_id) | PASS (unit tests) | IMPLEMENTED AND VERIFIED. |
| Multi-agent orchestration | YES | Sequential scan pipeline (recon → attack surface → vuln hunt → validation → remediation) in `agents/orchestrator.py`; bounded parallel dispatch (semaphore, 60s/agent) in `execute_all_85_agents` | `/api/agents/collaborate` — now a REAL dispatch pipeline (recon, dep-confusion, risk via `compute_posture`, exploit/remediation stages) | PASS | PARTIALLY IMPLEMENTED. Tier-3+ collaboration stages report NOT_EXECUTABLE honestly until handlers exist. |
| Tool calling (LLM function calling) | NO | None. No `tools`/`tool_calls` in any LLM path | — | NOT APPLICABLE | NOT IMPLEMENTED. Tool execution is deterministic adapters, not model-driven function calling. |
| MCP integration | NO | None | — | NOT APPLICABLE | NOT IMPLEMENTED. |
| AI workflows / automation | YES | Automation engine (`core/automation_engine.py`) with approval gates, audit logs | `/api/automation/*` | PASS (smoke) | PARTIALLY IMPLEMENTED. Steps now real where possible (recon/agent dispatch/risk/blue-team rules); `tool_run` steps are explicitly SIMULATED; unhandled types `NOT_EXECUTED`; overall status `COMPLETED_PARTIAL`. |
| Model evaluation | YES | Regex-signature classifier eval (macro P/R/F1, confusion matrix) + latency timing of live calls (`core/ai_evaluation.py`) | `/api/ai/evaluation/*` | PASS | IMPLEMENTED BUT NOT VERIFIED against a real model (regex "model" only; LLM path needs a key). |
| Fine-tuning | NO (simulated) | `core/ai_training.py` is a **simulation** (synthetic loss curve, fake `.bin` artifact); no torch/transformers in requirements | `/api/ai/training/*` | PASS (as simulation) | NOT IMPLEMENTED as real training. Do not present as model training. |
| AI observability | PARTIAL | Latency/count metrics via `ai_evaluations`; `/api/ai-agents/usage` now computed from persisted `agent_tasks` (tokens/cost honestly `null`) | `/api/ai-agents/usage`, audit logs | PASS | PARTIALLY IMPLEMENTED. No token/cost metering (reported as null, not fabricated). |
| AI security & governance | YES | Prompt-injection indicators, evidence redaction, LLM red-team harness (`core/llm_security_testing.py`), approval gates, audit trail, scope policy | `/api/ai/redteam/*`, `/api/approvals`, `core/audit.py` | PASS | PARTIALLY IMPLEMENTED. Heuristic regex harness only; no model-driven red-teaming without keys. |
| Kill-chain AI analysis | YES | `core/kill_chain/ai_analyzer.py` — was calling nonexistent `SWALLMClient.is_available()/.query()` (dead LLM path). Fixed 2026-11-07 to use `get_status()` + `reason()` | `/api/kill-chain/ai/analyze` | PASS (unit test updated) | IMPLEMENTED AND VERIFIED for fallback; AI-augmented path NOT VERIFIED (no key). |
| Threat intel (KEV/EPSS/enrich) | YES | NEW `core/threat_intel_live.py` — live CISA KEV JSON + FIRST EPSS API with 1h cache | `/api/v1/threat-intelligence/cisa-kev`, `/first-epss` (now live, 503 on feed failure) | NOT TESTED (until runtime check) | IMPLEMENTED BUT NOT VERIFIED until network probe. |

## Known fake/simulated artifacts removed on 2026-11-07
1. `execute_all_85_agents` marked everything SUCCESS with no execution → rewritten: real bounded dispatch, honest NOT_EXECUTABLE states.
2. `/api/ai-agents/usage` hardcoded (`total_requests: 142`, cost $0.042) → computed from `agent_tasks`; token/cost reported as null with note.
3. `/api/agents/collaborate` canned 6-stage output → real dispatch pipeline; stages report actual statuses.
4. v1 `/threat-intelligence/cisa-kev`, `/first-epss`, `/ai/models/status`, `/ai/models/test` hardcoded → live feeds / real client state / real adapter probes.
5. `enrich_indicator` claimed "sources_checked: VirusTotal…" without checking → now reports local repository only.
6. `automation_engine.execute_workflow` hardcoded step outputs → real scope/dispatch/risk/blue-team logic; `tool_run` explicitly SIMULATED; `report_gen` NOT_EXECUTED.
7. `web/ai_agent_api.py` heuristic-only provider catalogs documented as-is; `heuristic` pseudo-provider remains (deterministic, honestly labeled).
8. UI: `manageStatTokens` fallback `48200` → displays "—" when unmetered; badge "85 OPERATIONAL AGENTS" → "85 REGISTERED AGENTS".
9. `tool_registry` `backend_handler` strings pointing at nonexistent symbols → fixed to real symbols.
10. `.env` file was inert (never loaded) → `core/env_loader.py` now loads it (no new deps); `.env.example` documents `SWA_ENCRYPTION_KEY`/`SWA_API_TOKEN`.
11. Legacy `ai_api_key` setting stored plaintext in SQLite → AES-Fernet encrypted at rest with lazy migration on first read.
12. `KillChainAIAnalyzer` called nonexistent methods → fixed.
13. JS-scan endpoint imported nonexistent `js_intelligence_analyzer` (HTTP 500) → now uses `GhostJsAnalyzer.scan_url`.
14. v1 `/threat-intelligence/enrich` and `/incidents` crashed (TypeError) → fixed signatures.
15. Scope policy silently persisted arbitrary targets into `config/targets.json` → session-scoped authorization only; `SWA_ENFORCE_ALLOWLIST=1` now has real effect.
16. `run.py` defaulted to binding `0.0.0.0` → defaults to `127.0.0.1`.
17. v1 automation rules hardcoded → reads seeded workflows from automation engine.
18. Opt-in auth enforcement middleware added (`SWA_AUTH_ENABLED=true` or `SWA_API_KEY` set): `/api/*` requires master key or session token; public paths exempt.
19. `run_nmap_safe` ports argument now validated (flag-injection into nmap argv closed); leading-dash target guards added for nuclei/sqlmap/nmap.

## What we do NOT claim
- No model has been trained or fine-tuned anywhere in this repository.
- No dense vector embeddings exist.
- Live provider round-trips, tool-calling function schemas, and MCP servers do not exist.
- With placeholder API keys, the LLM runs in honest `heuristic_fallback` mode.
