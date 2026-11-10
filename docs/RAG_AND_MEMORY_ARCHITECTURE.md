# RAG AND AGENT MEMORY ARCHITECTURE

> **AUDIT CORRECTION — 2026-11-11 (read first):** a concurrent `51116f4` bulk sync reverted the 2026-11-07 corrections to this document. This file still describes aspirational/design-intent behavior in places, NOT verified reality. Verified fact:
> - No LLM round trip is verified anywhere (all providers `NOT_CONFIGURED`; mode = `heuristic_fallback`).
> - RAG is BM25 (sparse), NOT embeddings/vector search. Memory is regex-scrubbed, not guaranteed.
> - Tool execution is deterministic adapters; LLM function/tool calling does not exist.
> - `ai_training.py` is a simulation; tier-4 agents return static dicts; 85/85 dispatch != capability.
> - `SWA_ENFORCE_ALLOWLIST=1` disables dynamic session authorization; `SWA_AUTH_ENABLED=true` (or a real `SWA_API_KEY`) gates `/api/*`.
> - The 12-vector LLM harness is deterministic rules, not a live red-teamer.
> - CISA KEV/EPSS endpoints hit live feeds (1h cache); 503 on failure.
> See `docs/IMPLEMENTATION_REPORT.md` (addendum), `docs/TESTING_AND_VERIFICATION.md`, `docs/COMPLETE_AI_SYSTEM_INVENTORY.md`.

## Grounded Cybersecurity Intelligence, Tenant Isolation, and Secret Scrubbing

### 1. Retrieval-Augmented Generation (RAG) Architecture

The platform's RAG system (`core/rag_engine.py`) grounds AI reasoning in verified security documentation, CVE advisories, pentest reports, and compliance policies:

```text
Document (Advisory / Pentest Report / Policy)
                    │
                    ▼
          Semantic Token Chunking
       (250 words / 40-word overlap)
                    │
                    ▼
     BM25 / TF-IDF Sparse Vectorization
                    │
                    ▼
      SQLite Storage (`rag_chunks`)
       Indexed by `project_id` & `doc_id`
                    │
     [User Threat Reasoning Request]
                    │
                    ▼
        Hybrid BM25 Term Matching
                    │
                    ▼
          Citation Grounding Header
    "[CVE-2026-9011 - Chunk #1] (cve_advisory): ..."
                    │
                    ▼
        LLM / Heuristic Reasoning Response
```

#### Key Capabilities:
- **Tenant Project Isolation**: All chunk queries enforce `WHERE project_id = ?`, preventing cross-workspace data leakage.
- **Strict Citations**: Every grounding context block includes the document title, chunk index, and source category.
- **Zero Hallucination Anchor**: If no matching documents meet the relevance threshold, the engine explicitly reports ungrounded status rather than fabricating context.

---

### 2. Multi-Tier Agent Memory System

Managed by `core/agent_memory.py`:

| Memory Tier | Scope | Storage Mechanism | Retention Policy |
|---|---|---|---|
| **Working Memory** | Active Task / Scratchpad | Process Memory / Fast Buffer | Cleared upon task completion |
| **Episodic Memory** | Session Interaction History | SQLite `agent_memory_records` | Token budgeted (default: 4,000 tokens) |
| **Semantic Memory** | Learned Asset / Target Attributes | SQLite Knowledge Graph & Entities | Persistent across assessments |

#### Security & Secret Scrubbing:
Before any user turn, prompt, or tool output is committed to memory, `redact_secrets_from_text()` executes regex inspection against:
- OpenAI API keys (`sk-...`)
- GitHub Personal Access Tokens (`ghp_...`)
- Slack tokens (`xoxb-...`)
- Authorization headers (`Bearer ...`)
- Raw password and API key assignments

All matches are scrubbed to `[REDACTED_SECRET]`, guaranteeing that credentials are never stored in memory logs or conversational context.
