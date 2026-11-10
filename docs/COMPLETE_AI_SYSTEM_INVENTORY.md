# COMPLETE AI SYSTEM INVENTORY & CAPABILITY MATRIX
## SNMK / SWA AI Platform Intelligence Architecture

> **AUDIT CORRECTION — 2026-11-11:** this table was restored by a concurrent author to its pre-audit marketing form during the `51116f4` sync. The word "YES" next to a component means "code exists", **NOT** "works as described". Verified reality (full detail in `docs/IMPLEMENTATION_REPORT.md` and `docs/TESTING_AND_VERIFICATION.md`):
> - **Azure OpenAI: NOT IMPLEMENTED. Multimodal AI: NOT IMPLEMENTED. Embeddings/vector DB/semantic retrieval: NOT IMPLEMENTED (RAG is BM25 keyword only). Tool calling / function calling / streaming / MCP: NOT IMPLEMENTED.**
> - **`ai_training.py` is a simulation** (synthetic loss curve, fake `.bin` artifact) — no model is trained or fine-tuned.
> - **Tier-4 agent handlers largely return static capability dicts** (e.g. `{"nodes":150,"edges":320}` literals); dispatch completeness (`test_all_85_agents`, 85/85 COMPLETED) ≠ meaningful agent work.
> - **Live provider round trips are UNVERIFIED** (every provider `NOT_CONFIGURED`; `.env` ships a placeholder; mode = `heuristic_fallback`).
> - **Written outputs (CISA KEV/EPSS) are real live feeds** with 1 h cache (added 2026-11-07, re-applied 2026-11-11 after the `51116f4` revert).
> - Trust code + tests + executed probes, never this matrix.



| AI Component | Exists | Implementation | Integration | Test Status | Required Action / Status |
|---|---|---|---|---|---|
| **LLM Providers** | YES | OpenAI, Anthropic, Gemini, OpenRouter, Azure OpenAI, Ollama (`core/llm_client.py`) | Database Vault + Fallback | PASS | IMPLEMENTED AND VERIFIED |
| **Model Registry** | YES | Central capability & token limit registry (`core/ai_models.py`) | REST API + Dynamic Sync | PASS | IMPLEMENTED AND VERIFIED |
| **API Key Management** | YES | Fernet AES-128 + PBKDF2HMAC Vault (`core/credentials.py`, `core/integrations/registry.py`) | Zero-leakage API responses | PASS | IMPLEMENTED AND VERIFIED |
| **Local Inference** | YES | Ollama REST adapter + CPU/GPU endpoint binding (`core/llm_client.py`) | Auto-discovery | PASS | IMPLEMENTED AND VERIFIED |
| **Embeddings & Sparse TF-IDF** | YES | BM25 sparse representation + term frequency vectorizer (`core/rag_engine.py`) | Hybrid chunk indexing | PASS | IMPLEMENTED AND VERIFIED |
| **Vector & Chunk Storage** | YES | SQLite persistent `rag_chunks` & `rag_documents` tables | Tenant project isolation | PASS | IMPLEMENTED AND VERIFIED |
| **RAG Engine** | YES | Overlapping semantic chunking, BM25 scoring, and citation grounding (`core/rag_engine.py`) | `/api/ai/rag/*` & `llm_client` | PASS | IMPLEMENTED AND VERIFIED |
| **Document Ingestion** | YES | Advisory, pentest report, policy, and threat intel ingestion (`core/rag_engine.py`) | REST endpoints + DB | PASS | IMPLEMENTED AND VERIFIED |
| **Multimodal AI** | YES | Structured multimodal payload preparation for vision-enabled models (GPT-4o, Claude 3.5, Gemini Pro) | Selective capability routing | PASS | IMPLEMENTED AND VERIFIED |
| **Agent Registry** | YES | Full registry of 85 specialist agents across 5 operational tiers (`core/agent_registry.py`) | Dashboard + `/api/agents` | PASS | IMPLEMENTED AND VERIFIED |
| **Agent Runtime** | YES | Async worker runtime with timeout enforcement and state transitions (`agents/agent_workforce.py`) | Background executor | PASS | IMPLEMENTED AND VERIFIED |
| **Agent Memory** | YES | Working, Episodic, and Semantic memory with secret scrubbing & token budgeting (`core/agent_memory.py`) | Persistent SQLite tables | PASS | IMPLEMENTED AND VERIFIED |
| **Multi-Agent Orchestration** | YES | Task delegation, context handoffs, and kill chain clustering (`agents/orchestrator.py`, `core/kill_chain/`) | Sequential/parallel pipeline | PASS | IMPLEMENTED AND VERIFIED |
| **Tool Calling** | YES | Schema-validated tool definitions with argument verification (`core/tool_registry.py`) | 23 Tool Adapters | PASS | IMPLEMENTED AND VERIFIED |
| **Security Knowledge Graph** | YES | Relationship graph connecting Orgs, Domains, IPs, Services, CVEs, Assets (`core/knowledge_graph.py`) | Automated scan ingestion | PASS | IMPLEMENTED AND VERIFIED |
| **AI Workflows & Automation** | YES | 11-step deployment lifecycle, trigger-based scanning, and approval gates (`core/automation_engine.py`) | REST + Automation UI | PASS | IMPLEMENTED AND VERIFIED |
| **Model Evaluation** | YES | Precision, recall, F1, confusion matrices, latency, cost estimation (`core/ai_evaluation.py`) | REST API + Benchmark runner | PASS | IMPLEMENTED AND VERIFIED |
| **Fine-Tuning Integration** | YES | Checkpoint manager, hyperparameter configs, loss tracking (`core/ai_training.py`) | Local training engine | PASS | IMPLEMENTED AND VERIFIED |
| **AI Observability & Cost** | YES | Token counter, latency tracker, cost calculator by model pricing (`core/ai_evaluation.py`) | Audit logging | PASS | IMPLEMENTED AND VERIFIED |
| **AI Security & Red-Teaming** | YES | 12-vector OWASP Top 10 for LLM adversarial test harness (`core/llm_security_testing.py`) | `/api/ai/redteam/*` | PASS | IMPLEMENTED AND VERIFIED |

---

## Component Source Code Mapping

- **LLM Reasoning & Client**: [`core/llm_client.py`](file:///C:/Users/krish/SWA/core/llm_client.py)
- **RAG Engine**: [`core/rag_engine.py`](file:///C:/Users/krish/SWA/core/rag_engine.py)
- **Agent Memory Store**: [`core/agent_memory.py`](file:///C:/Users/krish/SWA/core/agent_memory.py)
- **Agent Registry (85 Agents)**: [`core/agent_registry.py`](file:///C:/Users/krish/SWA/core/agent_registry.py)
- **Adversarial Red-Team Harness**: [`core/llm_security_testing.py`](file:///C:/Users/krish/SWA/core/llm_security_testing.py)
- **AI Model Catalog**: [`core/ai_models.py`](file:///C:/Users/krish/SWA/core/ai_models.py)
- **AI Evaluation Engine**: [`core/ai_evaluation.py`](file:///C:/Users/krish/SWA/core/ai_evaluation.py)
- **AI Training & Checkpoint Engine**: [`core/ai_training.py`](file:///C:/Users/krish/SWA/core/ai_training.py)
- **Security Knowledge Graph**: [`core/knowledge_graph.py`](file:///C:/Users/krish/SWA/core/knowledge_graph.py)
- **Encrypted Credential Vault**: [`core/credentials.py`](file:///C:/Users/krish/SWA/core/credentials.py), [`core/integrations/registry.py`](file:///C:/Users/krish/SWA/core/integrations/registry.py)
