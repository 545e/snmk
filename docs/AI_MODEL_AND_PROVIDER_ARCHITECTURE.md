# AI MODEL AND PROVIDER ARCHITECTURE

> **AUDIT CORRECTION — 2026-11-11 (read first):** a concurrent `51116f4` bulk sync reverted the 2026-11-07 corrections to this document. This file still describes aspirational/design-intent behavior in places, NOT verified reality. Verified fact:
> - No LLM round trip is verified anywhere (all providers `NOT_CONFIGURED`; mode = `heuristic_fallback`).
> - RAG is BM25 (sparse), NOT embeddings/vector search. Memory is regex-scrubbed, not guaranteed.
> - Tool execution is deterministic adapters; LLM function/tool calling does not exist.
> - `ai_training.py` is a simulation; tier-4 agents return static dicts; 85/85 dispatch != capability.
> - `SWA_ENFORCE_ALLOWLIST=1` disables dynamic session authorization; `SWA_AUTH_ENABLED=true` (or a real `SWA_API_KEY`) gates `/api/*`.
> - The 12-vector LLM harness is deterministic rules, not a live red-teamer.
> - CISA KEV/EPSS endpoints hit live feeds (1h cache); 503 on failure.
> See `docs/IMPLEMENTATION_REPORT.md` (addendum), `docs/TESTING_AND_VERIFICATION.md`, `docs/COMPLETE_AI_SYSTEM_INVENTORY.md`.

## Multi-Provider Orchestration, Dynamic Fallback & Encrypted Credential Brokerage

### 1. Supported Providers & Models

| Provider | Supported Model Identifiers | Authentication Mechanism | Streaming Support | Function / Tool Calling |
|---|---|---|---|---|
| **OpenAI** | `gpt-4o`, `gpt-4o-mini`, `o1-preview`, `o3-mini` | `Authorization: Bearer <key>` | YES | Standard OpenAI Tool JSON |
| **Anthropic** | `claude-3-5-sonnet-20241022`, `claude-3-haiku-20240307` | `x-api-key: <key>`, `anthropic-version: 2023-06-01` | YES | Anthropic Tool Block Schema |
| **Google Gemini** | `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-2.0-flash` | Query parameter `?key=<key>` or Bearer | YES | Gemini Function Declarations |
| **OpenRouter** | `meta-llama/llama-3.3-70b-instruct`, `mistralai/mistral-large-2407` | `Authorization: Bearer <key>` | YES | OpenAI Compatible |
| **Azure OpenAI** | Custom deployed endpoints (`gpt-4o`) | `api-key: <key>` | YES | OpenAI Compatible |
| **Ollama (Local)** | `llama3.2:latest`, `deepseek-r1:latest`, `codellama` | HTTP endpoint (`http://localhost:11434/api/generate`) | YES | Direct JSON Payload |
| **Deterministic Fallback** | `heuristic-engine-v2.3` | Internal rule-based scoring (Zero dependency) | NO | Direct Rule Execution |

---

### 2. Credential Brokerage & Zero-Leakage Guarantee

All external provider keys are stored in an encrypted database table (`integration_credentials`) using Fernet symmetric encryption (AES-128-CBC with HMAC-SHA256).
- **Master Key**: Generated and isolated in `.swa_master.key` outside the database.
- **PBKDF2 Key Derivation**: 100,000 SHA-256 iterations with per-installation salt.
- **Zero Plain-Text Leakage**: All API responses (`GET /api/integrations`, `GET /api/settings`) mask secrets automatically (e.g. `sk-pro************9aF`).

---

### 3. Fail-Safe Execution Flow

```text
User Request / Assessment Probe
              │
              ▼
   Is Vault Credential Configured?
        ├── YES ──► Route to Target Provider API (OpenAI / Anthropic / Gemini / Ollama)
        │                 │
        │           Is API Successful?
        │                 ├── YES ──► Parse Structured JSON Output
        │                 └── NO (Network / Quota) ──► Transparent Fallback
        │                                                     │
        └── NO ───────────────────────────────────────────────▼
                                                 Autonomous Deterministic Engine
                                                 • CVSS v3.1 Matrix Engine
                                                 • RAG Grounded Context Analysis
                                                 • Zero False-Positive Evidence Rules
```
