# AGENT TOOL EXECUTION AND PARAMETER VALIDATION

> **AUDIT CORRECTION — 2026-11-11 (read first):** a concurrent `51116f4` bulk sync reverted the 2026-11-07 corrections to this document. This file still describes aspirational/design-intent behavior in places, NOT verified reality. Verified fact:
> - No LLM round trip is verified anywhere (all providers `NOT_CONFIGURED`; mode = `heuristic_fallback`).
> - RAG is BM25 (sparse), NOT embeddings/vector search. Memory is regex-scrubbed, not guaranteed.
> - Tool execution is deterministic adapters; LLM function/tool calling does not exist.
> - `ai_training.py` is a simulation; tier-4 agents return static dicts; 85/85 dispatch != capability.
> - `SWA_ENFORCE_ALLOWLIST=1` disables dynamic session authorization; `SWA_AUTH_ENABLED=true` (or a real `SWA_API_KEY`) gates `/api/*`.
> - The 12-vector LLM harness is deterministic rules, not a live red-teamer.
> - CISA KEV/EPSS endpoints hit live feeds (1h cache); 503 on failure.
> See `docs/IMPLEMENTATION_REPORT.md` (addendum), `docs/TESTING_AND_VERIFICATION.md`, `docs/COMPLETE_AI_SYSTEM_INVENTORY.md`.

## Deterministic Tool Adapters, Sandboxed Execution, and Schema Enforcement

### 1. Tool Execution Safety Model

All tools executed by autonomous agents pass through `core/tool_registry.py` and enforce:
1. **Schema Validation**: Parameters are validated using Pydantic and JSONSchema types before execution.
2. **SSRF Guardrail**: Target URLs and IP addresses are validated against `config/targets.json` and RFC 1918 / cloud metadata loopback filters.
3. **Structured Argument Passing**: No raw shell string concatenation. Process invocation utilizes explicit argument lists via `subprocess.Popen` or native Python async calls.
4. **Execution Timeouts**: Hard timeouts (e.g. 15s to 90s) prevent indefinite hangs.
5. **Output Normalization**: Raw command output is parsed into structured findings, HTTP request/response evidence, and CVSS metadata.

---

### 2. Primary Tool Capabilities

| Tool Adapter | Internal / External | Purpose | Timeout |
|---|---|---|---|
| `port_scanner` | Native Python Socket | Non-blocking TCP/UDP port enumeration | 30s |
| `http_crawler` | Native HTTPX Client | Deep DOM and REST API parameter extraction | 45s |
| `sqli_engine` | Native Python Engine | Boolean, time-based, and error-based SQLi verification | 60s |
| `xss_prober` | Native Python Engine | Reflected, stored, and DOM-based XSS verification | 30s |
| `ssrf_prober` | Native Python Engine | Cloud IMDSv1/v2 and internal loopback probe | 30s |
| `cors_prober` | Native Python Engine | Origin reflection and credentialed CORS leak test | 20s |
| `ssl_cipher_auditor` | Native SSL / Socket | TLS 1.0/1.1 deprecation and weak cipher detection | 25s |
| `header_analyzer` | Native HTTPX Client | Strict CSP, HSTS, X-Frame-Options audit | 15s |
| `llm_redteam_harness` | Native Async Engine | 12-vector OWASP Top 10 for LLM adversarial test | 90s |
| `waf_bypass_engine` | Native Python Engine | Header mutation and chunked encoding probe | 45s |
| `knowledge_graph_ingest` | Native SQLite Graph | Entity and relationship mapping | 20s |
