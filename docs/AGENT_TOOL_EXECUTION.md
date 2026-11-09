# AGENT TOOL EXECUTION AND PARAMETER VALIDATION

> **Audit corrections applied 2026-11-07:**
> - Tool execution in this codebase is **deterministic adapters**, not LLM-driven tool calling. There is no `tools` schema sent to any model, no `tool_calls` parsing, and no agent autonomously "chooses" a tool. The "Function Calling" column in provider docs does not apply here.
> - **Schema validation** at the HTTP layer is real (Pydantic). `core/tool_registry.py` `ToolMetadata` is a *metadata catalog only* — its `backend_handler` strings were corrected on 2026-11-07 to point at real symbols, but nothing dynamically imports or dispatches them. Claims about "JSONSchema types before execution" and "sandboxed execution" are aspirational; there is no sandbox.
> - **SSRF**: validation is real (`core/scope_policy.py` — DNS rebinding check, RFC 1918/metadata/loopback denial). Dynamic authorization is session-scoped and never persists to `targets.json`; strict mode exists via `SWA_ENFORCE_ALLOWLIST=1`.
> - **Structured argv** is real for the binary adapters (`create_subprocess_exec`/`subprocess.run` with arg lists, no `shell=True`). Timeouts are enforced (3–60 s). The `run_nmap_safe` ports argument is now regex-validated (2026-11-07) to close nmap flag-injection.
> - **Output parsing** for nmap (XML) is real; nuclei JSONL parsing is real but untested on this host (binary absent). sqlmap requires explicit lab mode.
> - `/api/tools/{tool_id}/execute` executes a small set of handlers for real (`dns`, `headers`, `ssl`, `ports`, `whois`, `js-scan`, `waf`, …); unknown registered tools previously got a fake `OPERATIONAL` response — they now receive an explicit not-executed result.
>
> ## Deterministic Tool Adapters, Sandboxed Execution, and Schema Enforcement

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
