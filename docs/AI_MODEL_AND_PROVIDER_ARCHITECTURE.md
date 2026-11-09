# AI MODEL AND PROVIDER ARCHITECTURE
## Audited 2026-11-07 — What actually exists in code

### 1. Providers (code reality)

| Provider | Wired in code | Auth mechanism | Model list source | Streaming | Tool calling |
|---|---|---|---|---|---|
| OpenAI | `OpenAIAdapter` probe (`GET /models`); chat path in `SWALLMClient` (`_call_llm`, chat/completions) | `Authorization: Bearer` | static `KNOWN_PROVIDER_MODELS` + live probe only via test endpoints | NO | NO |
| Anthropic | `AnthropicAdapter` probe; Messages API path (`anthropic-version: 2023-06-01`) | `x-api-key` | static catalog | NO | NO |
| Google Gemini | `GoogleGeminiAdapter` probe (`GET /v1beta/models?key=`); `generateContent` path | query `?key=` | static catalog | NO | NO |
| OpenRouter | `OpenRouterAdapter` probe (`GET /api/v1/auth/key`); OpenAI-compatible chat path | `Authorization: Bearer` + `HTTP-Referer`/`X-Title` | static catalog | NO | NO |
| Ollama (local) | `OllamaLocalAdapter` probe (`GET /api/tags`); OpenAI-compatible chat path | none (loopback) | static catalog | NO | NO |
| Azure OpenAI | **NOT IMPLEMENTED** (no adapter, no code path) | — | — | — | — |
| Deterministic fallback | `heuristic` provider in `SWALLMClient` | none | built-in | NO | Direct rule execution |

Default routing: `SWA_AI_PROVIDER=auto` → heuristic if no key; if a key is present in env (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENROUTER_API_KEY` / `SWA_AI_API_KEY` / `LLM_API_KEY`, placeholder-filtered) it selects that provider. Otherwise it falls back to the encrypted integrations vault via `integration_registry.get_default_ai_provider()`.

**No streaming, no function/tool calling anywhere.** History is truncated to the last 8 messages. Upstream errors are swallowed to a fixed notice string ("SWA AI Security Notice: Upstream LLM provider unavailable. Local heuristic fallback active.").

### 2. Fallback chain — simulated, not wired
`ai_models.fallback_model_id` is seeded (gpt-4o → claude-3-5-sonnet → gemini-1.5-flash → openrouter-default → ollama-local) but **never read by any executor**. Failure today is binary: LLM call succeeds or the client returns the heuristic notice string; it does not rotate providers.

### 3. Credential brokerage (real)
- `core/credentials.py`: Fernet (AES-128-CBC + HMAC-SHA256), PBKDF2-HMAC-SHA256 100k iterations, per-value 16-byte salt. Master key from `SWA_ENCRYPTION_KEY` or repo-root `.swa_master.key` (git-ignored).
- `core/integrations/registry.py`: `encrypted_credentials` table; `get_active_credential()` decrypts in-memory only for the outbound call; list APIs return masked values only.
- Legacy `ai_api_key` setting is now stored as `enc:v1:<cipher>:<salt>` (2026-11-07) with lazy in-place migration on first read; raw-key storage in the `settings` table is closed.
- `cryptography` fallback: if the package is missing, a non-authenticated HMAC-XOR cipher is used. **`cryptography` is a hard dependency in requirements.txt — do not remove it.**

### 4. Fail-safe execution flow (actual)
```text
Request → SWALLMClient._call_llm
   ├─ provider == 'heuristic' or no key → deterministic response text (labeled heuristic)
   └─ key present → provider HTTP call (30s timeout, no retries)
         ├─ success → response text
         └─ exception → fixed notice string (caller cannot distinguish failure from content)
```
The previous diagram ("transparent fallback to deterministic engine after provider failure") was aspirational; callers now at least get the notice, and Kill-Chain AI treats it as unavailable and uses its own deterministic path.

### 5. What is NOT verified
- Any real provider round trip (no valid keys on this machine; `.env` ships a placeholder).
- Token/cost metering (not implemented; reported as null).
- Azure OpenAI, Azure AD auth, managed identity: not present anywhere.
- Model behavior under tool-calling schemas: no tools schema is ever sent to a model.
