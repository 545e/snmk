# SNMK / SWA AI — Engineering Remediation & Verification Report
**Date:** November 7, 2026 (updated after remediation + re-verification)
**Scope:** Full audit of the `snmk` platform (SWA AI), root-cause repairs across backend, AI systems, security controls, automation, tooling, and frontend honesty, followed by re-verification.
**Official Repository:** `https://github.com/545e/snmk.git` (local: `C:\Users\krish\SWA`, branch `generation-2-complete-modernization`)
**Application URL:** `http://127.0.0.1:8000`
**Data preservation:** `swa_data.db` backed up to `backups/swa_data_preaudit_20261106.db` before any change (18,862,080 bytes). No rows, migrations, or schema were deleted or dropped. All migrations are additive-only and were not required.

---

## EXECUTIVE SUMMARY (HONEST)

- **Baseline (before changes):** 235 tests passed — but many "passes" encoded fake behavior (endpoints returning canned success, agents marked COMPLETED at 0 ms, hardcoded metrics). Real breakage existed: 4 runtime-crashing endpoints, an inert `.env`, an allowlist that silently rewrote itself, a plaintext API-key-at-rest setting, and a public `0.0.0.0` default bind.
- **After remediation:** full suite re-run **239 passed, 0 failed (488.7 s)** on Python 3.12. All changes were made with the running DB, schema, users, and credentials preserved. No credentials were revoked, rotated, or overwritten; the legacy plaintext `ai_api_key` value was **encrypted in place lazily** on first read.
- **What still is NOT done** — see **§ Remaining blockers**. This is not a production-certified release; it is an audited codebase with honest status reporting.

---

## A. Repository understanding (verified)

- **Product name:** SWA AI (Security Workflow Automation AI) — preserved.
- **Stack:** Python 3.12 / FastAPI / SQLite (WAL) / vanilla JS SPA (no framework) / Uvicorn. Single process, background asyncio tasks, WebSocket fan-out, in-memory pub/sub queue (no external worker).
- **Database:** `swa_data.db` (SQLite, WAL), ~55 tables total across modules, additive migrations only.
- **Startup:** `python run.py` (host now defaults to `127.0.0.1`, was `0.0.0.0`), or `uvicorn web.server:app`. `.env` is now loaded by the launchers via `core/env_loader.py` (no new dependency).
- **Not git-managed secrets:** `.env`, `swa_data.db`, `.swa_master.key` are git-ignored and were never committed. `.swa.pid` stale — runtime debris (git-ignored).
- **Two divergent AI-agent credential/catalog systems exist** (`integrations`+`encrypted_credentials` vs `ai_agents` table; `KNOWN_PROVIDER_MODELS` vs `PROVIDER_CATALOG`) — documented, not merged (merging would risk breaking working paths).
- **`SWA/` nested stale duplicate tree** exists in the working directory (old copies of run.py/server.py) — left untouched; user was not authorized to delete it.

## B. Complete AI understanding (as found)

Discovered and classified every AI subsystem; see `docs/COMPLETE_AI_SYSTEM_INVENTORY.md` for the full matrix. Headline classifications:
- **Real:** provider adapters (connection probes), Fernet credential vault, RAG (BM25), agent memory, knowledge graph, regex LLM red-team harness, AI evaluation (regex classifier), REA engine, orchestrator scan pipeline.
- **Simulated / fake (fixed 2026-11-07):** `execute_all_85_agents` (0 ms fake SUCCESS), `/api/ai-agents/usage` (hardcoded 142/$0.042/48,250 tokens), `/api/agents/collaborate` + v1 mirror (canned stages), v1 `/cisa-kev`, `/first-epss`, `/ai/models/status`, `/ai/models/test`, `enrich_indicator` (claimed VirusTotal/OTX sources unqueried), automation engine step outputs, `/api/tools/{id}/execute` fake `OPERATIONAL`, JS-scan ImportError 500, kill-chain LLM path calling nonexistent `SWALLMClient.is_available()/.query()`, tool_registry `backend_handler` → nonexistent symbols.
- **Partially fake (left as committed by owner, documented):** tier-4 agent handlers return static capability dicts (`{"nodes":150,"edges":320}`-style literals) — code executes, numbers are illustrative literals, not measurements. The test `test_all_85_agents` asserts 85/85 COMPLETED, not 85/85 meaningful.
- **NOT IMPLEMENTED (and not claimed):** dense embeddings, vector DB, LLM function/tool calling, streaming, MCP, Azure OpenAI, multimodal, real model training (ai_training is a simulation), inbound LLM auth enforcement by default.

## C. AI implementation matrix

See `docs/COMPLETE_AI_SYSTEM_INVENTORY.md`. Summary: no component is rated above "PARTIALLY IMPLEMENTED" except the credential vault (IMPLEMENTED AND VERIFIED) and the registry (IMPLEMENTED AND VERIFIED for registration). Every "VERIFIED" claim is backed by a passing test or a direct probe.

## D. Provider verification

| Provider | Credential | Authentication | Model request | Tool calling | Result |
|---|---|---|---|---|---|
| OpenAI | placeholder in `.env` | UNTESTED (no key) | UNTESTED | N/A (not implemented) | NOT_CONFIGURED |
| Anthropic | none configured | UNTESTED | UNTESTED | N/A | NOT_CONFIGURED |
| Google Gemini | none configured | UNTESTED | UNTESTED | N/A | NOT_CONFIGURED |
| OpenRouter | none configured | UNTESTED | UNTESTED | N/A | NOT_CONFIGURED |
| Ollama (local) | n/a | UNTESTED (no daemon) | UNTESTED | N/A | UNTESTED |
| heuristic (built-in) | none | n/a | deterministic, honest fallback | n/a | PASS |

Live connection probes and model round-trips are BLOCKED pending a real, user-authorized API key (and explicit approval for any billable call).

## E. Agent verification (by code path, honest)

| Tier | Handlers wired | Honest status |
|---|---|---|
| 1 Specialist workforce (17) | DB-summary execution via `agents/agent_workforce.py` (Supervisor returns a static 19-step plan) | REGISTERED + executable (DB summaries), NOT LLM agents |
| 2 Offensive recon (9) | recon/attack-surface/fuzzer/dep-confusion/vuln-hunter/exploit-validator/remediation all wired (Nov 8); 8–90 s timeouts | REAL handlers (refused-port safe), results honest |
| 3 OWASP plugins (10) | real plugin probe + optional LLM synthesis | REAL (deterministic probe; LLM optional) |
| 4 Core engines (32) | generic import handlers added 2026-11-08 (`11f54d9`); **mostly static capability dicts** — a few do real work (`scope_enforcement_policy`) | PARTIAL — outputs are not measurements |
| 5 Tool adapters (17) | tool inventory lookup | REGISTERED + status lookup, not execution |

`execute_all_85_agents` performs real dispatches (semaphore 4, 120 s timeout/agent) and reports `COMPLETED`/`FAILED`/`NOT_EXECUTABLE` per agent and `COMPLETED`/`DEGRADED` overall. `tests/test_all_85_agents.py` asserts all 85 complete; we fixed a fuzzer timeout to keep it green — dispatch completeness ≠ capability.

## F. Tool verification

| Tool | Dependency | Installation | Execution | Parsing | Result |
|---|---|---|---|---|---|
| swa_native suite | Python | YES | YES (native engines) | YES | PASS (unit tests) |
| microsoft_defender | PowerShell | YES | PARTIAL (status query) | YES | PARTIAL |
| nmap/nuclei/sqlmap/nikto/… | external binaries | **NO (absent on host)** | blocked | n/a | NOT INSTALLED (honest) |
| amass | binary | NO | blocked | n/a | NOT INSTALLED |
| REA CLI | binary | NO | native fallback works | YES (native) | PASS (native path) |

## G. API verification (high level)

~331 endpoints across `web/server.py` (176), `/api/v1` (78), enterprise (39), AI-agents (14), kill-chain (24). Fixed crashes: js-scan ImportError, v1 enrich/incidents TypeErrors. Hardened: opt-in auth enforcement middleware (`SWA_AUTH_ENABLED=true` or real `SWA_API_KEY`), SSRF scope leak closed, nmap ports flag-injection closed, plaintext AI key encrypted. Response schemas preserved (no breaking contract changes except where documented in docs/API_INVENTORY.md).

## H. UI/UX implementation

Frontend unchanged in structure (identity preserved). Honest fixes: token stat shows "—" when unmetered (was fabricated `48200`), "85 OPERATIONAL AGENTS" badge → "85 REGISTERED AGENTS". No pages were redesigned in this pass; visual redesign was out of safe scope this session and no fake controls were added — remaining UI debt listed in § M.

## I. Database and preservation

- `swa_data.db` backed up to `backups/swa_data_preaudit_20261106.db` before any code change; no tables dropped/altered; additive-only pattern preserved; seed defaults (automation workflows) NOT rewritten in the local DB.
- The legacy plaintext `settings.ai_api_key` is encrypted **in place, lazily, on first read** (`enc:v1:`); zero data loss, zero rotation, no revocation.
- No migration required for any fix. WAL mode and `PRAGMA quick_check` unchanged.

## J. Dependency upgrades

**None applied.** No dependency was upgraded this pass — every proposed bump was judged more risky than valuable for the audit scope. Known items documented for the maintainer: fastapi TestClient deprecation (starlette), no `cryptography` fallback allowed to engage, `requirements-dev` has only pytest+cov (fine).

## K. Files changed (2026-11-07)

- `run.py` — env loading via `core/env_loader.py`; host default `127.0.0.1` (was `0.0.0.0`)
- `swa_cli.py` — env loading at startup
- `core/env_loader.py` — NEW: minimal .env parser (no deps)
- `core/credentials.py` — added `encrypt_secret_value`/`decrypt_secret_value`/`is_encrypted_secret_value`
- `core/scope_policy.py` — `_allowlist_enforced()` (SWA_ENFORCE_ALLOWLIST); session-scoped dynamic authorization (no more silent persistence to targets.json)
- `core/scanner_integrations.py` — nmap ports regex validation + leading-dash guards (nmap/nuclei/sqlmap)
- `core/threat_intel_live.py` — NEW: live CISA KEV + FIRST EPSS fetchers with 1h cache
- `core/agent_registry.py` — honest `NOT_EXECUTABLE` path in dispatch; `execute_all_85_agents` rewritten (bounded real dispatch)
- `core/automation_engine.py` — step handlers now real/honest; seeded defaults point at registered agents
- `core/kill_chain/ai_analyzer.py` — fixed nonexistent API calls; deterministic fallback retained
- `core/tool_registry.py` — `backend_handler` metadata strings corrected to real symbols
- `core/kill_chain/ai_analyzer.py`, `web/kill_chain_router.py` — async LLM path fixed
- `web/server.py` — JSONResponse import; opt-in auth enforcement middleware; `.env` no longer loaded at import (launchers do it); legacy ai_api_key encrypted at rest + lazy migration reader; tool-execute js-scan fixed; scope auto-authorize persistence removed
- `web/v1/router.py` — live KEV/EPSS, real AI status/test, honest automation rules, fixed enrich/incidents calls
- `web/ai_agent_api.py` — real usage metrics from `agent_tasks`; collaborate = real dispatch pipeline
- `web/enterprise_api.py` — threat-intel enrich reports local repo only (no fake "sources_checked")
- `web/static/app.js` — token stat renders "—" when unmetered
- `web/static/index.html` — badge honesty fix
- `config/*` — untouched (targets.json belongs to the operator)
- Docs: COMPLETE_AI_SYSTEM_INVENTORY.md (rewritten honest), SECURITY_TOOL_INVENTORY.md (rewritten honest), AI_MODEL_AND_PROVIDER_ARCHITECTURE.md (rewritten honest), AI_AGENT_ARCHITECTURE.md, MULTI_AGENT_WORKFLOWS.md, AGENT_TOOL_EXECUTION.md, AI_SECURITY_AND_GOVERNANCE.md, RAG_AND_MEMORY_ARCHITECTURE.md, API_INVENTORY.md (corrections header), COMPLETE_REPOSITORY_ARCHITECTURE.md (corrections), TESTING_AND_VERIFICATION.md (see § L), IMPLEMENTATION_REPORT.md (this file)
- Tests: `tests/test_cyber_kill_chain_suite.py` (asyncio.run for async analyzer), `tests/test_ai_automation_and_operations.py` (expect honest `COMPLETED_PARTIAL` + real step statuses)
- `.env.example` — documents `SWA_ENCRYPTION_KEY`, `SWA_API_TOKEN`

## L. Test evidence

- **Baseline (pre-change):** 235 passed, 0 failed — but the suite enshrined several fake behaviors.
- **Post-change run 1 (2026-11-09, same tree):** **81 failed / 156 passed** — every failure was HTTP 401 caused by my `.env` loader running at `web.server` import (a placeholder `SWA_API_KEY` in `.env` was treated as configured by my middleware). Root-caused and fixed (import-time load removed; placeholder keys ignored when `SWA_AUTH_ENABLED=false`). The one non-auth failure in that run (`test_ai_automation_and_operations::test_03`) exposed the fake-COMPLETED automation statuses; the test was updated to assert the honest `COMPLETED_PARTIAL`.
- **Post-change run 2 (2026-11-09, combined tree):** **238 passed / 1 failed**. The one failure was the concurrent session's `tests/test_all_85_agents.py`: `assert 84 == 85` — `fuzzer_agent` exceeded the 60 s per-agent dispatch timeout under suite load (~36 s standalone). Fix: per-agent dispatch timeout 60 s → 120 s in `core/agent_registry.execute_all_85_agents` (plus matching error string). `tests/test_all_85_agents.py` re-run in isolation: **PASS (89 s)**.
- **Run 3 (full suite re-run with the fix):** **239 passed, 0 failed** (488.7 s, 2026-11-11). This includes the live CISA KEV / FIRST EPSS tests hitting the real feeds. Treat this run as authoritative; the earlier "100% green" claims in repository history were not backed by comparable measurement.
- **Live HTTP probes against a running instance** (2026-11-09, port 8010, `run.py`): `/health` OK; `/api/system/status` → HEALTHY(7) with 2 honestly NOT_CONFIGURED; `/api/ai/status` → NOT_CONFIGURED / `heuristic_fallback`; `/api/ai/llm-status` → `heuristic`, `has_api_key:false`; `/api/ai-agents/usage` → real counts from DB (3 configured / 1 CONNECTED pre-existing record); `/api/agents/summary` → 85 registered across 5 tiers; `/api/v1/ai/models/status` → real client state (`HEURISTIC_FALLBACK`, default_model gpt-4o); `/api/settings` → `has_api_key:false` (no plaintext key stored or returned); `/api/tools/registry` → 34 tools served. CISA KEV feed verified reachable (catalog 2026.11.06, 1769 entries); FIRST EPSS API verified (CVE-2021-44228: epss 0.99999).
- **CI (`.github/workflows/ci.yml`)**: not executed from this machine; GitHub Actions results unchanged this pass.

## M. Remaining blockers / not done

1. **No valid AI provider credentials on this machine** → zero verified LLM round trips; AI-augmented paths are code-complete but unexercised. Blocked on a user-provided key (and approval for billable use).
2. **No external scanner binaries installed** (nmap, nuclei, sqlmap, nikto…) → tool execution paths untested live; install guides are served by the inventory API. Blocked on user authorization to install system-wide tools.
3. **No dense embeddings / vector DB** — RAG is BM25; upgrading means new dependencies and is a product decision, not a repair.
4. **LLM function/tool calling, streaming, MCP** — not implemented; adding them is feature work, not remediation.
5. **UI redesign** — only honesty fixes applied; "professional enterprise redesign" deferred (would be large, review-gated frontend work; no fake controls were added instead).
6. **`.git` untouched** — nothing committed or pushed (awaiting explicit user authorization); `SWA-phase3` working tree left fully intact; `SWA/` duplicate tree flagged for the user to decide on.
7. **Docker image, CI green status, CodeQL** — not executed this pass; cannot be claimed.
8. **Browser end-to-end verification** — HTTP-level verification was performed against the running app; visual/DOM verification via Playwright is pending (Playwright is installed in `venv`; chromium download requires user go-ahead).

## O. Environment/process hazard discovered (important)

This working directory (`C:\Users\krish\SWA`) is shared with another automated session/process (commits authored by `545e` appear every few hours — e.g. `6417bf2` 09:13, `c4bbfc3` 09:40 on 2026-11-07; `11f54d9` 2026-11-08 "activate and wire all 85 cybersecurity agents… 100% execution pass rate"). Effects observed:
- My changes from this audit were swept into that process's commits (e.g. `6417bf2` contains my `core/threat_intel_live.py`, my collaborate rewrite; `c4bbfc3` contains my README/UI badge edits). Those commits carry marketing-grade messages that exceed what the code does.
- `11f54d9` wired tier-4/tier-2 handlers and added `tests/test_all_85_agents.py` asserting 85/85 COMPLETED; its handlers largely return static dicts. My earlier honest `NOT_EXECUTABLE` reporting for tier 4 was overwritten by that wiring.
- `SWA/SWA` nested stale duplicate tree remains in the repo directory. `C:\Users\krish\SWA-phase3` (separate checkout, branch `phase3-security-foundation`) contains uncommitted WIP from that session and was **not** touched.
- Nobody should `git commit`/`push` from this directory until the owner reconciles the two sessions' work. This report intentionally leaves the working tree with reviewable changes and commits nothing.

## N. Overall completion status

**NOT production-ready; substantially audited with honest behavior and real fixes.** The application boots, serves its UI, passes its suite (result recorded in § L), and its AI/agent subsystems no longer claim success without executing. Residual risk concentrates in unverified provider paths and uninstalled external scanners.
