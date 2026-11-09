# AI SECURITY, GOVERNANCE & RED-TEAMING

> **Audit corrections applied 2026-11-07 (read first):**
> - The 12-vector harness is a **deterministic rule-based prober**, not an LLM-driven red-teamer. It passes offline without any API key; it checks regex indicators and transport-level behaviors, not whether a live model actually leaks data.
> - "Indirect Prompt Injection – sanitizes third-party retrieved documents" is a **design claim, not a wired control**: `core/app_security.sanitize_untrusted_input_for_llm` exists but is not called on the RAG retrieval path; RAG context is inserted verbatim into the system prompt by `llm_client.reason()`. Treat retrieved content as untrusted by policy, not by enforcement.
> - No model has ever executed on this machine with a real provider key (`.env` ships a placeholder); the platform runs in `heuristic_fallback` mode. Any behavior observably tied to an LLM round trip is UNVERIFIED until a key is configured.
> - Tool execution does NOT expose shell/PowerShell to models; external binaries run only via adapter allowlists with `scope_policy` validation. LLM-driven function/tool calling does not exist in this codebase at all.
> - Approval gates are enforced in the automation engine for non-lab targets and exist as an `approval_requests` table + `/api/approvals` UI path; the autonomous scan pipeline does not currently pause for human approval.
> - Cross-tenant isolation is by `project_id`/`workspace_id` filters in the DB and RAG store; there is no cryptographic tenant isolation, and `SWA_ENFORCE_ALLOWLIST=1` is required for strict scope enforcement (dynamic target authorization is session-scoped by default, never persisted to `targets.json`).

## Guardrails Against Adversarial LLM Threats, Jailbreaks, and Data Leakage

The platform enforces strict AI security controls in compliance with the OWASP Top 10 for Large Language Model Applications:

### 1. 12-Vector LLM Adversarial Test Coverage

Tested and verified via `core/llm_security_testing.py` and accessible in the UI at `viewAiLab`:

1. **LLM-01: Direct Prompt Injection**:
   - Defended via delimiter escape isolation and system instruction precedence enforcement.
2. **LLM-02: Indirect Prompt Injection**:
   - Sanitizes third-party retrieved documents prior to LLM context assembly.
3. **LLM-03: System Prompt Extraction**:
   - System prompts forbid verbatim quotation of internal operating instructions or canary tokens.
4. **LLM-04: Jailbreak & Roleplay Evasion**:
   - Rejects "DAN", fictional persona, or anti-restriction roleplay attempts.
5. **LLM-05: Sensitive Data Disclosure**:
   - Prevents exfiltration of private canary tokens and synthetic secrets.
6. **LLM-06: Insecure Output Handling**:
   - Enforces HTML entity escaping to prevent model-generated XSS payloads in web renderers.
7. **LLM-07: Excessive Agency & Tool Invocation**:
   - Destructive operating system commands (`rm -rf`, `del /f`) require human-in-the-loop approval.
8. **LLM-08: RAG Poisoning & Retrieval Manipulation**:
   - Enforces threshold relevancy, document validation, and source citation verification.
9. **LLM-09: Training Data Leakage**:
   - Forbids memorized proprietary PII or database credential disclosures.
10. **LLM-10: Unsafe Tool Permissions**:
    - Disallows unauthorized permission flags (`force_admin_grant=true`) passed in tool arguments.
11. **LLM-11: Denial of Service & Token Flooding**:
    - Enforces hard token limits (`max_tokens`) and request timeouts.
12. **LLM-12: Multi-Tenant Cross-Contamination**:
    - Segregates session context and knowledge bases by `project_id`.

---

### 2. Zero-Trust Tool Calling Protocol
- Models are **never** given direct shell execution capabilities.
- Tools only accept typed, validated schemas defined in `core/tool_registry.py`.
- Outputs from tools are treated as untrusted strings and sanitized before client display.
