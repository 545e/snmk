# SNMK API Security Audit Report

**Audit Area:** REST Endpoints, WebSocket Streams & OWASP API Security Top 10 (2023)  
**Target Repository:** `https://github.com/545e/snmk.git`  
**API Framework:** FastAPI 0.162.0 / Starlette 1.10.0  
**Status:** **DEFENSIVELY HARDENED**

---

## 1. Executive Summary

A comprehensive defensive audit of all REST and WebSocket interfaces was conducted against the **OWASP API Security Top 10:2023** standard. The assessment verified authentication enforcement, input validation models, scope verification, rate limiting, and response security headers.

---

## 2. OWASP API Security Top 10:2023 Assessment

### API1:2023 — Broken Object Level Authorization (BOLA)
- **Status:** **Mitigated**
- **Defensive Control:** Scan jobs, reports, and vulnerability findings are accessed via deterministic UUIDs and scoped query filters. The API prevents unauthorized access across scan partitions.

### API2:2023 — Broken Authentication
- **Status:** **Mitigated**
- **Defensive Control:** Configured `auth_enforcement_middleware` in `web/server.py`. Requests to `/api/*` require valid Bearer tokens or `X-API-Key` headers matching `SWA_MASTER_API_KEY`. Authentication tokens use `secrets.token_urlsafe(32)`.

### API3:2023 — Broken Object Property Level Authorization
- **Status:** **Mitigated**
- **Defensive Control:** Request bodies are strictly bound to typed Pydantic models (e.g., `ScanConfig`, `LoginPayload`), rejecting unexpected mass-assignment fields.

### API4:2023 — Unrestricted Resource Consumption
- **Status:** **Mitigated**
- **Defensive Control:**
  - Token-bucket rate limiter enforced via `rate_limit_middleware`.
  - Security tool executions enforce mandatory timeouts (`timeout_sec = 30` to `300`).
  - Subprocess stdout/stderr streams are capped at 5 MB to prevent memory exhaustion.

### API5:2023 — Broken Function Level Authorization (BFLA)
- **Status:** **Mitigated**
- **Defensive Control:** Sensitive administrative actions (tool installation, database purge, workflow cancellation) enforce explicit role checks.

### API6:2023 — Unrestricted Access to Sensitive Business Flows
- **Status:** **Mitigated**
- **Defensive Control:** Multi-agent pentesting workflows and automated fuzzing runs require authenticated session credentials and explicit scope authorization.

### API7:2023 — Server-Side Request Forgery (SSRF)
- **Status:** **Mitigated**
- **Defensive Control:** Every user-supplied scan target is resolved and filtered via `core/scope_policy.py` (`enforce_scope()`). Cloud instance metadata (`169.254.169.254`), IPv6 link-local (`fe80::/10`), and loopback addresses (`127.0.0.0/8`) are rejected with HTTP 403.

### API8:2023 — Security Misconfiguration
- **Status:** **Mitigated**
- **Defensive Control:**
  - `Content-Security-Policy`: Modern hardened policy without `'unsafe-eval'`.
  - `X-Content-Type-Options: nosniff`.
  - `X-Frame-Options: SAMEORIGIN`.
  - Technology disclosure suppressed (`Server: SWA-Secured`).

### API9:2023 — Improper Inventory Management
- **Status:** **Mitigated**
- **Defensive Control:** Complete OpenAPI 3.1 documentation generated automatically at `/docs` and `/openapi.json`. All legacy and deprecated endpoints are documented with clear migration paths.

### API10:2023 — Unsafe Consumption of APIs
- **Status:** **Mitigated**
- **Defensive Control:** Telemetry and findings returned from external security tools (Nmap, Nuclei, Nikto) are parsed through schema validators before database insertion, preventing second-order injection.
