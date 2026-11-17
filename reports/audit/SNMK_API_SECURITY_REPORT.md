# SNMK — API Security Report

| | |
|---|---|
| **Revision** | `39f441b` |
| **Surface** | 197 FastAPI routes (176 under `/api`), 1 WebSocket, 4 OpenAPI-compatible paths |
| **Method** | Route enumeration against a live instance, handler-by-handler review, dynamic verification of the authentication boundary |
| **Standard applied** | OWASP API Security Top 10 (2023) |

---

## 1. The surface

| Prefix | Routes | Authentication |
|---|---|---|
| `/api` | 176 | Gated when authentication is enabled |
| `/v1` | 2 | **Gated** (fixed in this pass — the `/api`-only predicate missed them) |
| `/chat`, `/models` | 2 | **Gated** (fixed in this pass) |
| `/health`, `/healthz`, `/ready`, `/status` | 6 | Public by design |
| `/docs`, `/redoc`, `/openapi.json`, `/swagger.json` | 4 | Public by design |
| `/.well-known/security.txt`, `/security.txt`, `/sitemap.xml`, `/favicon.ico`, `/` | 5 | Public by design |
| `WS /ws` | 1 | **Gated** (fixed in this pass) |

---

## 2. OWASP API Security Top 10

### API2:2023 — Broken Authentication
**Severity:** Critical · **Status:** FIXED

`POST /api/auth/login` and `POST /api/v1/auth/login` minted a valid session
for **any** caller. The `password` field was never read, and the v1 login
derived the role from the client-supplied username, so `{"username":"admin"}`
produced an administrator session.

Measured before the fix:

```
POST /api/auth/login    {"username":"attacker"}  -> 200, token
POST /api/v1/auth/login {"username":"admin"}     -> 200, token, role=admin
```

After the fix both return **401**, and the role comes from server-side
configuration or from a verified master API key — never from the request.

**Fix:** `core/app_security.create_login_session()` is now the only place a
login session is created.
**Tests:** `tests/test_auth_hardening.py`.

### API3:2023 — Broken Object Level Authorization
**Severity:** High · **Status:** Open

Object-level authorisation is inconsistent. The sibling endpoints that
resolve an identifier through the database before returning it are safe —
`GET /api/reports/vulnerability-assessment/{id}/download`
(`web/server.py:1797`) and `GET /api/cyber/export/download/{id}`
(`web/server.py:6148`) both look the identifier up. But
`GET /api/kill-chain/reports/{report_id}/download`
(`web/kill_chain_router.py:398`) interpolates the identifier straight into a
filesystem path:

```python
file_path = os.path.join(output_dir, f"{report_id}.{ext}")
if not os.path.exists(file_path):
    raise HTTPException(status_code=404, ...)
return FileResponse(path=file_path, ...)
```

Starlette percent-decodes the path before matching, so `%5C` and `%3A`
survive into the parameter; on Windows `os.path.join(dir, "C:\\...\\x.md")`
returns the absolute second argument, and `..\\..\\` traverses. The
extension is caller-selected from `html|pdf|json|csv|markdown|md`.

**Fix:** resolve the path and assert it is inside `output_dir`
(`core/app_security.safe_resolve_path` already exists), and reject a
`report_id` that is not a strict identifier.

### API4:2023 — Unrestricted Resource Consumption
**Severity:** High · **Status:** Open

Three separate mechanisms:

1. **Unbounded `limit`.** Most list endpoints declare `limit: int = N` with
   no `Query(..., ge=, le=)` bounds — unlike `/api/assets`, which does it
   correctly. `limit=100000000` and negative values are accepted.
2. **Whole-table reads.** `GET /api/findings` with the default parameters
   returns the entire findings table, including the evidence blobs.
3. **Unbounded background tasks.** Every scan request spawns a full
   multi-agent orchestration with no global concurrency cap.

**Fix:** apply `Query(default=..., ge=1, le=...)` to every list endpoint;
add a global semaphore on scan creation with a 429 above the cap.

### API5:2023 — Broken Function Level Authorization
**Severity:** High · **Status:** Open

`require_role()` exists (`core/app_security.py:271`) and is imported by
`web/v1/router.py`, but it is applied to **zero routes**. Every
authenticated caller has the same authority. RBAC is a declaration, not a
control.

### API6:2023 — Unrestricted Access to Sensitive Business Flows
**Severity:** Medium · **Status:** Open

The tool-execution endpoints have no rate limit of their own, and the
platform-wide limiter is bypassed for failed authentication (§API7).

### API7:2023 — Server Side Request Forgery
**Severity:** High · **Status:** FIXED (partial)

Seven SSRF paths were found. All are now closed:

| Endpoint | Vector | Fix |
|---|---|---|
| `POST /api/integrations/test` | `endpoint_url` → outbound request carrying the provider's stored key | `core/integrations/endpoint_policy.py` |
| `POST /api/integrations/{id}/test` | the stored credential sent to a caller-chosen host | same |
| `PUT /api/ai-agents/{id}` then `POST /api/ai-agents/{id}/test` | the stored AI key sent to a caller-chosen `base_url` | same |
| `POST /api/notifications/test` | `webhook_url` POSTed verbatim | `validate_tool_target` |
| `POST /api/tools/dependency-check` | the target fetched without the scope check its siblings perform | `enforce_scope` |
| `POST /api/scope/targets` | arbitrary domain persisted into the allowlist | documented in the security report |

**Still open:** DNS rebinding (the guard resolves at validation time and the
outbound request resolves again). The fix is to pass the validated address
to the connection.

### API8:2023 — Security Misconfiguration
**Severity:** Medium · **Status:** Open

* `/docs`, `/redoc` and `/openapi.json` are public, disclosing the full
  API surface. Disable them in production.
* `/api/auth/status` returns `auth_enabled`, `authenticated`, `role` and
  `identity` — including `{"authenticated": true, "role": "admin",
  "identity": "local_system_admin"}` when authentication is off.
* The container published `0.0.0.0:8000` with no authentication variables.
  **Fixed** — now loopback-only with `SWA_AUTH_ENABLED=true`.

### API9:2023 — Improper Inventory Management
**Severity:** Medium · **Status:** FIXED (partial)

`/api/tools/registry` now publishes a `handler_resolution` block per tool,
so a declared handler that does not resolve is visible before it is
executed rather than after. All 34 resolve.

The stale `config/85_agents_matrix.json` remains an orphaned artefact that
disagrees with the registry on five agents' timeouts. It should be either
generated from `discover_all_agents()` or deleted.

### API10:2023 — Unsafe Consumption of APIs
**Severity:** Medium · **Status:** Open

The platform consumes 20 third-party APIs (VirusTotal, AbuseIPDB, Shodan,
Censys, OTX, URLhaus, Splunk, Wazuh, Elastic, DefectDojo, CrowdStrike,
Tenable, OpenAI, Anthropic, Gemini, OpenRouter, Ollama, CISA KEV, FIRST
EPSS, AWS/Azure/GCP). Two problems:

* **35 requests have no explicit timeout** (bandit B113/B310). A hung
  upstream holds a worker.
* **The response is trusted.** `res.json()` is read and indexed without a
  schema check, so a changed upstream shape surfaces as a `KeyError` in the
  middle of a scan rather than as a clean "the provider's response changed".

### API1:2023 — Broken Object Level Authorization
Covered by API3.

---

## 3. Input validation

| Concern | State |
|---|---|
| Request models | Pydantic v2 throughout; the models are the validation boundary |
| Path parameters | Mostly typed, but not validated for format — `report_id` is the exception (API3) |
| Query parameters | `Query(...)` bounds are applied inconsistently (API4) |
| Body size | **No global limit.** Uploads are read fully into memory before the 50 MB check (SEC-19) |
| Content-Type | Not enforced; `python-multipart` parses whatever is sent |
| Unknown fields | Pydantic's default is to **ignore** them, which is the safe default for mass-assignment |

---

## 4. Rate limiting

```
web/server.py:190   rate_limit_middleware      <- registered second
web/server.py:252   auth_enforcement_middleware <- registered third
```

Starlette inserts each `add_middleware` at index 0, so the **last
registered is outermost**: the execution order is
`assets → security_headers → auth → rate_limit → CORS → router`.

**The rate limiter sits inside the authentication gate.** A request that
fails authentication returns 401 before the limiter is consulted, so
**failed-authentication attempts are never throttled** — which is precisely
the traffic a brute-force attack generates.

Two further weaknesses: all loopback clients are fully exempt
(`web/server.py:228`), and the bucket state is per-process and in-memory,
so it is ineffective behind a proxy or across workers.

**Fix:** register the rate limiter last so it is outermost; give
`/api/auth/*` a strict per-IP budget; remove the blanket loopback exemption
(use a separate authenticated quota for local tools); move the counters to a
shared store.

---

## 5. Mass assignment

`PUT /api/ai-agents/{id}` writes a set of columns selected by an
allowlist (`core/database.py:9190`), which is the correct pattern. The
`base_url` column was, however, writable and is what the credential
exfiltration in SEC-04 abused. It is now constrained by the endpoint policy,
and the mutation endpoint requires authentication.

---

## 6. Recommendations

| # | Action | Effort |
|---|---|---|
| 1 | Fix the path traversal in the kill-chain report download | Low |
| 2 | Bound every `limit` parameter with `Query(ge=, le=)` | Low |
| 3 | Move the rate limiter outside the auth gate | Low |
| 4 | Apply `require_role()` to the state-changing routes | Medium — needs a role matrix |
| 5 | Add the 35 missing timeouts and validate the upstream responses | Medium |
| 6 | Add a global body-size middleware and stream the uploads | Medium |
| 7 | Pin the resolved IP so DNS rebinding cannot bypass the guard | Medium |
| 8 | Disable `/docs` in production and minimise `/api/auth/status` | Low |
| 9 | Delete or regenerate `config/85_agents_matrix.json` | Low |
| 10 | Add a table-driven negative-input test for every route | Medium |
