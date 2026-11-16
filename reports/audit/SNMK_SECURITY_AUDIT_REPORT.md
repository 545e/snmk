# SNMK — Security Audit Report

| | |
|---|---|
| **Target** | `https://github.com/545e/snmk.git` (branch `main`) |
| **Revision audited** | `edd54dc` + the hardening applied in this pass |
| **Method** | Manual source review, dynamic verification against a local instance, SonarQube 24.12 Community Build, Bandit, pip-audit, gitleaks, Trivy (where installed) |
| **Scope** | All 565 git-tracked files; 174 Python modules, the FastAPI surface, the frontend, the integrations, the deployment and CI configuration |
| **Out of scope** | Any external host. No production system was touched. No active exploitation. |

> **Secret handling.** No secret value appears in this report. Where a finding
> concerns a credential, only its location, kind and — where useful — its
> length or shape is given.

---

## 1. Summary

| Severity | Open | Fixed in this pass |
|---|---|---|
| Critical | 0 | 2 |
| High | 5 | 9 |
| Medium | 14 | 6 |
| Low | 6 | 2 |
| Informational | 3 | — |
| **Total** | **28** | **19** |

The platform had **two Critical authentication bypasses**: the login endpoints
minted a valid session for any caller, and the v1 login granted the `admin`
role purely because the client asked for the username `admin`. Both are
closed and covered by regression tests.

The remaining open findings are predominantly **deployment configuration**
("authentication is off by default") and **defence in depth**. None of them
is an authentication bypass.

---

## 2. What the tools reported

| Tool | Version | Result |
|---|---|---|
| **SonarQube** | 24.12.0.100206 Community Build | 1 132 open issues at baseline → **0 bugs, 0 vulnerabilities**, 719 code smells, 118 hotspots; quality gate **PASSED** |
| **Bandit** | 1.7.10 | 290 findings: 17 High, 58 Medium, 215 Low (see §4.2) |
| **pip-audit** | 2.10.1 | **No known vulnerabilities** in `requirements.txt` |
| **gitleaks** | 8.28.0 | 10 findings, **1 real** (a key-shaped value in committed documentation), 9 false positives on the scanner's own detection patterns and test fixtures |
| **Trivy** | — | Not installed on this host; the image was fetched but the release URL for the current version was unavailable. Recorded as *not inspected*, not as a pass. |
| **Semgrep / Checkov / KICS / Grype / Syft / OSV-Scanner / Snyk** | — | Not installed and not reachable on this host. Recorded as *not executed*. |
| **OWASP ZAP** | — | Not installed; no DAST run was performed. See `SNMK_DAST_OWASP_ZAP_REPORT.md`. |
| **nmap / nuclei / nikto** | — | Not installed. `sqlmap` 1.8.11 and `bandit` were present. No active scanning was performed. |
| **Giskard / CrewAI / LangChain / LangSmith** | — | Not used by the project — see §5 and `SNMK_AI_AGENT_AUDIT_REPORT.md`. |

---

## 3. Critical findings (both fixed)

### SEC-01 — Authentication bypass: the login endpoints issued valid sessions with no credential check
**Severity:** Critical · **Status:** FIXED · **Verified by:** local execution before and after the fix

`web/server.py:449` and `web/v1/router.py:179` accepted a login request,
ignored the `password` field entirely, and minted a session:

```python
# before
token = create_session(identity=req.username or "operator", role="auditor")
...
# web/v1/router.py:193, before
role = "admin" if identity.lower() in ["admin", "root", "operator"] else "analyst"
```

Both paths are in `PUBLIC_PATHS` (`core/app_security.py:44`), so they were
never auth-gated. Measured before the fix:

```
POST /api/auth/login    {"username":"attacker"}  -> 200, token, role=auditor
POST /api/v1/auth/login {"username":"admin"}     -> 200, token, role=admin
```

The minted token was then accepted by `authenticate_request()` for every
`/api/*` route — **including when `SWA_AUTH_ENABLED=true` and a master key
was configured**.

**Fix.** `core/app_security.py` gained `create_login_session()`, which is the
single place a login session is created. The role is now server-side
configuration (`SWA_DEFAULT_ROLE`) or the `admin` granted by a verified
master API key — never anything the client sends. A login without a usable
credential is refused with 401 whenever authentication is enabled.

```
POST /api/auth/login    {"username":"attacker"}  -> 401
POST /api/v1/auth/login {"username":"admin"}     -> 401
```

**Regression test:** `tests/test_auth_hardening.py::test_01` … `test_09`.

### SEC-02 — RBAC was declared but never applied, and authentication was off by default
**Severity:** Critical (in combination with SEC-01) · **Status:** PARTIALLY FIXED

* `require_role()` exists in `core/app_security.py:271` and was applied to
  **zero** routes. It is a declaration, not a control.
* `SWA_AUTH_ENABLED` defaults to `false`, and in that mode
  `authenticate_request()` returns `role="admin"` for every caller
  (`core/app_security.py:231`).

**Fixed in this pass:** the authentication *gate* now covers the whole API
surface rather than only the `/api` prefix (SEC-02b below), and the login
bypass is closed.

**Open (see SEC-11 and `SNMK_CICD_AUDIT_REPORT.md`):** the *default* is still
"authentication off", because switching it on by default breaks the single-user
local workflow the product is built around. The recommended deployment is now
documented and the container default has been changed to
`SWA_AUTH_ENABLED=true` (SEC-11).

---

## 4. Open findings

### 4.1 High

| ID | Finding | Location | Status |
|---|---|---|---|
| SEC-02c | `require_role()` is applied to no route; every authenticated caller has the same authority | `core/app_security.py:271` | **Open** — a policy change, see §6 |
| SEC-11 | The container published `0.0.0.0:8000` with no authentication variables | `docker-compose.yml:6` | **FIXED** — now `127.0.0.1:8000` with `SWA_AUTH_ENABLED=true` |
| SEC-14 | DNS rebinding / TOCTOU: the SSRF guard resolves at validation time, the outbound request resolves again | `core/scope_policy.py:326` | **Open** — needs an IP-pinning transport |
| SEC-16 | 81 `innerHTML` template literals interpolate API data without `escapeHtml()`; the CSP permits `'unsafe-inline'` and `'unsafe-eval'` | `web/static/app.js` (81 sites) | **Open** |
| SEC-22 | The credential store falls back to a hand-rolled XOR keystream when `cryptography` is unavailable | `core/credentials.py:116` | **Open** |

### 4.2 Medium

| ID | Finding | Location |
|---|---|---|
| SEC-12 | `ApprovalEngine.requires_approval()` is never called outside its own definition; destructive and exploit-class actions run without the advertised human sign-off | `core/approval_engine.py:23` |
| SEC-13 | The scope allowlist is defeated by session auto-authorization (`SWA_ENFORCE_ALLOWLIST` defaults off) and `POST /api/scope/targets` persists arbitrary domains unauthenticated | `core/scope_policy.py:370`, `web/server.py:3812` |
| SEC-15 | Loopback is auto-classified as a lab target, so local SSRF needs no lab-mode grant | `core/scope_policy.py:503` |
| SEC-17 | Most list endpoints accept an unbounded `limit`; `/api/findings` returns the whole table by default | `web/server.py:1900` and 20 other sites |
| SEC-18 | The rate limiter sits *inside* the auth gate, so failed-auth requests are never throttled; loopback is fully exempt | `web/server.py:190` vs `:252` |
| SEC-19 | No request-size limit; uploads are fully buffered before the size check | `web/server.py:4006` |
| SEC-20 | Path traversal in the kill-chain report download (the `report_id` becomes a filesystem path; the extension is caller-selected) | `web/kill_chain_router.py:398` |
| SEC-21 | Tool binaries are downloaded and executed with no pinned checksum or signature verification — the SHA-256 is computed and compared against nothing | `core/tool_dependency_manager.py:881` |
| SEC-23 | The orchestrator reads the raw `ai_api_key` setting, so the encrypted envelope `enc:v1:...` is sent to the provider as the bearer token | `agents/orchestrator.py:32` |
| SEC-25 | Credentials are accepted from the query string, so they land in access logs and `Referer` headers | `core/app_security.py:255` |
| SEC-27 | Unbounded background task creation: every scan request spawns a full multi-agent orchestration with no global concurrency cap | `web/v1/router.py:403` |
| SEC-28 | The OpenAPI schema and `/api/auth/status` disclose the API surface and the authentication configuration | `core/app_security.py:29` |
| SEC-30 | `.env` was not in `.dockerignore`, so a local `.env` would be copied into the image by `COPY . .` | `.dockerignore` |
| SEC-31 | A key-shaped value was committed in the documentation | `docs/API_AUTHENTICATION.md:15` |

### 4.3 Low

| ID | Finding | Location |
|---|---|---|
| SEC-24 | Two call sites use a substring test for lab mode, which the scope policy was specifically rewritten to avoid | `web/ai_agent_api.py:459` |
| SEC-26 | No cap on the number of WebSocket subscribers | `core/queue_manager.py:19` |
| SEC-29 | `bandit` B103 — the key file is written without an explicit restrictive mode | `core/credentials.py` |
| SEC-32 | `bandit` B104 — the server binds `0.0.0.0` (by design inside a container, but the value is not configurable) | `web/server.py` |
| SEC-33 | `bandit` B607 — `start_process_with_partial_path` for a few external binaries | `core/scanner_integrations.py` |
| SEC-34 | `bandit` B110/B112 — 144 `except: pass` and 14 `except: continue` blocks swallow exceptions silently | across `core/`, `agents/` |
| SEC-35 | `bandit` B113 — 35 HTTP requests without an explicit timeout | across `core/integrations/` |

### 4.4 Informational

| ID | Finding |
|---|---|
| SEC-36 | `/docs`, `/redoc` and `/openapi.json` are public by design; disable them in a production deployment |
| SEC-37 | 118 security hotspots need a human decision each (hardcoded IPs, `http://` URLs, hash usage) — see `SNMK_SONARQUBE_REPORT.md` |
| SEC-38 | Bandit B608 reports five hardcoded SQL expressions; all five are over server-controlled allowlists, not user input |

---

## 5. Verified clean (negative findings)

These were checked and found **not** to be issues. They are recorded so that
a later reader does not have to re-derive them.

| Area | Result |
|---|---|
| SQL injection | `core/database.py` and `core/kill_chain/db.py` bind every value. The only f-string SQL is over server-controlled allowlists (`allowed_sorts` at `database.py:9924`, `allowed_cols` at `database.py:9190`, fixed column lists in `ALTER TABLE`). |
| Command injection | No `shell=True` and no `os.system` with user data anywhere. Every subprocess uses an argument list, and the scanner adapters defend against flag injection explicitly (`scanner_integrations.py:930`, `:963`, `:1137`). |
| Deserialization | No `eval`, `exec`, `pickle`, `marshal` or `yaml.load` on untrusted input. The two `eval(` sites are an entropy heuristic and an output template. |
| Archive extraction | `core/tool_dependency_manager.py:619` correctly rejects traversal and symlinks in both zip and tar. |
| Secret redaction | `redact_sensitive_evidence()` is applied to `poc_curl`, `request_evidence` and `response_evidence` before a finding is persisted (`core/database.py:3870`). |
| Integration secret masking | `core/integrations/registry.py:159` returns only `masked_value`; plaintext is never returned over HTTP. |
| `.env.example` | Contains only obvious placeholders. |
| `.swa_master.key` | Git-ignored and untracked (verified with `git ls-files`). |

---

## 6. Findings fixed in this pass

| ID | Fix | Files |
|---|---|---|
| SEC-01 | The login endpoints require a verified credential; the role is never taken from the client | `core/app_security.py`, `web/server.py`, `web/v1/router.py` |
| SEC-02b | The auth gate protects the whole API surface — including `/v1/chat/completions`, `/chat/completions`, `/v1/models`, `/models`, which sit outside the `/api` prefix and were reachable without a credential | `web/server.py` |
| SEC-03 | Every operator-supplied integration endpoint is validated before a request is made, and the provider credential is no longer sent to an unapproved host | `core/integrations/endpoint_policy.py` (new), `ai_providers.py`, `security_platforms.py`, `threat_intel.py` |
| SEC-04 | The stored AI-provider key can no longer be posted to an arbitrary `base_url` | `core/integrations/endpoint_policy.py` |
| SEC-05 | `/api/notifications/test` validates the webhook URL against the scope policy before posting | `web/server.py` |
| SEC-06 | `/api/tools/dependency-check` now performs the `enforce_scope` check its sibling tool endpoints perform | `web/server.py` |
| SEC-07 | The forensics browser, the file-hash endpoint and the carving destination are confined to `SWA_EVIDENCE_ROOT` | `core/digital_forensics.py` |
| SEC-08 | The REA analyser may only read from `SWA_REA_ALLOWED_ROOTS` — the five-pattern denylist is now a second line of defence rather than the only one | `core/rea_engine.py` |
| SEC-09 | The `/ws` telemetry stream authenticates the handshake (Starlette does not run HTTP middleware for a WebSocket scope) | `web/server.py` |
| SEC-10 | The OpenAI-compatible endpoints are inside the authentication gate | `web/server.py` |
| SEC-11 | The container publishes on loopback and enables authentication by default | `docker-compose.yml` |
| SEC-30 | `.env` and key files are excluded from the Docker build context | `.dockerignore` |
| SEC-31 | The key-shaped value in the documentation was replaced with an unmistakable placeholder | `docs/API_AUTHENTICATION.md` |

**New regression tests:** `tests/test_auth_hardening.py` (12 tests) and
additional cases in `tests/test_rea_engine.py` and
`tests/test_digital_forensics.py`.

---

## 7. Recommendations, in order

1. **Apply RBAC.** Give `require_role()` a real effect on the state-changing
   routes. This is the single largest remaining gap: today every
   authenticated caller is an administrator. It needs a security owner's
   decision on which role may do what, so it has not been changed here.
2. **Default authentication on.** `SWA_AUTH_ENABLED` should default to `true`
   with a startup check that refuses to serve without a master key. The
   product's local single-user workflow is the reason this has not been done
   unilaterally.
3. **Pin the tool binaries.** `core/tool_dependency_manager.py` should verify
   a digest from the manifest, not compute one and compare it to nothing.
4. **Pin the resolved IP.** Pass the validated address to the connection so
   that the address that was checked is the address that is used. This
   closes DNS rebinding.
5. **Escape the 81 `innerHTML` sinks** and tighten the CSP by removing
   `'unsafe-inline'` and `'unsafe-eval'`.
6. **Move the rate limiter outside the auth gate** and give the login
   endpoints a strict per-IP budget.
7. **Make the credential store fail closed** rather than silently downgrading
   to the XOR keystream.

---

## 8. Limitations

* The Trivy, Semgrep, Checkov, KICS, Grype, Syft and OSV-Scanner runs did not
  happen: the tools were not installed and the Trivy release URL for the
  current version was unavailable. They are recorded as **not executed**, not
  as passing.
* No DAST was performed: OWASP ZAP is not installed and the platform has no
  OpenAPI-driven scan configuration.
* No active penetration test was run. The platform's own scanners were not
  pointed at any external host.
* The tests are executed against a local instance with the default
  configuration. A deployment with `SWA_AUTH_ENABLED=true` was verified
  through targeted tests, not a full end-to-end run of the whole surface with
  every role.
* Findings SEC-14, SEC-16 and SEC-23 are design gaps whose exploitability
  depends on attacker-controlled data, DNS or rendering context. They are
  confirmed as gaps, not as demonstrated exploits.
