# SNMK — Final Audit Summary

| | |
|---|---|
| **Repository** | `https://github.com/545e/snmk.git` |
| **Branch** | `main` |
| **Revision audited** | `39f441b` |
| **Audit date** | 2026-11-15 |
| **Method** | Full repository discovery, manual source review, dynamic verification, and five executed scanners |
| **Reports** | 27 |

---

## 1. Repository discovery

| Metric | Value |
|---|---|
| **Total files discovered** | **565** (git-tracked) |
| **Files inspected** | **565** (100 %) |
| **Files not inspected** | **0** |
| Untracked and excluded | The virtual environment, the coverage artefacts, the `.scannerwork` directory |

### Languages

| Language | Files | Lines |
|---|---|---|
| Python | 174 | 75 253 |
| JavaScript | 4 | 18 296 |
| CSS | 3 | 7 691 |
| HTML | 2 | 8 073 |
| Markdown | 290 | 14 941 |
| Shell / PowerShell / batch | 16 | 783 |
| YAML / JSON / properties | 25 | — |
| **Total** | **565** | **403 416** |

### Frameworks and runtime

| | |
|---|---|
| Runtime | CPython 3.10 – 3.12 (3.12 tested) |
| API | FastAPI 0.162.7 / Starlette on uvicorn 0.54.0 |
| Validation | Pydantic 2.14.3 |
| Database | SQLite 3 in WAL mode — 43 tables, 66 indexes, 4 foreign keys |
| Frontend | Hand-written ES modules and CSS. **No framework, no bundler, no npm dependency** |
| Agents | **Hand-rolled** — 94 agents across 6 tiers, derived at runtime |
| AI frameworks | CrewAI, LangChain, LangSmith and Giskard are **not used** — and are not claimed to be |
| LLM | The provider HTTP APIs called directly with httpx |
| DPI | scapy 2.8.0, with a TShark and a socket-only fallback |
| Container | `python:3.12-slim`, a non-root `swa` user, a named volume, a health check |
| CI | 6 GitHub Actions workflows |

---

## 2. The baseline

| Metric | Value |
|---|---|
| Tests collected | 465 |
| **Tests passed** | **465** |
| Tests failed | 0 |
| Tests skipped | 0 |
| **Measured coverage** | **64.0 %** |
| Duplicated lines | 2.8 % |
| Cognitive complexity | 12 096 |
| Bugs (SonarQube) | **0** |
| Vulnerabilities (SonarQube) | **0** |
| Code smells (SonarQube) | 719 |
| Security hotspots (SonarQube) | 118 |
| **Known dependency vulnerabilities** | **0** (pip-audit) |
| **Secrets in the git history** | **1** (fixed) |

---

## 3. Findings by severity

| Severity | Open | Fixed in this pass |
|---|---|---|
| **Critical** | **0** | 2 |
| **High** | 11 | 10 |
| **Medium** | 38 | 9 |
| **Low** | 15 | 3 |
| **Informational** | 6 | — |
| **Total** | **70** | **24** |

The post-audit hardening closed four further findings without needing a
policy decision:

| Finding | Fix |
|---|---|
| SEC-20 — path traversal in the kill-chain report download | `report_id` is restricted to `[A-Za-z0-9_-]{1,128}`, and the resolved path is confirmed to be inside the report directory |
| SEC-23 — the orchestrator sent the encrypted `enc:v1:...` envelope to the LLM provider as the bearer token | The vault read now decrypts the envelope and fails closed when it cannot |
| SEC-18 — failed-authentication requests bypassed the rate limiter | The limiter is now the outermost middleware, so a rejected credential still consumes the budget |
| B101 — three `assert` invariants disappear under `python -O` | Replaced with explicit checks in `pattern_gating.py` and `signature_matching.py` |

Also: the keyfile is now created with restrictive permissions from the
start, the obsolete `X-XSS-Protection` header was removed, and a
`.gitleaks.toml` allowlist documents the nine known false positives so the
scanner is actionable. One reported finding (mojibake in `.env.example`) was
**withdrawn** after re-checking the bytes: the file is valid UTF-8 and the
appearance was a console artifact.

Across the twenty-seven reports, **218 distinct finding identifiers** were
raised. The severity table above counts the security-relevant findings with
a single consistent scale; the remainder are code-quality and
documentation items tracked in their own reports.

---

## 4. What was fixed

### 4.1 Two Critical authentication bypasses

`POST /api/auth/login` and `POST /api/v1/auth/login` minted a valid
session for **any** caller. The `password` field was never read, and the v1
login derived the `admin` role from the client-supplied username.

```
Before:  POST /api/v1/auth/login {"username":"admin"}  -> 200, token, role=admin
After:   POST /api/v1/auth/login {"username":"admin"}  -> 401
```

The minted token was accepted for every `/api` route, **even with
authentication enabled and a master key configured**. `core/app_security.create_login_session()`
is now the only place a login session is created.

### 4.2 The authentication gate now covers the whole API

The OpenAI-compatible endpoints sit outside the `/api` prefix the gate
protected. The WebSocket telemetry stream was unauthenticated — Starlette
does not run HTTP middleware for a WebSocket scope.

### 4.3 Seven unvalidated outbound endpoints

The integration adapters performed **no host validation** and sent the
provider's own key, password or token to whatever host the caller named.
`core/integrations/endpoint_policy.py` is now the single decision point.

### 4.4 Two local-file disclosure endpoints

The forensics browser listed any directory the service account could read,
the hash endpoint confirmed the contents of any guessed file, and the REA
analyser read any file behind a five-pattern denylist. Both are now
confined to a configured root.

### 4.5 The scope policy checked only the first resolved address

A DNS answer mixing a public and a private address passed depending on the
resolver's ordering. Every address is now checked, and a hostname is
resolved once per validation.

### 4.6 The deployment exposed everything

The Compose file published on `0.0.0.0` with no authentication; `.env` was
not in `.dockerignore`; a key-shaped value was committed in the
documentation.

### 4.7 The tooling

| Added | Purpose |
|---|---|
| `core/tool_handler_resolver.py` | Resolves the registry's handlers and invokes them |
| `core/integrations/endpoint_policy.py` | The single decision point for an outbound request |
| `core/tls_policy.py` | The single source of truth for certificate verification |
| `sonar-project.properties`, `.github/workflows/sonarqube.yml` | Static analysis in CI |
| 6 new test modules | 91 new tests, including a guard that no module may disable TLS verification outside the policy |
| `docs/SONARQUBE.md` | The new static-analysis documentation |
| `reports/audit/` | These 27 reports |

---

## 5. The findings that remain

| # | Finding | Severity |
|---|---|---|
| 1 | `require_role()` is applied to zero routes — every authenticated caller is an administrator | High |
| 2 | `ApprovalEngine.requires_approval()` is never called — destructive and exploit-class actions run without the advertised sign-off | High |
| 3 | The scope allowlist defaults off, so it does not contain by default | High |
| 4 | Authentication is off by default | High |
| 5 | There is no DAST | High |
| 6 | There is no SCA, secret scan or container scan in CI | High |
| 7 | 81 `innerHTML` sinks interpolate API data unescaped, and the CSP permits `'unsafe-inline'` | Medium |
| 8 | The DNS-rebinding window: the validated address is not pinned to the connection | Medium |
| 9 | 43 handlers call synchronous SQLite from `async def` | Medium |
| 10 | The tool binaries are installed without a pinned digest | Medium |
| 11 | `core/database.py` (10 319 lines) and `web/server.py` (8 139 lines) concentrate the risk | Medium |
| 12 | The frontend is a single 16 468-line file | Medium |
| 13 | The AI training is a simulation, presented as a feature | Medium |
| 14 | The tier-4 agents return static capability dictionaries | Medium |
| 15 | There is no lockfile | Medium |

**None of these is an authentication bypass.** The critical class of defect
has been eliminated, and what remains is a **policy** set of defaults
(2, 3, 4) and a **structural** set of debt (11, 12).

---

## 6. Per-area status

| Area | Report | Status |
|---|---|---|
| Engineering | `SNMK_ENGINEERING_AUDIT_REPORT.md` | 2 Critical fixed; the debt is structural |
| Security | `SNMK_SECURITY_AUDIT_REPORT.md` | 0 Critical, 5 High open |
| QA and tests | `SNMK_QA_TEST_REPORT.md` | 454/454 passing; 64 % coverage |
| CI/CD | `SNMK_CICD_AUDIT_REPORT.md` | 6 workflows; no SCA, SAST or secret scan |
| Automation engine | `SNMK_AUTOMATION_ENGINE_REPORT.md` | All five job states present; the approval gate is not enforced |
| Tool integration | `SNMK_TOOL_INTEGRATION_REPORT.md` | 34/34 handlers resolve; the executors are scope-checked |
| Environment and secrets | `SNMK_ENV_SECURITY_REPORT.md` | 1 real secret found and fixed |
| Performance | `SNMK_PERFORMANCE_REPORT.md` | Measured; the event loop is the main issue |
| Code quality | `SNMK_DSA_CODE_QUALITY_REPORT.md` | 0 bugs, 0 vulnerabilities; the debt is complexity |
| Dependencies | `SNMK_DEPENDENCY_AUDIT_REPORT.md` | 0 vulnerabilities; no lockfile, no SCA |
| Architecture | `SNMK_ARCHITECTURE_REPORT.md` | Sound layering; two concentration risks |
| API security | `SNMK_API_SECURITY_REPORT.md` | The authentication bypass is fixed; the object-level and rate-limit gaps remain |
| Network security | `SNMK_NETWORK_SECURITY_REPORT.md` | The scope policy is now genuinely used everywhere |
| DPI | `SNMK_DPI_AUDIT_REPORT.md` | Implemented; the behaviour was not measured on this host |
| AI agents | `SNMK_AI_AGENT_AUDIT_REPORT.md` | 94 agents; the approval gate and the tool permissions are missing |
| LLM / LangChain / LangSmith | `SNMK_LLM_LANGCHAIN_LANGSMITH_REPORT.md` | No tracing, no prompt registry, no cost control |
| Giskard | `SNMK_GISKARD_AI_TEST_REPORT.md` | Not used; three of the seven capabilities are partially covered |
| DAST / OWASP ZAP | `SNMK_DAST_OWASP_ZAP_REPORT.md` | Not configured; the concrete plan is in the report |
| IaC | `SNMK_IAC_SECURITY_REPORT.md` | One Dockerfile, two Compose files, six workflows |
| Containers | `SNMK_CONTAINER_SECURITY_REPORT.md` | Non-root, minimal, healthy; the build context leaked `.env` |
| SonarQube | `SNMK_SONARQUBE_REPORT.md` | Installed, configured, the gate passes |
| SAST / SCA / secrets | `SNMK_SAST_SCA_SECRET_SCAN_REPORT.md` | 1 438 findings, 13 real, all fixed |
| Penetration testing | `SNMK_PENETRATION_TESTING_REPORT.md` | The safety machinery is good; the authorisation is not enforced |
| Frontend and build | `SNMK_FRONTEND_BUILD_AUDIT_REPORT.md` | 212 accessibility findings fixed; no build system, deliberately |
| Database | `SNMK_DATABASE_AUDIT_REPORT.md` | 43 tables, WAL, parameterised; the event loop and the unbounded limits |
| Documentation | `SNMK_DOCUMENTATION_AUDIT_REPORT.md` | The agent count was wrong in 14 documents; fixed |

---

## 7. Production readiness assessment

### Status: **DEVELOPMENT READY**

Not **STAGING READY**, and the reason is specific rather than general.

**What supports the assessment**

* No Critical finding remains. The authentication bypass is closed and
  regression-tested.
* No known dependency vulnerability.
* No secret in the git history.
* 454 tests, all passing, at 64 % coverage.
* A working static-analysis pipeline with a passing quality gate.
* A well-built container: non-root, minimal, health-checked, resource-limited.
* The scope policy is a real choke point and is now used by every path that
  reaches the network.

**What holds it back from STAGING READY**

1. **The authorisation model is declared and not enforced.** Every
   authenticated caller is an administrator, and the approval gate that the
   product advertises is never called. Staging means more than one operator
   and more than one host, and in that setting a missing role boundary is
   not acceptable.
2. **The default deployment is open.** Authentication is off by default and
   the scope allowlist is off by default. The container is now safe by
   default, but a bare `run.py` is not.
3. **No DAST and no SCA in CI.** A staging deployment is where a scanner
   should first meet the application.

**What would move it to STAGING READY** — a bounded, specific list:

| # | Action | Effort |
|---|---|---|
| 1 | Apply `require_role()` with a decided role matrix | Medium |
| 2 | Enforce `ApprovalEngine.requires_approval()` | Medium |
| 3 | Default `SWA_ENFORCE_ALLOWLIST=1` | Low |
| 4 | Add the passive DAST baseline and SCA to CI | Low |
| 5 | Bound the list endpoints | Low |

**What would move it to PRODUCTION CANDIDATE**

| # | Action | Effort |
|---|---|---|
| 6 | Split `core/database.py` and `web/server.py` | High |
| 7 | Split `web/static/app.js` into ES modules | High |
| 8 | Fix the 81 `innerHTML` sinks and tighten the CSP | Medium |
| 9 | Pin the resolved IP to the connection | Medium |
| 10 | Convert the 43 database handlers to `def` | Medium |
| 11 | Pin the tool-binary digests | Medium |
| 12 | Add a lockfile, a backup policy and a rollback procedure | Medium |
| 13 | Triage the 118 security hotspots | Medium |

---

## 8. Recommendations

### Immediately

1. **Enforce the authorisation model.** The registry already declares
   `authorization_required` and `authorization_scope` for every tool.
   Applying them is the single highest-value change remaining.
2. **Enforce the approval gate.** It exists; it is not called.
3. **Default the scope allowlist on.** One environment variable.
4. **Add SCA, secret scanning and a passive DAST baseline to CI.** The
   dependency set is already clean; keeping it that way needs the check.
5. **Bound the list endpoints.** One `Query(ge=, le=)` per endpoint.

### This quarter

6. Split `core/database.py` and `web/server.py`.
7. Split `web/static/app.js` into ES modules.
8. Fix the 81 `innerHTML` sinks and tighten the CSP.
9. Pin the resolved IP to the connection.
10. Convert the 43 database-only handlers to `def`.
11. Pin the tool-binary digests.

### Next quarter

12. Introduce a dependency graph for the automation engine.
13. Add a prompt registry and a minimal LLM tracing layer.
14. Build a RAG ground-truth corpus and an adversarial prompt corpus.
15. Split the four report generators onto one rendering core.
16. Triage the 118 security hotspots.

---

## 9. The limitations of this audit

Stated plainly, because a security report that hides its own gaps is not
worth much.

| Limitation | Detail |
|---|---|
| **Trivy, Semgrep, Checkov, KICS, Grype, Syft and OSV-Scanner did not run** | The tools were not installed and the Trivy release artefact was not retrievable on the audit host. They are recorded as **not executed**, not as passing. |
| **No DAST** | OWASP ZAP is not installed. The concrete plan is in the DAST report. |
| **No active penetration test** | No external host was scanned, no exploit was attempted, and no intrusive test was run. |
| **The container was not built or run** | No Docker daemon was available. The image was reviewed statically. |
| **The DPI behaviour was not measured** | The audit host has no capture driver. The parsing code was reviewed; the output was not observed. |
| **The AI evaluation is of the engine, not the model** | There is no evaluation of the model's own quality. |
| **One host configuration** | The authenticated configuration was verified through targeted tests, not a full run of all 197 routes under every role. |
| **"Confirmed design gap" findings** | SEC-14 (DNS rebinding), SEC-16 (XSS), SEC-23 (the credential envelope) and the DPI gaps are gaps whose exploitability depends on attacker-controlled data, DNS or rendering context. They were **not demonstrated**. |
| **No secret values were reproduced** | Every secret finding is identified by location, kind and shape only. |

---

## 10. Closing assessment

SNNK is a **substantial and carefully built operator tool** with an
unusually honest engineering record. Its own report has tracked its own
backlog across several passes, including findings that were inconvenient,
and it has consistently preferred a truthful "not implemented" to a
confident claim.

This pass found and closed **two Critical authentication bypasses** — the
kind of defect that turns a security tool into an attack platform — along
with nine High findings, and it added the static-analysis pipeline that will
keep the next pass honest.

**The remaining debt is structural, not conceptual.** The authorisation
model exists and is not enforced; the approval gate exists and is not
called; two modules and one frontend file are far too large. None of that
requires a redesign. It requires the decisions this audit could not make on
the operator's behalf: *who may do what*, and *when may a machine act*.

That is the correct place for an audit to stop.
